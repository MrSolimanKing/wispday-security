/**
 * WispDay — useAppLockLifecycle
 * =====================================================================
 * This hook governs key hygiene across the app's foreground/background
 * lifecycle. It is the piece that ensures the user's master key does not
 * outlive the foreground session: when the app is backgrounded, the key
 * is wiped from RAM (zero-filled) and the encrypted databases are closed,
 * so memory inspection of a backgrounded app cannot recover key material.
 *
 * Why this is hard, and what the design accounts for
 * --------------------------------------------------
 * On iOS the OS grants only a short execution window after backgrounding
 * before it suspends the process; a long JS timer scheduled for "later"
 * will not reliably fire while suspended. The security-critical wipe is
 * therefore performed SYNCHRONOUSLY and FIRST (before any `await`), so it
 * cannot be cut off by suspension. The asynchronous database teardown that
 * follows is best-effort: if the OS suspends mid-teardown, the keys are
 * already gone and the worst case is an unclean-but-still-encrypted DB
 * file that is recovered on next open.
 *
 * Security tiers
 * --------------
 *   Max security (biometric storage on):
 *     On background, wipe + lock IMMEDIATELY. No grace period. Returning
 *     to foreground requires an unlock (handled by the lock screen).
 *
 *   Standard (no biometric storage):
 *     On background, schedule a short grace wipe, then silently re-unlock
 *     and reopen on return if the key is still present.
 *
 *   Vault binding:
 *     A separate grace-based tier kept here for future reference. It is
 *     gated on the `vault_key_binding_enabled` flag and follows the same
 *     wipe routine as the others. (This tier is not the app's current
 *     default; the branch is retained intentionally.)
 *
 * The actual key operations (lockMemory, autoUnlock, the biometric flag)
 * live in EncryptionService.ts; this hook only decides WHEN to invoke
 * them across the app lifecycle. App-specific calls (analytics, DB
 * reopen, sync reconnect) are marked `// [app boundary]`.
 */

import { useEffect, useRef } from 'react';
import { AppState, AppStateStatus } from 'react-native';
import BackgroundTimer from 'react-native-background-timer';

// [app boundary] — app modules: persistent KV store, encrypted DB teardown
// helpers, sync reconnect, analytics, and the auth state. Stubbed to the
// surface this hook uses so the lifecycle logic reads on its own.
import {
  quiesceForLock, 
  connectAndWatch,
  powerSync,
  closeSharedMirrorDbAsync,
  reopenAllMirrors,
  generateUUID,
  recordEvent,
} from '../database/AppDatabase';


import { encryptionService } from '../middleware/EncryptionMiddleware';
import { appStorage } from '../storage/AppStorage';

// Grace window (ms) before a non-Max tier wipes keys after backgrounding.
const STANDARD_GRACE_MS = 20_000;

interface Params {
  setIsDbReady: (v: boolean) => void;
  setIsAppLocked: (v: boolean) => void;
}

/**
 * Shared close routine: wipe key material, lock the UI, then best-effort
 * tear down the encrypted databases.
 *
 * Ordering is the security argument:
 *   1. lockMemory() FIRST and synchronously — it zero-fills the master key
 *      buffer (and the secondary-DB key) in RAM. It runs before any await
 *      so OS suspension cannot interrupt it; once it returns, no JS-side
 *      copy of any key remains.
 *   2. Lock the UI synchronously so no decrypted view can stay on screen.
 *   3. Close the databases (async, best-effort). This also evicts the
 *      secondary-DB key from SQLCipher's native memory. If suspension cuts
 *      this short, the keys from step 1 are already gone.
 */
async function closeAndWipe(
  setIsDbReady: (v: boolean) => void,
  setIsAppLocked: (v: boolean) => void,
  lockUi: boolean,
) {
  // 1. Wipe keys first — synchronous, cannot be interrupted by suspension.
  encryptionService.lockMemory();

  // 2. Lock the UI immediately so no decrypted view survives.
  if (lockUi) {
    setIsDbReady(false);
    setIsAppLocked(true);
  }

  // 3. Best-effort encrypted-DB teardown. Keys are already gone by here.
  try {
    await closeSharedMirrorDbAsync();   // [app boundary]
    await powerSync.disconnect();       // [app boundary]
    await quiesceForLock();             // [app boundary]
    console.log('🔒 Databases closed + keys wiped');
  } catch (e) {
    console.warn('[lock] closeAndWipe cleanup cut short (keys already wiped):', e);
  }
}

export function useAppLockLifecycle({ setIsDbReady, setIsAppLocked }: Params) {
  const backgroundTimeoutRef = useRef<number | null>(null);
  const backgroundTimestampRef = useRef<number | null>(null);

  const { isAuthenticated } = useAuth();
  const isAuthRef = useRef(isAuthenticated);
  isAuthRef.current = isAuthenticated;

  useEffect(() => {
    const subscription = AppState.addEventListener('change', (nextAppState: AppStateStatus) => {
      // Shield: an intentional biometric-prompt background (e.g. a settings
      // migration) must NOT trigger a lock.
      if (encryptionService.isIntentionalBackground) {
        return;
      }

      const isVaultBinding = appStorage.getBoolean('vault_key_binding_enabled');
      // Read the biometric (Max) flag from the engine, NOT appStorage:
      // appStorage is encrypted and init-dependent, so getBoolean() can return
      // undefined before init resolves and silently skip the Max wipe. The
      // engine keeps this flag in a plain store, always readable synchronously.
      const isMaxSecurity = encryptionService.isBiometricProtectionEnabled();

      // ── Session tracking ([app boundary] analytics only) ──
      if (nextAppState === 'active') {
        const sessionId = generateUUID();
        appStorage.set('current_session_id', sessionId);
        appStorage.set('session_start_time', Date.now().toString());
        recordEvent('session_start', { session_id: sessionId });
      }
      if (nextAppState === 'background') {
        const sessionId = appStorage.getString('current_session_id');
        const startTime = parseInt(appStorage.getString('session_start_time') || '0');
        if (sessionId && startTime) {
          const duration_s = Math.round((Date.now() - startTime) / 1000);
          if (duration_s > 5) {
            recordEvent('session_end', { session_id: sessionId, duration_s, ended_by: 'background' });
          }
          appStorage.delete('current_session_id');
          appStorage.delete('session_start_time');
        }
      }

      // ── BACKGROUND ──
      if (nextAppState === 'background') {
        if (isMaxSecurity) {
          // Claim the background execution window so the async DB cleanup in
          // closeAndWipe can finish before iOS suspends. The key wipe itself
          // is synchronous-first inside closeAndWipe, so even a short window
          // means keys are gone immediately; start()/stop() only protects the
          // best-effort DB close that follows.
          BackgroundTimer.start();
          backgroundTimestampRef.current = Date.now();
          closeAndWipe(setIsDbReady, setIsAppLocked, true) // instant: wipe + lock UI
            .finally(() => { BackgroundTimer.stop(); });
          return;
        }

        if (isVaultBinding) {
          // Future-reference tier: grace-based wipe.
          backgroundTimestampRef.current = Date.now();
          if (backgroundTimeoutRef.current) BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
          backgroundTimeoutRef.current = BackgroundTimer.setTimeout(() => {
            closeAndWipe(setIsDbReady, setIsAppLocked, true);
            backgroundTimeoutRef.current = null;
          }, STANDARD_GRACE_MS);
          return;
        }

        // Standard tier: short grace, then wipe key + close DBs.
        BackgroundTimer.start(); // claim the window
        backgroundTimestampRef.current = Date.now();
        backgroundTimeoutRef.current = BackgroundTimer.setTimeout(async () => {
          encryptionService.lockMemory(); // sync first
          try { await closeSharedMirrorDbAsync(); } catch {}
          BackgroundTimer.stop();
        }, STANDARD_GRACE_MS);
        return;
      }

      // ── FOREGROUND ──
      if (nextAppState === 'active') {
        // Max / Vault: do NOT silently reopen. Cancel any pending timer; if
        // keys were wiped, the lock screen handles re-unlock and reopen.
        if (isMaxSecurity || isVaultBinding) {
          if (backgroundTimeoutRef.current) {
            BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
            backgroundTimeoutRef.current = null;
          }
          // Vault: if returned within grace and keys still present, no lock.
          if (isVaultBinding && backgroundTimestampRef.current) {
            const elapsed = (Date.now() - backgroundTimestampRef.current) / 1000;
            backgroundTimestampRef.current = null;
            if (encryptionService.ready && elapsed <= 60) return; // quick return, still unlocked
          }
          // Otherwise keys are (or should be) wiped → ensure lock screen shows.
          if (!encryptionService.ready) {
            setIsDbReady(false);
            setIsAppLocked(true);
          }
          return;
        }

        // Standard: silent reopen.
        if (backgroundTimeoutRef.current) {
          BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
          backgroundTimeoutRef.current = null;
        }
        if (encryptionService.ready) { backgroundTimestampRef.current = null; return; }
        backgroundTimestampRef.current = null;
        encryptionService.autoUnlock().then(async (unlocked) => {
          if (!unlocked) { console.error('❌ [Standard] Auto-unlock failed.'); return; }
          await reopenAllMirrors();                                  // [app boundary]
          if (isAuthRef.current && !powerSync.connected) {
            await connectAndWatch();                                 // [app boundary]
          }
        }).catch(e => console.error('❌ [Standard] autoUnlock threw:', e));
      }
    });

    return () => {
      subscription.remove();
      if (backgroundTimeoutRef.current) BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
    };
  }, [setIsDbReady, setIsAppLocked]);
}