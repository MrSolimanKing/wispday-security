/**
 * WispDay — Route.tsx high level under the App.tsx (excerpt)
 * =====================================================================
 * This is a TRIMMED excerpt of the app's root component. The full root
 * wires up theming, subscriptions, navigation and the entire provider
 * tree — none of which is security-relevant — and those are collapsed to
 * a single `[app boundary]` placeholder here. What remains is the boot /
 * unlock security gate: the logic that decides, at startup and on unlock,
 * whether the app may show decrypted content.
 *
 * What a reviewer can verify from this excerpt:
 *
 *   1. COLD-START FAILS LOCKED. Initial locked state is derived
 *      synchronously: if biometric key binding is enabled and the key is
 *      not already in RAM, the app starts LOCKED. A killed-and-relaunched
 *      app therefore does not come back unlocked — it must pass the lock
 *      screen first. The database init is gated on this: startDb() only
 *      runs when the app is not locked.
 *
 *   2. KEY-ACCESS FAILURES NEVER WIPE DATA. startDb() classifies init
 *      errors. A failure to READ the biometric key (temporary lockout,
 *      user cancel, or a key invalidated by a biometric change) returns to
 *      the lock screen and wipes nothing — the database is intact and the
 *      user can retry. Only a genuine key/DB mismatch offers a reset, and
 *      that reset is destructive ONLY on explicit user confirmation. The
 *      app never silently destroys local data on a key error.
 *
 *   3. UNLOCK GATES UI ON KEY RESTORATION. The lock screen is shown
 *      whenever the app is locked; its onUnlockSuccess reopens the
 *      encrypted databases and recovers the session BEFORE the UI is
 *      unlocked, so no decrypted view is mounted until keys are back.
 *
 * Key operations live in EncryptionService.ts. App wiring (DB init, the
 * provider tree, session recovery, analytics) is marked `[app boundary]`.
 */

import React, { useEffect, useState } from 'react';
import { Alert, BackHandler, Platform } from 'react-native';
import BootSplash from 'react-native-bootsplash';

import { appStorage } from '../storage/AppStorage';
import { encryptionService } from '../middleware/EncryptionMiddleware';
import { useAppLockLifecycle } from '../hooks/useAppLockLifecycle.ts';
import { SecurityLockScreen } from '../screens/security/SecurityLockScreen.tsx';

// [app boundary] — encrypted-database init / teardown / rotation. The
// security-relevant facts are only how their RESULTS are handled below.
declare function initializePowerSync(): Promise<void>;
declare function rotateDatabaseFiles(): Promise<void>;
declare function reopenAllMirrors(): Promise<void>;
declare function recordEvent(name: string, props?: Record<string, unknown>): void;

// [app boundary] — auth context. Only the pieces the gate uses are shown.
declare function useAuth(): {
  user: unknown;
  isEncryptionReady: boolean;
  recoverSession: () => Promise<void>;
  softLogout?: () => Promise<void>;
};

// [app boundary] — the full app once unlocked (provider tree, navigation,
// screens). Collapsed: its internals are not part of this repo.
declare function AppShell(props: { theme: any }): React.ReactElement;

export function Router({ theme }: { theme: any }) {
  const { user, isEncryptionReady, recoverSession, softLogout } = useAuth();

  const [isDbReady, setIsDbReady] = useState(false);

  // (1) COLD-START LOCK DECISION — synchronous, at first render.
  // If biometric binding is on and the key is not already in RAM, start LOCKED.
  const [isAppLocked, setIsAppLocked] = useState(() => {
    const vaultEnabled = appStorage.getBoolean('vault_key_binding_enabled');
    return !!vaultEnabled && !encryptionService.ready;
  });

  // (2) DATABASE INIT WITH FAIL-SAFE ERROR CLASSIFICATION.
  const startDb = async () => {
    try {
      await initializePowerSync();   // [app boundary] opens the encrypted DBs
      setIsDbReady(true);
    } catch (error: any) {
      const msg = String(error?.message || '');

      // Case A — could not READ the key. NOT corruption; the DB is fine.
      // Covers temporary lockout/cancel and a key invalidated by a biometric
      // change. Return to the lock screen and wipe NOTHING.
      const biometricOn = encryptionService.isBiometricProtectionEnabled();
      const isKeyAccessFailure =
        msg === 'AUTH_TEMPORARILY_UNAVAILABLE' ||
        msg === 'BIOMETRIC_BUNDLE_UNAVAILABLE' ||
        msg.includes('Device_Key_Failure') ||
        msg.includes('Device_Key_Missing');

      if (biometricOn && isKeyAccessFailure) {
        console.warn('🔐 [Boot] Biometric key not available right now — returning to lock screen');
        try { BootSplash.hide({ fade: true }); } catch {}
        recordEvent('app_error', { error: 'biometric_key_failure', screen: 'startup' });
        encryptionService.lockMemory();
        setIsDbReady(false);
        setIsAppLocked(true);
        return;
      }

      // Case B — genuine key/DB mismatch. Offer a reset, but make it
      // DESTRUCTIVE ONLY on explicit user confirmation. Cloud-synced data is
      // unaffected; this only resets the local encrypted DB files.
      const isKeyMismatch =
        msg === 'CORRUPT_DB_KEY_MISMATCH' ||
        msg.includes('file is not a database') ||
        msg.includes('not a database') ||
        msg.includes('SQLITE_NOTADB');

      if (isKeyMismatch) {
        try { BootSplash.hide({ fade: true }); } catch {}
        recordEvent('app_error', { error: 'db_key_mismatch', screen: 'startup' });

        Alert.alert(
          'Storage Reset Required',
          'We detected an issue with your local database encryption.\n\nYour cloud-synced data is completely safe.',
          [
            { text: 'Cancel', style: 'cancel' },
            {
              text: 'Reset & Close App',
              style: 'destructive',
              onPress: async () => {
                await rotateDatabaseFiles();        // [app boundary]
                if (softLogout) await softLogout(); // [app boundary] ends session
                Alert.alert(
                  'Reset Complete',
                  'Please close the app and reopen it.',
                  [{ text: 'Got it', onPress: () => { if (Platform.OS === 'android') BackHandler.exitApp(); } }],
                  { cancelable: false },
                );
              },
            },
          ],
        );
        return;
      }

      // Case C — anything else. Never hang on the splash; offer a retry that
      // clears stale key/init state first so it genuinely re-runs.
      console.error('❌ [Boot] DB init failed (unclassified):', error);
      try { BootSplash.hide({ fade: true }); } catch {}
      Alert.alert(
        'Startup Problem',
        'The app had trouble starting up. Please try again, or close and reopen the app.',
        [
          { text: 'Try Again', onPress: () => { encryptionService.lockMemory(); startDb(); } },
          { text: 'Cancel', style: 'cancel' },
        ],
        { cancelable: true },
      );
    }
  };

  // Boot the DB only when the app is NOT locked. While locked, the lock
  // screen owns the flow and startDb runs after a successful unlock.
  useEffect(() => {
    if (!isAppLocked) {
      startDb();
    }
  }, [isAppLocked]);

  // Background/foreground key-wipe lifecycle (wipes the key from RAM on
  // background; see useAppLockLifecycle).
  useAppLockLifecycle({ setIsDbReady, setIsAppLocked });

  // (3) LOCK GATE. While locked, render ONLY the lock screen. onUnlockSuccess
  // reopens the encrypted DBs and recovers the session BEFORE unlocking the UI.
  if (isAppLocked) {
    return (
      <SecurityLockScreen
        theme={theme}
        softLogout={softLogout}
        onSecureLogout={() => setIsAppLocked(false)}
        onUnlockSuccess={async () => {
          // Keys are back in RAM (the lock screen's tryUnlock loaded them).
          // Reopen the encrypted databases BEFORE unlocking the UI.
          try {
            await reopenAllMirrors();   // [app boundary]
          } catch (e) {
            console.warn('[Unlock] DB reopen failed:', e);
          }
          await recoverSession();        // [app boundary]
          setIsAppLocked(false);
        }}
      />
    );
  }

  // Do not render the app until the encrypted DB is open.
  if (!isDbReady) return null;

  // [app boundary] — the full provider tree / navigation / screens. The gate
  // above guarantees this is only reached with keys loaded and DBs open.
  return <AppShell theme={theme} />;
}