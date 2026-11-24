// useAppLockLifecycle.ts
import { useEffect, useRef } from 'react';
import { AppState, AppStateStatus } from 'react-native';
import BackgroundTimer from 'react-native-background-timer';
import { encryptionService } from '../middleware/EncryptionMiddleware';
import { appStorage } from '../storage/AppStorage';
import { quiesceForLock, connectAndWatch, powerSync } from '../database/AppDatabase';
import { closeSharedMirrorDbAsync, reopenAllMirrors } from '../database/SharedMirrorConnection';
import { generateUUID } from '../utils/itemUtils';
import { recordEvent } from '../api/analytics';
import { useAuth } from '../providers/AuthProvider';
import { createMMKV } from 'react-native-mmkv';

const STANDARD_GRACE_MS = 20_000; // tune
// const STANDARD_GRACE_MS = 10_000; // tune
 
// ─────────────────────────────────────────────────────────────────────────────
// 🔬 RELEASE-SAFE WIPE TIMING DIAGNOSTICS (temporary — remove before final ship)
//
// Writes timestamps to a SEPARATE, UNENCRYPTED MMKV instance — NOT appStorage,
// because appStorage is encrypted by the key that closeAndWipe() wipes. If we
// used appStorage, the diag write inside closeAndWipe (which runs right AFTER
// the key is wiped) could fail, producing a false "no wipe logged" reading.
// This standalone store has no key dependency, so it always reads/writes.
//
// The decisive number is:  wipedAt − backgroundedAt
//   ≈ grace (e.g. 60s) AND wipedAt < foregroundedAt  → wipe ran IN BACKGROUND ✅
//   ≈ foregroundedAt (delta == time you were away)    → wipe ran ON RESUME ❌
//   wipedAt absent but keys gone                       → OS cleared memory ❌
//
// Render readWipeDiag() on a debug <Text> to inspect after each test.
// ─────────────────────────────────────────────────────────────────────────────
const diagStore = createMMKV({ id: 'wipe_diag' }); // plain, unencrypted, no key dependency

const DIAG = {
  bg:   'diag_backgrounded_at',
  wipe: 'diag_wiped_at',
  fg:   'diag_foregrounded_at',
  tier: 'diag_tier',
};

const diagMark = (key: string, value: string | number): void => {
  try { diagStore.set(key, String(value)); } catch {}
};

const diagDelete = (key: string): void => {
  try { diagStore.remove(key); } catch {}
}; 

// Call this from your screen to display the result of the last cycle.
export const readWipeDiag = (): string => {
  try {
    const bg   = parseInt(diagStore.getString(DIAG.bg)   || '0');
    const wipe = parseInt(diagStore.getString(DIAG.wipe) || '0');
    const fg   = parseInt(diagStore.getString(DIAG.fg)   || '0');
    const tier = diagStore.getString(DIAG.tier) || '?';

    if (!bg) return 'DIAG: no background event yet';

    const awayDelta = fg ? Math.round((fg - bg) / 1000) : null; // s actually backgrounded

    // Guard: the test is only valid if you actually stayed backgrounded a while.
    // If away < 30s, this run does not test the background-wipe behaviour.
    if (fg && awayDelta !== null && awayDelta < 30) {
      return [
        `tier: ${tier}`,
        `away total: ${awayDelta}s`,
        `⚠️ INVALID RUN — you were only away ${awayDelta}s.`,
        `Stay backgrounded 90s+ before returning, then read again.`,
      ].join('\n');
    }

    const wipeDelta = wipe ? Math.round((wipe - bg) / 1000) : null;          // s after backgrounding
    const wipeVsFg  = (wipe && fg) ? Math.round((wipe - fg) / 1000) : null;  // <0 = wiped before return

    let verdict = 'UNKNOWN';
    if (!wipe) {
      verdict = 'NO WIPE LOGGED (keys cleared by OS, or never wiped)';
    } else if (!fg) {
      verdict = 'wipe logged, not yet returned';
    } else if (wipe < fg - 1500) {
      verdict = '✅ WIPE RAN IN BACKGROUND (before return)';
    } else {
      verdict = '❌ WIPE RAN ON / AFTER RESUME';
    }

    return [
      `tier: ${tier}`,
      `wipe−bg: ${wipeDelta ?? '—'}s   (grace target ${Math.round(STANDARD_GRACE_MS/1000)}s)`,
      `away total: ${awayDelta ?? '—'}s`,
      `wipe−fg: ${wipeVsFg ?? '—'}s   (negative = wiped before return)`,
      verdict,
    ].join('\n');
  } catch (e) {
    return 'DIAG read error: ' + String(e);
  }
};
 
interface Params {
  setIsDbReady: (v: boolean) => void;
  setIsAppLocked: (v: boolean) => void;
}



// ── Lock / unlock ordering ──────────────────────────────────────────────────
// The database close after a lock takes a moment (queued writes drain first). Coming back within
// a few seconds, the unlock used to reopen the databases while that close was still running –
// the close then shut them again, or the unlock waited on it. Now each lock has a number: the
// unlock tells a running close to stop, waits for it (a few seconds at most), and only lets the
// app in if no new lock happened meanwhile.
let lockEpoch = 0;
let unlockedEpoch = -1;
let teardown: Promise<void> | null = null;

/** Changes with every lock (Max / Vault). */
export const currentLockEpoch = () => lockEpoch;

/** The app is being unlocked: a close still running for the last lock stops where it is. */
export function cancelLockTeardown(): void {
  unlockedEpoch = lockEpoch;
}

/** Resolves when the last lock's close has finished (or after `timeoutMs`). */
export async function waitForLockTeardown(timeoutMs = 5000): Promise<void> {
  const t = teardown;
  if (!t) return;
  let timer: ReturnType<typeof setTimeout> | null = null;
  await Promise.race([
    t.catch(() => {}),
    new Promise<void>((r) => { timer = setTimeout(r, timeoutMs); }),
  ]);
  if (timer) clearTimeout(timer);
}

// shared close routine
async function closeAndWipe(setIsDbReady: (v:boolean)=>void, setIsAppLocked: (v:boolean)=>void, lockUi: boolean) {
  // 1. WIPE KEYS FIRST — synchronous, microseconds, cannot be interrupted by suspension.
  //    This is the security-critical line. It MUST run before any `await`, because an
  //    await can let iOS suspend the process before we return. lockMemory() also clears
  //    the mirror key (extractedMirrorKey), so all JS-side key copies are gone right here.
  encryptionService.lockForBackground(); // lockMemory() + no Face ID until the lock screen asks
  const epoch = ++lockEpoch;
  const stillLocked = () => epoch === lockEpoch && unlockedEpoch !== epoch;
  // diagMark(DIAG.wipe, Date.now());    // 🔬 stamp the moment keys left RAM

  // 2. Lock the UI immediately (synchronous) so no decrypted view can survive.
  if (lockUi) {
    setIsDbReady(false);
    setIsAppLocked(true);
  } 

  // 3. Best-effort DB teardown. If iOS suspends mid-way, keys are ALREADY gone (step 1);
  //    worst case is an unclean-but-encrypted DB file, recovered on next open.
  //    closeSharedMirrorDbAsync() evicts the mirror key from SQLCipher's native memory.
  const run = (async () => {
    try {
      await closeSharedMirrorDbAsync(stillLocked);
      if (!stillLocked()) return;
      await powerSync.disconnect();
      if (!stillLocked()) return;
      await quiesceForLock();
      console.log('🔒 Mirror closed + keys wiped');
    } catch (e) {
      console.warn('[lock] closeAndWipe cleanup cut short (keys already wiped):', e);
    }
  })();
  teardown = run;
  try {
    await run;
  } finally {
    if (teardown === run) teardown = null;
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
      // 🛡️ Shield: intentional Face ID background (settings) — never lock.
      if (encryptionService.isIntentionalBackground) {
        return;
      }

      const isVaultBinding = appStorage.getBoolean('vault_key_binding_enabled');
      // 🔑 Read Max from the ENGINE, not appStorage. appStorage is encrypted and
      //    init-dependent; getBoolean() returns undefined before init() resolves,
      //    which would silently skip the Max wipe. The engine's flag lives in a
      //    plain store and is always readable synchronously.
      const isMaxSecurity  = encryptionService.isBiometricProtectionEnabled();

      // ── Session tracking ───────────────────────────────
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

      // ── BACKGROUND ─────────────────────────────────────
      if (nextAppState === 'background') {
        // 🔬 start a fresh diagnostic cycle: record bg time + tier, clear old wipe/fg
        // const tierName = isMaxSecurity ? 'max' : isVaultBinding ? 'vault' : 'standard';
        // diagMark(DIAG.bg, Date.now());
        // diagMark(DIAG.tier, tierName);
        // diagDelete(DIAG.wipe); diagDelete(DIAG.fg);

        if (isMaxSecurity) {
            // Claim the background execution window so the async DB cleanup inside
            // closeAndWipe can finish before iOS suspends. The KEY WIPE itself is
            // already synchronous-first inside closeAndWipe, so even if this window
            // is short, the keys are gone immediately; start()/stop() just protects
            // the best-effort DB close that follows.
            BackgroundTimer.start();
            backgroundTimestampRef.current = Date.now();
            closeAndWipe(setIsDbReady, setIsAppLocked, true)   // instant: wipe + lock UI
              .finally(() => { BackgroundTimer.stop(); });
            return;
        }

        if (isVaultBinding) {
            backgroundTimestampRef.current = Date.now();
            if (backgroundTimeoutRef.current) BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
            backgroundTimeoutRef.current = BackgroundTimer.setTimeout(() => {
            closeAndWipe(setIsDbReady, setIsAppLocked, true); // after 3 min, locks UI
            backgroundTimeoutRef.current = null;
            }, STANDARD_GRACE_MS);
            return; 
        }

        // Standard
            BackgroundTimer.start();                       // claim the window
          backgroundTimestampRef.current = Date.now(); 
          backgroundTimeoutRef.current = BackgroundTimer.setTimeout(async () => {
            encryptionService.lockMemory();              // sync first
            try { await closeSharedMirrorDbAsync(); } catch {}
            // diagMark(DIAG.wipe, Date.now());
            BackgroundTimer.stop();
          }, STANDARD_GRACE_MS);                                       // 3s, NOT 10–60s
          return; 
      }

    if (nextAppState === 'active') {
        // diagMark(DIAG.fg, Date.now());   // 🔬 stamp the moment of return (before reopen logic)
        // Max/Vault: do NOT silently reopen. Cancel any pending timer; if keys were
        // wiped, SecurityLockScreen handles Face ID and reopen happens in onUnlockSuccess.
        if (isMaxSecurity || isVaultBinding) {
            if (backgroundTimeoutRef.current) {
                BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
                backgroundTimeoutRef.current = null;
            }
            // Vault: if returned within grace and keys still present, no lock needed
            if (isVaultBinding && backgroundTimestampRef.current) {
                const elapsed = (Date.now() - backgroundTimestampRef.current) / 1000;
                backgroundTimestampRef.current = null;
                if (encryptionService.ready && elapsed <= 60) return; // quick return, still unlocked
            }
            // Otherwise keys are (or should be) wiped → ensure lock screen shows
            if (!encryptionService.ready) {
            setIsDbReady(false);
            setIsAppLocked(true);
            }
            return;
        }

        // Standard: silent reopen (unchanged)
        if (backgroundTimeoutRef.current) {
            BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
            backgroundTimeoutRef.current = null;
        }
        if (encryptionService.ready) { backgroundTimestampRef.current = null; return; }
        backgroundTimestampRef.current = null;
        encryptionService.autoUnlock().then(async (unlocked) => {
            if (!unlocked) { console.error('❌ [Standard] Auto-unlock failed.'); return; } 
            await reopenAllMirrors();
            
             if (isAuthRef.current && !powerSync.connected) {
                    await connectAndWatch();
                }
            // if (!powerSync.connected) await connectAndWatch();
        }).catch(e => console.error('❌ [Standard] autoUnlock threw:', e));
        }
    });

    return () => {
      subscription.remove();
      if (backgroundTimeoutRef.current) BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
    };
  }, [setIsDbReady, setIsAppLocked]);
}

// // useAppLockLifecycle.ts
// import { useEffect, useRef } from 'react';
// import { AppState, AppStateStatus } from 'react-native';
// import BackgroundTimer from 'react-native-background-timer';
// import { encryptionService } from '../middleware/EncryptionMiddleware';
// import { appStorage } from '../storage/AppStorage';
// import { quiesceForLock, connectAndWatch, powerSync } from '../database/AppDatabase';
// import { closeSharedMirrorDbAsync, reopenAllMirrors } from '../database/SharedMirrorConnection';
// import { generateUUID } from '../utils/itemUtils';
// import { recordEvent } from '../api/analytics';
// import { useAuth } from '../providers/AuthProvider';

// const STANDARD_GRACE_MS = 60_000; // tune
// // const STANDARD_GRACE_MS = 1_000; // tune
 
// interface Params {
//   setIsDbReady: (v: boolean) => void;
//   setIsAppLocked: (v: boolean) => void;
// }



// // shared close routine
// async function closeAndWipe(setIsDbReady: (v:boolean)=>void, setIsAppLocked: (v:boolean)=>void, lockUi: boolean) {
//   try {
//     await quiesceForLock();
//     await powerSync.disconnect();
//     await closeSharedMirrorDbAsync();   // evict mirror key from native memory
//     encryptionService.lockMemory();     // wipe all keys from RAM
//     if (lockUi) {
//       setIsDbReady(false);
//       setIsAppLocked(true);
//     }
//     console.log('🔒 Mirror closed + keys wiped');
//   } catch (e) {
//     console.warn('[lock] closeAndWipe failed:', e);
//   }
// }

// export function useAppLockLifecycle({ setIsDbReady, setIsAppLocked }: Params) {
//   const backgroundTimeoutRef = useRef<number | null>(null);
//   const backgroundTimestampRef = useRef<number | null>(null);


//   const { isAuthenticated } = useAuth();
//   const isAuthRef = useRef(isAuthenticated);
//   isAuthRef.current = isAuthenticated;

//   useEffect(() => {
//     const subscription = AppState.addEventListener('change', (nextAppState: AppStateStatus) => {
//       // 🛡️ Shield: intentional Face ID background (settings) — never lock.
//       if (encryptionService.isIntentionalBackground) {
//         return;
//       }

//       const isVaultBinding = appStorage.getBoolean('vault_key_binding_enabled');
//       const isMaxSecurity  = appStorage.getBoolean('max_security_enabled');

//       // ── Session tracking ───────────────────────────────
//       if (nextAppState === 'active') {
//         const sessionId = generateUUID();
//         appStorage.set('current_session_id', sessionId);
//         appStorage.set('session_start_time', Date.now().toString());
//         recordEvent('session_start', { session_id: sessionId });
//       }
//       if (nextAppState === 'background') {
//         const sessionId = appStorage.getString('current_session_id');
//         const startTime = parseInt(appStorage.getString('session_start_time') || '0');
//         if (sessionId && startTime) {
//           const duration_s = Math.round((Date.now() - startTime) / 1000);
//           if (duration_s > 5) {
//             recordEvent('session_end', { session_id: sessionId, duration_s, ended_by: 'background' });
//           }
//           appStorage.delete('current_session_id');
//           appStorage.delete('session_start_time');
//         }
//       }

//       // ── BACKGROUND ─────────────────────────────────────
//       if (nextAppState === 'background') {
//         if (isMaxSecurity) {
//             closeAndWipe(setIsDbReady, setIsAppLocked, true);   // instant, locks UI
//             return;
//         }

//         if (isVaultBinding) {
//             backgroundTimestampRef.current = Date.now();
//             if (backgroundTimeoutRef.current) BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
//             backgroundTimeoutRef.current = BackgroundTimer.setTimeout(() => {
//             closeAndWipe(setIsDbReady, setIsAppLocked, true); // after 3 min, locks UI
//             backgroundTimeoutRef.current = null;
//             }, STANDARD_GRACE_MS);
//             return; 
//         }

//         // Standard
//         backgroundTimestampRef.current = Date.now();
//         if (backgroundTimeoutRef.current) BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
//         backgroundTimeoutRef.current = BackgroundTimer.setTimeout(() => {
//             closeAndWipe(setIsDbReady, setIsAppLocked, false);  // grace, does NOT lock UI
//             backgroundTimeoutRef.current = null;
//             console.log("Memory cleared")
//         }, STANDARD_GRACE_MS);
//         return;
//       }

//     if (nextAppState === 'active') {
//         // Max/Vault: do NOT silently reopen. Cancel any pending timer; if keys were
//         // wiped, SecurityLockScreen handles Face ID and reopen happens in onUnlockSuccess.
//         if (isMaxSecurity || isVaultBinding) {
//             if (backgroundTimeoutRef.current) {
//                 BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
//                 backgroundTimeoutRef.current = null;
//             }
//             // Vault: if returned within grace and keys still present, no lock needed
//             if (isVaultBinding && backgroundTimestampRef.current) {
//                 const elapsed = (Date.now() - backgroundTimestampRef.current) / 1000;
//                 backgroundTimestampRef.current = null;
//                 if (encryptionService.ready && elapsed <= 60) return; // quick return, still unlocked
//             }
//             // Otherwise keys are (or should be) wiped → ensure lock screen shows
//             if (!encryptionService.ready) {
//             setIsDbReady(false);
//             setIsAppLocked(true);
//             }
//             return;
//         }

//         // Standard: silent reopen (unchanged)
//         if (backgroundTimeoutRef.current) {
//             BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
//             backgroundTimeoutRef.current = null;
//         }
//         if (encryptionService.ready) { backgroundTimestampRef.current = null; return; }
//         backgroundTimestampRef.current = null;
//         encryptionService.autoUnlock().then(async (unlocked) => {
//             if (!unlocked) { console.error('❌ [Standard] Auto-unlock failed.'); return; } 
//             await reopenAllMirrors();
            
//              if (isAuthRef.current && !powerSync.connected) {
//                     await connectAndWatch();
//                 }
//             // if (!powerSync.connected) await connectAndWatch();
//         }).catch(e => console.error('❌ [Standard] autoUnlock threw:', e));
//         }
//     });

//     return () => {
//       subscription.remove();
//       if (backgroundTimeoutRef.current) BackgroundTimer.clearTimeout(backgroundTimeoutRef.current);
//     };
//   }, [setIsDbReady, setIsAppLocked]);
// }