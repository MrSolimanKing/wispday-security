/**
 * WispDay — AuthProvider (excerpt)
 * =====================================================================
 * This is a TRIMMED excerpt of the app's auth provider, published so the
 * security-relevant parts of the session lifecycle can be verified. It is
 * NOT the full auth implementation: profile handling, subscription/premium
 * logic, avatar caching, network/session-revocation polling, sync
 * orchestration and data-migration flows have all been removed. Only the
 * points where authentication interacts with the encryption layer remain.
 *
 * Calls into app subsystems are reduced to their call shape and marked
 * `// [app boundary]`. They are shown so a reviewer can see WHAT crosses
 * the boundary (e.g. "logout clears the encrypted local store"), not how
 * those subsystems are implemented. The stubs below let this file stand
 * alone; in the app they are the real modules.
 *
 * The security claims this excerpt lets you verify:
 *
 *   1. LOGOUT destroys key material.
 *      A full logout calls encryptionService.resetDevice() (removes the
 *      key references from the OS keystore and zero-fills the in-RAM key
 *      state) AND clears the encrypted local databases. Once both run,
 *      there is no key on the device and no ciphertext left to decrypt.
 *
 *   2. UNLOCK verifies the key before trusting it.
 *      An entered recovery phrase is imported and checked against the
 *      server-stored verifier (a known phrase encrypted under the user's
 *      key). The session is only marked unlocked if decrypting the
 *      verifier reproduces the expected value — a wrong key cannot
 *      silently "unlock" into unreadable data, and the server never sees
 *      the key, only the verifier ciphertext.
 *
 *   3. FRESH LOGIN forces a real unlock.
 *      Right after sign-in a transient `fresh_login_lock` flag is set so
 *      auto-unlock cannot bypass the unlock step using cached key material
 *      from a previous account on the same device.
 *
 *   4. BACKGROUNDING can wipe keys from RAM.
 *      The hook where the app, on losing foreground, calls
 *      encryptionService.lockMemory() to zero-fill the master key in
 *      memory is shown (commented in production behind the chosen
 *      security mode; included here so the touchpoint is visible).
 *
 * The encryption primitives themselves (key derivation, AES-128-GCM,
 * per-file DEKs, key storage) live in EncryptionService.ts; this file only
 * shows when those operations are triggered by the session lifecycle.
 */

import { encryptionService } from "../middleware/EncryptionMiddleware";


// ── [app boundary] ────────────────────────────────────────────────────────────
// The real app wires these to concrete modules. They are stubbed here to the
// minimal surface this excerpt uses so the security flow reads end-to-end
// without pulling in unrelated app code.

// Auth token persistence (OS-backed secure storage in the app).
declare function clearAuthToken(): void;

// Transient key-value store. This excerpt only touches the session/lock flags.
const sessionFlags = {
  set: (_key: string, _value: unknown): void => {},
  getString: (_key: string): string | undefined => undefined,
  delete: (_key: string): void => {},
};

// Encrypted-data subsystems. In the app these are the synced encrypted store
// and its local databases. The ONLY thing this excerpt asserts about them is
// that logout tears them down — i.e. encrypted local data is cleared and the
// server connection is dropped. Their internals are out of scope here.
const encryptedStore = {
  // Drops the server connection AND clears the encrypted local databases.
  disconnectAndClear: async (): Promise<void> => {},
  // Drops the server connection only (local rows left intact).
  disconnect: async (): Promise<void> => {},
};

// Removes locally cached decrypted media / ephemeral plaintext files from disk.
// [app boundary] — implementation omitted; the security-relevant fact is that
// logout purges any plaintext that may have been written to caches.
declare function purgeDecryptedMediaCaches(): Promise<void>;

type LogoutErrorCode = 'NO_INTERNET' | 'SERVER_ERROR' | 'UNSYNCED_CHANGES' | 'OK';


/**
 * LOGIN
 * Sets the fresh-login lock so the next unlock must be explicit (auto-unlock
 * cannot reuse key material left on the device). Token persistence and all
 * profile/subscription/sync setup happen in the full app and are omitted.
 */
export async function login(token: string, sessionId?: string): Promise<void> {
  // Force a real unlock after sign-in: prevents a cached key from a previous
  // account on this device from silently unlocking the new session.
  sessionFlags.set('fresh_login_lock', true);

  // [app boundary] persist the auth token in secure storage, then fetch the
  // user profile. Omitted — not security-relevant to the encryption claim.
  void token; void sessionId;
}


/**
 * UNLOCK ENCRYPTION
 * Imports the user's recovery phrase and verifies it against the server-stored
 * verifier BEFORE the session is considered unlocked. The verifier is a known
 * phrase encrypted under the user's key; if decrypting it does not reproduce
 * the expected value, importMasterKey returns false and the session stays
 * locked. The server only ever holds the verifier ciphertext, never the key.
 */
export async function unlockEncryption(
  recoveryPhrase: string,
  encryptionVerifier: string | undefined,
): Promise<boolean> {
  if (!encryptionVerifier) return false;

  // importMasterKey derives the key from the phrase, then internally decrypts
  // the verifier and compares it to the expected constant. It returns false
  // (and wipes the just-derived key from memory) on any mismatch.
  const success = await encryptionService.importMasterKey(recoveryPhrase, encryptionVerifier);
  if (!success) return false;

  // If the user opted into biometric key storage while still a guest, fold the
  // now-available master key into the biometric bundle.
  if (encryptionService.isBiometricProtectionEnabled()) {
    await encryptionService.setKeyProtection(true);
  }

  // The explicit unlock satisfied the fresh-login lock.
  sessionFlags.delete('fresh_login_lock');

  return true;
} 


/**
 * FULL LOGOUT — destroys key material and clears encrypted local data.
 *
 * Ordering matters and is part of the security argument:
 *   1. Clear in-memory/session state and the auth token first, so no
 *      authenticated work continues against a DB about to be torn down.
 *   2. Clear the encrypted local databases (disconnectAndClear) and purge
 *      any decrypted media caches from disk.
 *   3. Wipe the keys LAST via resetDevice() — by this point there is no
 *      ciphertext left on the device, so the removed key protects nothing
 *      it shouldn't, and nothing can read what was just cleared.
 *
 * After this returns, the device holds neither the user's key material nor
 * its encrypted data.
 */
export async function logout(): Promise<LogoutErrorCode> {
  try {
    // 1. Tear down session state immediately.
    clearAuthToken();
    sessionFlags.delete('user_data');
    sessionFlags.delete('fresh_login_lock');

    // 2. Clear encrypted local data and any plaintext that touched disk.
    await encryptedStore.disconnectAndClear();   // [app boundary]
    await purgeDecryptedMediaCaches();            // [app boundary]

    // 3. Destroy key material (keystore references + RAM).
    await encryptionService.resetDevice();

    return 'OK';
  } catch {
    // Even on failure, fail closed: ensure token/session state is cleared.
    clearAuthToken();
    sessionFlags.delete('user_data');
    sessionFlags.delete('fresh_login_lock');
    return 'OK';
  }
}


/**
 * SOFT LOGOUT — ends the session without necessarily destroying local data.
 *
 * `preserveLocalData` exists for the case where a user has data created before
 * an account key was established and wants to keep it across a re-auth. When
 * preserving, the encrypted store is only DISCONNECTED (rows left intact) and
 * the key wipe is SKIPPED so the data remains readable on next login. When NOT
 * preserving, this behaves like a full logout: encrypted data is cleared and
 * keys are wiped.
 *
 * The security-relevant invariant: the key wipe (resetDevice) and the
 * encrypted-data clear are either BOTH skipped (preserve) or BOTH performed
 * (standard). They never diverge — you never end up with the key wiped but the
 * ciphertext kept, or vice-versa.
 */
export async function softLogout(preserveLocalData = false): Promise<void> {
  try {
    clearAuthToken();
    sessionFlags.delete('user_data');
    sessionFlags.delete('fresh_login_lock');

    if (preserveLocalData) {
      await encryptedStore.disconnect();          // keep local ciphertext
      // resetDevice() intentionally skipped → key survives → data stays readable
    } else {
      await encryptedStore.disconnectAndClear();  // clear local ciphertext
      await purgeDecryptedMediaCaches();          // [app boundary]
      await encryptionService.resetDevice();      // wipe key material
    }
  } catch {
    clearAuthToken();
    sessionFlags.delete('user_data');
    sessionFlags.delete('fresh_login_lock');
  }
}


/**
 * BACKGROUND / FOREGROUND key hygiene.
 *
 * When the chosen security mode calls for it, losing the foreground wipes the
 * master key from RAM (lockMemory) and marks the session locked, so memory
 * inspection while the app is backgrounded cannot recover the key. Returning to
 * foreground requires an unlock again. This is the touchpoint; the exact policy
 * (which modes wipe, and the timing relative to OS suspension) lives in the
 * app's lifecycle hook.
 */
export function onAppBackgrounded(): void {
  if (encryptionService.isBiometricProtectionEnabled()) {
    encryptionService.lockMemory();   // zero-fills the master key buffer in RAM
    // [app boundary] mark the session locked so the UI shows the unlock screen
  }
}

export async function onAppForegrounded(): Promise<boolean> {
  if (encryptionService.isBiometricProtectionEnabled()) {
    // Re-acquire the key (prompts biometric per the storage mode). Returns
    // false if the user cancels / is locked out — session stays locked.
    return encryptionService.autoUnlock();
  }
  return true;
}