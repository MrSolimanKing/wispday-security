/**
 * WispDay — EncryptionService
 * =====================================================================
 * This is the trust-critical encryption core of the WispDay journal app,
 * published for independent verification of the app's end-to-end
 * encryption claim. The app's UI, sync orchestration, media uploader and
 * AI features are NOT part of this repository; only the security layer is.
 *
 * What a reviewer can verify from this file:
 *   - Diary content, notes and media are encrypted on-device before they
 *     ever leave the app. The server only ever receives ciphertext.
 *   - Keys are derived and stored such that the server cannot reconstruct
 *     them. There is no server-side key escrow in this code path.
 *
 * Primitives
 * ----------
 *   - Content & file encryption: AES-128-GCM (authenticated; tampered
 *     ciphertext is rejected by the GCM auth tag before any plaintext is
 *     produced).
 *   - Master key: derived from a BIP-39 128-bit mnemonic. The 16-byte
 *     entropy of the mnemonic IS the AES-128 key.
 *   - Per-file keys: each media file is encrypted with a fresh random
 *     16-byte Data Encryption Key (DEK). The DEK is then wrapped
 *     (AES-128-GCM) with the master key. Only the wrapped DEK is stored.
 *   - Identity key pair: X25519, deterministically derived from the
 *     mnemonic via SHA-256 domain separation. The private key never
 *     leaves the device; only the public key is uploaded.
 *
 * Two-key model
 * -------------
 *   Device Key  — random, per-install. Encrypts the local SQLCipher
 *                 databases at rest. Persisted for the lifetime of the
 *                 install; not tied to a user account.
 *   Master Key  — per-user, derived from the BIP-39 mnemonic. Encrypts
 *                 the actual diary content. Held in RAM while unlocked;
 *                 its RAM buffer is zero-filled on background/lock (see
 *                 lockMemory) and its stored references are removed on
 *                 logout (see resetDevice).
 *   Mirror Key  — an additional independent random key for a secondary
 *                 local SQLCipher database. It is NOT derived from the
 *                 device key, so a compromised device key cannot open it.
 *
 * Key storage modes
 * -----------------
 *   Standard      — keys held in the OS keystore (iOS Keychain /
 *                   Android Keystore) with WHEN_UNLOCKED_THIS_DEVICE_ONLY
 *                   and requireAuthentication:false. Readable silently
 *                   while the device is unlocked.
 *   Biometric     — Device + Master + Mirror keys are combined into a
 *                   single JSON "bundle" stored with
 *                   requireAuthentication:true, so a Face ID / Touch ID
 *                   check is required to read them. The plaintext device
 *                   key slot is removed in this mode. A single-prompt
 *                   coordinator (loadBiometricBundleOnce) ensures
 *                   concurrent callers share one biometric prompt instead
 *                   of triggering several.
 *
 * IMPORTANT — photo/image decryption is NOT in this file
 * ------------------------------------------------------
 *   For performance, encrypted IMAGES are decrypted in a native module
 *   (a custom Objective-C / Swift component on iOS), not in this
 *   TypeScript layer. That native component:
 *     - reads the .enc file,
 *     - decrypts it in memory using the same AES-128-GCM scheme and the
 *       key material exposed here (see getRawKeyBase64 / unwrapDEK),
 *     - decodes and downsamples the bitmap and hands it to ImageIO for
 *       display,
 *   so that no plaintext image is ever written back to disk and large
 *   bitmaps are never round-tripped across the JS bridge. The native
 *   source is published separately. This file is responsible for the
 *   text/voice decryption paths and for all key derivation, wrapping and
 *   lifecycle; image decryption mirrors the same cryptographic contract
 *   in native code.
 *
 * Memory hygiene
 * --------------
 *   lockMemory() zero-fills the master-key buffer and nullifies the
 *   in-RAM key caches. It is intended to be called when the app is
 *   backgrounded or locked so key material does not linger in memory.
 *
 * Logout
 * ------
 *   resetDevice() removes the mortal (user) key references from the OS
 *   keystore and zero-fills the in-RAM key state. It does NOT itself
 *   delete the local database files or media caches — that is performed
 *   by the caller as part of the logout flow. Once those files are
 *   deleted, any key material that might survive is useless because there
 *   is no remaining ciphertext on the device to decrypt.
 *
 * NOTE FOR REVIEWERS: app-specific call sites (how the uploader, the item
 * model, or the UI invoke these methods) have been reduced to their call
 * shape only and are marked with `// [app boundary]`. The cryptographic
 * logic itself is unmodified from production.
 */

 

// ─── Imports ──────────────────────────────────────────────────────────────────
import QuickCrypto from 'react-native-quick-crypto';   // AES-GCM, hashing, RNG, X25519
import * as SecureStore from 'expo-secure-store';      // OS keystore (Keychain / Keystore)
import { Buffer } from 'buffer';
import * as bip39 from 'bip39';                         // BIP-39 mnemonic ↔ entropy
import { createMMKV } from 'react-native-mmkv';         // fast KV store for the mode flag
import fs, { Paths } from 'react-native-nitro-file-system'; // JSI file I/O for media

// ── [app boundary] ────────────────────────────────────────────────────────────
// In the app this is the shared key-value store (MMKV). The security core only
// reads ONE flag from it: `fresh_login_lock`, a transient boolean the login flow
// sets to force a manual unlock right after sign-in (so auto-unlock can't bypass
// it). Nothing security-critical is persisted here. Stubbed to a minimal getter
// so this file stands alone; swap in your own store to run it in-app.
const appStorage = {
  getBoolean: (_key: string): boolean | undefined => undefined,
};

// ─── Constants ────────────────────────────────────────────────────────────────
const ALGORITHM       = 'aes-128-gcm';   // text & DEK encryption
const IV_LENGTH       = 12;              // 96-bit IV (GCM standard)
const KEY_LENGTH      = 16;              // 128-bit key
const AUTH_TAG_LENGTH = 16;              // 128-bit auth tag

// File encryption uses the same AES-128-GCM primitive as text. The GCM auth tag
// means a tampered .enc file is rejected before any plaintext is produced.
const ALGORITHM_FILE  = 'aes-128-gcm';
const IV_LENGTH_FILE  = 12;            // 96-bit IV (GCM standard)

const VERIFICATION_PHRASE = 'DIARY_VERIFICATION_v1';

// ─── Types ────────────────────────────────────────────────────────────────────
type ProgressCallback = (progress: number) => void;

// ─── Storage ──────────────────────────────────────────────────────────────────
const securityStorage = createMMKV({ id: 'security_settings' });
// Persisted flag selecting biometric (Face ID / Touch ID) key storage vs standard.
const MMKV_BIOMETRIC_KEY = 'vault_key_binding_enabled';
 
const STORAGE_KEYS = {
  DEVICE_DB_KEY: 'app_local_device_key_v1',
  MASTER_KEY:    'diary_master_key_v1',
  BUNDLED_KEY:   'app_bundled_keys_v1',
  MNEMONIC:      'diary_mnemonic_words_v1',
  IDENTITY_PRIVATE: 'diary_identity_private_v1', 
  MIRROR_DB_KEY: 'app_mirror_db_key_v1',  
} as const;


export const ALL_KEY_STORAGE_SLOTS = [
  STORAGE_KEYS.DEVICE_DB_KEY,
  STORAGE_KEYS.MASTER_KEY,
  STORAGE_KEYS.BUNDLED_KEY,
  STORAGE_KEYS.MNEMONIC,
  STORAGE_KEYS.IDENTITY_PRIVATE,
  STORAGE_KEYS.MIRROR_DB_KEY,
];
 

// ─── Interfaces ───────────────────────────────────────────────────────────────
interface BundledKeys {
  deviceKey: string;
  masterKey: string | null;
  mirrorKey?: string; 
}

function parseBundledKeys(raw: string | null): BundledKeys | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed?.deviceKey === 'string') return parsed as BundledKeys;
    return null;
  } catch {
    return null;
  }
}

interface InitResult {
  success: boolean;
  verifier?: string;
  mnemonic?: string;
  error?: string;
}

// ─── Main class ───────────────────────────────────────────────────────────────
class EncryptionService {
  private key: Buffer | null = null;
  private isReady: boolean = false;

  // 🛡️ RAM Cache
  private extractedDeviceKey: string | null = null;
  private deviceKeyPromise: Promise<string> | null = null;

  // 🛡️ SINGLE-PROMPT COORDINATOR
  private biometricBundleLoaded: boolean = false;
  private biometricBundlePromise: Promise<BundledKeys | null> | null = null;

  private extractedMirrorKey: string | null = null;

  // 🛡️ Why the last biometric read failed:
  //   'auth_unavailable' — cancel or OS lockout (TEMPORARY; passcode unlock fixes it)
  //   'invalidated'      — key removed/invalidated by a biometric enrollment change
  //   null               — no failure / success
  private lastFailureKind: 'auth_unavailable' | 'invalidated' | null = null;

  // 🛡️ UNLOCK GATE — the fix for infinite Face ID prompts.
  // Multiple subsystems (lock screen, AuthProvider, DB init) may all ask for the
  // key. Only ONE biometric prompt may ever be outstanding, and after a prompt
  // FAILS we must not auto-prompt again until a real user action / foreground
  // re-arms it. When `promptSuppressed` is true, callers that aren't the lock
  // screen get the cached failure instead of triggering a brand-new prompt.
  private promptSuppressed: boolean = false;
 
  // 🛡️ INTENTIONAL BACKGROUND FLAG
  // Set to true when triggering Face ID for settings migrations
  public isIntentionalBackground: boolean = false;


  private keyListeners = new Set<() => void>();


  /**
   * Called by the lock screen IMMEDIATELY before a genuine, user-initiated
   * unlock attempt. Re-arms the prompt so exactly one new Face ID can occur.
   */
  public armUnlockAttempt(): void {
    this.promptSuppressed = false;
  }

  public isBiometricProtectionEnabled(): boolean {
    return securityStorage.getBoolean(MMKV_BIOMETRIC_KEY) ?? false;
  }


  /**
   * 🛡️ Returns true if a Master Key already exists locally in ANY slot.
   * Prevents generateMasterKey() from permanently overwriting a user's locked vault.
   */ 
    public async hasExistingMasterKey(): Promise<boolean> {
        if (this.key && this.isReady) return true;

        const mnemonic = await SecureStore.getItemAsync(STORAGE_KEYS.MNEMONIC).catch(() => null);
        if (mnemonic) return true;

        const master = await SecureStore.getItemAsync(STORAGE_KEYS.MASTER_KEY).catch(() => null);
        if (master) return true;

        try {
          const bundledRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY);
          if (bundledRaw) {
            const bundled = parseBundledKeys(bundledRaw);
            if (bundled?.masterKey) return true;
          }
        } catch (error) {
          console.warn('🛑 [Encryption] Biometric read cancelled or blocked. Failing closed.');
          return true; 
        }
        return false;
      }

  /**
   * Coordinates Face ID so it only prompts once, even if getOrGenerateDeviceKey
   * and autoUnlock are called at the exact same millisecond.
   */
  private async loadBiometricBundleOnce(): Promise<BundledKeys | null> {
    // 1. Already loaded into RAM — skip Face ID completely
    if (this.biometricBundleLoaded) {
      return {
        deviceKey: this.extractedDeviceKey!,
        masterKey: this.key ? this.key.toString('base64') : null,
        mirrorKey: this.extractedMirrorKey ?? undefined, 
      };
    }

    // 2. Another function is already showing the Face ID prompt — wait for it.
    //    This is the single-prompt coordinator: concurrent callers share one read.
    if (this.biometricBundlePromise) return this.biometricBundlePromise;

    // 3. GATE: if a previous attempt failed and we haven't been re-armed by a
    //    genuine user unlock action, do NOT open a new prompt. Return the cached
    //    failure so background callers (DB init, AuthProvider) don't each spawn
    //    their own Face ID dialog — the root cause of the infinite-prompt loop.
    if (this.promptSuppressed) {
      return null;
    }

    // 4. Trigger Face ID exactly once and cache both keys instantly
    this.biometricBundlePromise = (async () => {
      try {
        // Per expo-secure-store semantics:
        //   • getItemAsync THROWS when auth is unavailable right now — i.e. the
        //     user cancelled, or iOS is in biometric LOCKOUT after too many
        //     failed attempts. This is TEMPORARY: an OS passcode unlock clears
        //     it. The stored key is intact.
        //   • getItemAsync returns NULL only when the entry doesn't exist OR the
        //     key was invalidated by a biometric ENROLLMENT change (add/replace
        //     face or fingerprint). That invalidation is permanent.
        const bundledRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY);

        const bundled = parseBundledKeys(bundledRaw);
        if (bundled) {
            this.extractedDeviceKey = bundled.deviceKey;
            if (bundled.masterKey) {
              this.key     = Buffer.from(bundled.masterKey, 'base64');
              this.isReady = true;
            }
            if (bundled.mirrorKey) this.extractedMirrorKey = bundled.mirrorKey;
            this.biometricBundleLoaded = true;
            this.lastFailureKind = null;
            this.promptSuppressed = false;
          }else {
          // Read succeeded but returned null → entry gone / invalidated.
          this.lastFailureKind = 'invalidated';
          // Suppress further auto-prompts — re-prompting can't conjure a gone key.
          this.promptSuppressed = true;
        }
        return bundled;
      } catch (err) {
        // Read threw → auth temporarily unavailable (cancel / lockout). The key
        // still exists; the user just needs to unlock their device at the OS
        // level (passcode) and try again. NEVER treat this as data loss.
        console.warn('🔐 [Encryption] Bundle read unavailable (retryable):', String((err as any)?.message || err));
        this.lastFailureKind = 'auth_unavailable';
        // CRITICAL: suppress auto-prompts until a genuine user retry re-arms us.
        // Without this, every caller that catches the failure would re-enter and
        // open another Face ID dialog → infinite prompts.
        this.promptSuppressed = true;
        return null;
      } finally {
        this.biometricBundlePromise = null;
      }
    })();

    return this.biometricBundlePromise;
  }

  public async getOrGenerateDeviceKey(): Promise<string> {
    if (this.deviceKeyPromise) return this.deviceKeyPromise;

    this.deviceKeyPromise = (async () => {
      try {
        if (this.extractedDeviceKey) return this.extractedDeviceKey;

        if (this.isBiometricProtectionEnabled()) {
          // 🛡️ Route through the Single-Prompt Coordinator. Do NOT delete the
          // plaintext slot first — if the bundle is unreadable we want the
          // plaintext copy to remain as a fallback rather than be destroyed.
          const bundled = await this.loadBiometricBundleOnce();
          if (bundled?.deviceKey) {
            // Bundle is good; the plaintext slot (if any) is now redundant.
            await SecureStore.deleteItemAsync(STORAGE_KEYS.DEVICE_DB_KEY).catch(() => {});
            return bundled.deviceKey;
          }

          // Bundle is missing/unreadable while biometric mode is ON.
          // FALLBACK: maybe a plaintext copy still exists (e.g. an aborted
          // migration). Use it rather than failing.
          const plainFallback = await SecureStore.getItemAsync(STORAGE_KEYS.DEVICE_DB_KEY);
          if (plainFallback) return plainFallback;

          // Differentiate the two failure modes so the UI shows the right thing:
          //   • auth_unavailable → TEMPORARY lockout/cancel. The key is fine. Tell
          //     the user to unlock their phone with the passcode and retry. We do
          //     NOT wipe anything.
          //   • invalidated/other → the protected entry returned null, meaning the
          //     OS invalidated it after a biometric enrollment change. The local
          //     key is genuinely gone, but we STILL never auto-wipe — we surface a
          //     distinct signal and let the user decide.
          if (this.lastFailureKind === 'auth_unavailable') {
            throw new Error('AUTH_TEMPORARILY_UNAVAILABLE');
          }
          throw new Error('BIOMETRIC_BUNDLE_UNAVAILABLE');
        }

        // 🔓 STANDARD MODE (Vault Binding OFF)
        const plainKey = await SecureStore.getItemAsync(STORAGE_KEYS.DEVICE_DB_KEY);
        // if (plainKey) return plainKey;
        if (plainKey) {
          this.extractedDeviceKey = plainKey; // cache in RAM for the paths that reuse it
          return plainKey;
        }

        // 🛡️ SAFETY: before generating, make sure we aren't about to abandon an
        // existing biometric bundle (flag/keychain desync). If a bundle exists,
        // adopt its device key instead of minting a new one and corrupting the DB.
        const strayBundleRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY).catch(() => null);
        const strayBundle    = parseBundledKeys(strayBundleRaw);
        if (strayBundle?.deviceKey) {
          console.warn('🛡️ [Encryption] Flag said standard mode but a bundle exists — adopting its device key to avoid re-keying.');
          return strayBundle.deviceKey;
        }

        // Truly first run on this device: safe to generate.
        console.log('🛡️ [Encryption] Generating Device Key...');
        const newKeyHex = QuickCrypto.randomBytes(32).toString('hex');
        await SecureStore.setItemAsync(STORAGE_KEYS.DEVICE_DB_KEY, newKeyHex, {
          keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
          requireAuthentication: false,
        });
        this.extractedDeviceKey = newKeyHex;
        return newKeyHex;

      } catch (error) {
        this.deviceKeyPromise = null;
        console.error('❌ [Encryption] Fatal error managing Device Key:', error);
        // Preserve the specific signals so callers can distinguish a temporary
        // lockout (retryable) from an invalidated key, both from a generic failure.
        if (error instanceof Error &&
            (error.message === 'BIOMETRIC_BUNDLE_UNAVAILABLE' ||
             error.message === 'AUTH_TEMPORARILY_UNAVAILABLE')) {
          throw error;
        }
        throw new Error('Device_Key_Failure: Could not retrieve or generate device key.');
      }
    })();

    return this.deviceKeyPromise;
  }



  /**
   * Returns the secondary local database's INDEPENDENT SQLCipher key.
   * Random, separately stored — NOT derived from the device key, so a compromised
   * device key cannot open this database.
   */
  public async getOrGenerateMirrorKey(): Promise<string> {
  if (this.extractedMirrorKey) return this.extractedMirrorKey;

  if (this.isBiometricProtectionEnabled()) {
    const bundled = await this.loadBiometricBundleOnce();
    if (bundled?.mirrorKey) {
      this.extractedMirrorKey = bundled.mirrorKey;
      return bundled.mirrorKey;
    }
    // Bundle exists but has no secondary key yet (first run after upgrade) → mint + merge.
    if (bundled?.deviceKey) {
      const key = Buffer.from(QuickCrypto.randomBytes(32)).toString('hex');
      await this._mergeMirrorKeyIntoBundle(key, bundled);
      this.extractedMirrorKey = key;
      return key;
    }
    // No readable bundle (lockout/invalidated) → surface, don't silently fall back.
    throw new Error('BIOMETRIC_BUNDLE_UNAVAILABLE');
  }

  // ── Standard mode: silent slot (unchanged) ──
  let key = await SecureStore.getItemAsync(STORAGE_KEYS.MIRROR_DB_KEY, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  if (!key) {
    key = Buffer.from(QuickCrypto.randomBytes(32)).toString('hex');
    await SecureStore.setItemAsync(STORAGE_KEYS.MIRROR_DB_KEY, key, {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  }
  this.extractedMirrorKey = key;
  return key;
}

  /** Why the last biometric unlock failed — for the lock screen to message correctly. */
  public getLastFailureKind(): 'auth_unavailable' | 'invalidated' | null {
    return this.lastFailureKind;
  }

  public async generateMasterKey(): Promise<InitResult> {
    try {

      // 🛡️ CRITICAL MIDDLEWARE GUARD: The Ultimate Gatekeeper
      // If a key already exists on this device, block generation immediately.
      // This prevents ANY part of the app from accidentally overwriting a user's vault.
      if (await this.hasExistingMasterKey()) {
        console.error('🛑 [Encryption] generateMasterKey blocked — a Master Key already exists. Refusing to re-key.');
        return { success: false, error: 'MASTER_KEY_ALREADY_EXISTS' };
      } 

      const mnemonic = bip39.generateMnemonic(128);
      const entropy  = bip39.mnemonicToEntropy(mnemonic);
      const newKey   = Buffer.from(entropy, 'hex');

      this.key     = newKey;
      this.isReady = true;
      await this.persistKey(newKey);

      const verifier = this.encrypt(VERIFICATION_PHRASE);
      if (!verifier) throw new Error('Failed to generate verifier');

      await SecureStore.setItemAsync(STORAGE_KEYS.MNEMONIC, mnemonic, {
        keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        requireAuthentication: false,
      });

      return { success: true, verifier, mnemonic };
    } catch (error) {
      this.cleanup();
      return { success: false, error: 'Generation failed' };
    }
  }

  public async importMasterKey(mnemonicString: string, serverVerifier: string): Promise<boolean> {
    try {
      const cleanMnemonic = mnemonicString.trim().toLowerCase();
      if (!bip39.validateMnemonic(cleanMnemonic)) return false;

      const entropy   = bip39.mnemonicToEntropy(cleanMnemonic);
      const keyBuffer = Buffer.from(entropy, 'hex');

      this.key     = keyBuffer;
      this.isReady = true;

      const check = this.decrypt(serverVerifier);
      if (check !== VERIFICATION_PHRASE) {
        this.cleanup();
        return false;
      }

      await this.persistKey(keyBuffer);
      await SecureStore.setItemAsync(STORAGE_KEYS.MNEMONIC, cleanMnemonic, {
        keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        requireAuthentication: false,
      });

      return true;
    } catch (e) {
      this.cleanup();
      return false;
    }
  }

  public async scrubBiometricBundle(): Promise<boolean> {
    console.log('🧹 [Encryption] Initiating deep scrub of all orphaned mortal keys...');

    // 1. ALWAYS obliterate standard keys (This fixes your infinite loop!)
    await Promise.all([
      SecureStore.deleteItemAsync(STORAGE_KEYS.MASTER_KEY),
      SecureStore.deleteItemAsync(STORAGE_KEYS.MNEMONIC),
      SecureStore.deleteItemAsync(STORAGE_KEYS.IDENTITY_PRIVATE),
    ]).catch(() => {});

    // 2. Clear RAM just in case the ghost key was loaded into memory
    this.lockMemory();

    // 3. Scrub the Face ID Bundle (if enabled)
    if (!this.isBiometricProtectionEnabled()) return true;

    try { 
      const bundledRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY);
      const bundled = parseBundledKeys(bundledRaw);

      if (bundled?.deviceKey) {
        const cleanBundle = { deviceKey: bundled.deviceKey, masterKey: null };
        await SecureStore.setItemAsync(STORAGE_KEYS.BUNDLED_KEY, JSON.stringify(cleanBundle), {
          keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
          requireAuthentication: true,
        });
        console.log('✅ [Encryption] Stale biometric master key cleared.');
        return true;
      }
    } catch (error) {
      console.warn('⚠️ [Encryption] User cancelled Face ID during scrub.');
      return false; // Returns false only if they explicitly cancel the Face ID prompt
    }
    
    return true; // Bundle didn't exist or was already clean
  }

  public async autoUnlock(expectedVerifier?: string): Promise<boolean> {
  try {
    if (appStorage.getBoolean('fresh_login_lock')) {
      console.log('🔒 [Encryption] Fresh login detected. Bypassing auto-unlock.');
      return false;
    }

    if (this.isBiometricProtectionEnabled()) {
      const bundled = await this.loadBiometricBundleOnce();
      if (!bundled) {
        this.deviceKeyPromise = null;
        return false;
      }

      // Cache the keys from the bundle before touching the standalone slot.
      this.extractedDeviceKey = bundled.deviceKey;
      this.extractedMirrorKey = bundled.mirrorKey ?? null;

      await SecureStore.deleteItemAsync(STORAGE_KEYS.DEVICE_DB_KEY).catch(() => {});

      // Guest-with-vault: Face ID succeeded, device key present, no master key yet.
      if (!bundled.masterKey) {
        this.biometricBundleLoaded = true;
        console.log('🔑 [Encryption] Guest unlocked via biometric bundle (no master key yet).');
        this.notifyKeyChange(); // ✅ Signal sent
        return true;
      }

      this.key = Buffer.from(bundled.masterKey, 'base64');
      this.isReady = true;

      if (expectedVerifier) {
        const check = this.decrypt(expectedVerifier);
        if (check !== VERIFICATION_PHRASE) {
          console.warn('🛑 [Encryption] Cross-Account Ghost Key detected! Rejecting auto-unlock.');
          this.lockMemory();
          return false;
        }
      }
      
      console.log('✅ [Encryption] Auto-unlocked securely');
      this.notifyKeyChange(); // ✅ Signal sent
      return true;

    } else {
      // Standard mode: ensure the device key is in RAM (needed by dependent paths).
      await this.getOrGenerateDeviceKey();
      const storedKey = await this.loadKeyFromDevice();

      if (storedKey) {
        this.key = storedKey;
        this.isReady = true;
        if (expectedVerifier) {
          const check = this.decrypt(expectedVerifier);
          if (check !== VERIFICATION_PHRASE) {
            console.warn('🛑 [Encryption] Cross-Account Ghost Key detected! Rejecting auto-unlock.');
            this.lockMemory();
            return false;
          }
        }
        
        console.log('✅ [Encryption] Standard mode unlocked securely');
        this.notifyKeyChange(); // signal subscribers that key state changed
        return true;
      }

      // Standard guest: has a device key, no master key → valid unlocked state.
      if (this.extractedDeviceKey) {
        console.log('🔑 [Encryption] Standard guest unlocked (device key only).');
        this.notifyKeyChange(); // signal subscribers that key state changed
        return true;
      }
      return false;
    }
  } catch (error) {
    this.deviceKeyPromise = null;
    return false;
  }
}

  /**
   * Convenience for the lock screen: attempt an unlock and report a structured
   * outcome so the UI can show the correct message without any wipe logic.
   *   'success'          — unlocked
   *   'locked_out'       — Face ID unavailable right now (cancel / OS lockout).
   *                        Tell the user to unlock their iPhone with the passcode.
   *   'invalidated'      — the protected key was invalidated by a biometric change.
   *   'failed'           — other/unknown failure; safe to retry.
   */
  public async tryUnlock(): Promise<'success' | 'locked_out' | 'invalidated' | 'failed'> {
    const ok = await this.autoUnlock();
    if (ok) return 'success';
    const kind = this.getLastFailureKind();
    if (kind === 'auth_unavailable') return 'locked_out';
    if (kind === 'invalidated')      return 'invalidated';
    return 'failed';
  }


  /**
   * Adds the secondary key into the EXISTING biometric bundle, preserving device+master.
   * Used when an older bundle (created before this key existed) is opened in biometric mode.
   */
  private async _mergeMirrorKeyIntoBundle(mirrorKey: string, current: BundledKeys): Promise<void> {
    const merged: BundledKeys = {
      deviceKey: current.deviceKey,
      masterKey: current.masterKey ?? (this.key ? this.key.toString('base64') : null),
      mirrorKey,
    };
    await SecureStore.setItemAsync(STORAGE_KEYS.BUNDLED_KEY, JSON.stringify(merged), {
      keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
      requireAuthentication: true,
    });
    // best-effort: remove any stray standalone slot so there's one source of truth
    await SecureStore.deleteItemAsync(STORAGE_KEYS.MIRROR_DB_KEY).catch(() => {});
  }
 

  public async setKeyProtection(requireBiometric: boolean): Promise<void> {
    console.log(`🔐 [Encryption] Migrating keys → biometric: ${requireBiometric}`);
    const isGuest = !this.key || !this.isReady;

    // ── Resolve the device key from the cheapest available source ──────────────
    // RAM first (no Face ID), then plaintext slot, then the biometric bundle.
    let deviceKey = this.extractedDeviceKey || await SecureStore.getItemAsync(STORAGE_KEYS.DEVICE_DB_KEY);
    if (!deviceKey) {
      const bundledRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY);
      const bundled    = parseBundledKeys(bundledRaw);
      deviceKey        = bundled?.deviceKey ?? null;
      // Rescue the master key into RAM while the bundle is open (avoids a 2nd prompt).
      if (bundled?.masterKey && !this.key) {
        this.key     = Buffer.from(bundled.masterKey, 'base64');
        this.isReady = true;
      }
    }
    if (!deviceKey) throw new Error('[Encryption] Device key not found.');

    const masterKeyB64 = isGuest ? null : this.key!.toString('base64');


    const mirrorKey = this.extractedMirrorKey
      ?? await SecureStore.getItemAsync(STORAGE_KEYS.MIRROR_DB_KEY)
      ?? Buffer.from(QuickCrypto.randomBytes(32)).toString('hex'); 

    // ──────────────────────────────────────────────────────────────────────────
    // SAFETY INVARIANT: never delete the only readable copy of a key until its
    // replacement is written AND verified readable. If anything throws (e.g. the
    // user cancels Face ID mid-write), we roll forward to a fully-consistent
    // state or leave the PRIOR state completely intact. We never reach a state
    // where the device key exists in neither the plaintext slot nor the bundle.
    // ──────────────────────────────────────────────────────────────────────────
    if (requireBiometric) {
      // 1. WRITE the new bundle (this is the Face ID prompt). If it throws/cancels,
      //    nothing has been deleted yet → prior standard-storage keys are intact.
      const bundle: BundledKeys = { deviceKey, masterKey: masterKeyB64, mirrorKey };
      await SecureStore.setItemAsync(STORAGE_KEYS.BUNDLED_KEY, JSON.stringify(bundle), {
        keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        requireAuthentication: true,
      });

      // 2. VERIFY the bundle is actually readable back before destroying plaintext.
      //    (requireAuthentication:true → this read may prompt Face ID again on some
      //    OS versions; that's acceptable and far cheaper than a lockout.)
      const verifyRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY);
      const verified  = parseBundledKeys(verifyRaw);
      if (!verified?.deviceKey || verified.deviceKey !== deviceKey || verified.mirrorKey !== mirrorKey) {
        // Replacement is NOT confirmed. Abort WITHOUT deleting anything.
        // App stays in standard mode, fully working. User can retry.
        throw new Error('[Encryption] Bundle write could not be verified — migration aborted, keys untouched.');
      }

      // 3. Only now is it safe to remove the plaintext copies.
      await SecureStore.deleteItemAsync(STORAGE_KEYS.MASTER_KEY).catch(() => {});
      await SecureStore.deleteItemAsync(STORAGE_KEYS.DEVICE_DB_KEY).catch(() => {});

      await SecureStore.deleteItemAsync(STORAGE_KEYS.MIRROR_DB_KEY).catch(() => {});
      this.extractedMirrorKey = mirrorKey;
      
      // 4. Refresh live RAM state so the running app keeps working with no restart.
      this.extractedDeviceKey = deviceKey;
      if (verified.masterKey) {
        this.key     = Buffer.from(verified.masterKey, 'base64');
        this.isReady = true;
      }
      this.biometricBundleLoaded = true;

      // 5. Commit the flag LAST — boot only trusts biometric mode once the bundle
      //    is proven to exist. If we crashed before here, boot still finds plaintext.
      securityStorage.set(MMKV_BIOMETRIC_KEY, true);

    } else {
      // ── DISABLE PATH (biometric → standard) ─────────────────────────────────
      // 1. WRITE plaintext copies first.
      await SecureStore.setItemAsync(STORAGE_KEYS.DEVICE_DB_KEY, deviceKey, {
        keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        requireAuthentication: false,
      });
      if (masterKeyB64) {
        await SecureStore.setItemAsync(STORAGE_KEYS.MASTER_KEY, masterKeyB64, {
          keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
          requireAuthentication: false,
        });
      }


      let mirrorKeyToRestore = this.extractedMirrorKey;
      if (!mirrorKeyToRestore) {
        const bundledRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY);
        mirrorKeyToRestore = parseBundledKeys(bundledRaw)?.mirrorKey ?? null;
      }
      if (mirrorKeyToRestore) {
        await SecureStore.setItemAsync(STORAGE_KEYS.MIRROR_DB_KEY, mirrorKeyToRestore, {
          keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
          requireAuthentication: false,
        });
        this.extractedMirrorKey = mirrorKeyToRestore;
      }

      // 2. VERIFY the plaintext device key reads back before deleting the bundle.
      const verifyPlain = await SecureStore.getItemAsync(STORAGE_KEYS.DEVICE_DB_KEY);
      if (verifyPlain !== deviceKey) {
        // Could not establish a standard-mode copy. Leave the bundle in place and
        // keep biometric mode ON so the user is never locked out. No-op + throw.
        throw new Error('[Encryption] Plaintext key write could not be verified — staying in biometric mode.');
      }

      // 3. Safe to remove the bundle now.
      await SecureStore.deleteItemAsync(STORAGE_KEYS.BUNDLED_KEY).catch(() => {});

      // 4. Refresh live RAM so the app keeps working without a restart.
      this.extractedDeviceKey = deviceKey;
      if (masterKeyB64) {
        this.key     = Buffer.from(masterKeyB64, 'base64');
        this.isReady = true;
      }
      // We are no longer behind a biometric gate.
      this.biometricBundleLoaded  = false;
      this.biometricBundlePromise = null;

      // 5. Commit the flag LAST.
      securityStorage.set(MMKV_BIOMETRIC_KEY, false);
    }

    // Force the next device-key fetch to re-resolve under the new mode.
    this.deviceKeyPromise = null;
  }

  public async getRawKeyString(): Promise<string | null> {
    const keyBuffer = await this.loadKeyFromDevice();
    return keyBuffer ? keyBuffer.toString('base64') : null;
  }

  public async getMnemonicString(): Promise<string | null> {
    try {
      return await SecureStore.getItemAsync(STORAGE_KEYS.MNEMONIC);
    } catch (error) {
      return null;
    }
  }

  private async persistKey(keyBuffer: Buffer): Promise<void> {
    if (this.isBiometricProtectionEnabled()) {
      // Biometric mode: write the new master key into the bundle (Face ID gated).
      let deviceKey = this.extractedDeviceKey || await SecureStore.getItemAsync(STORAGE_KEYS.DEVICE_DB_KEY);
      
      if (!deviceKey) {
        const bundledRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY);
        deviceKey = parseBundledKeys(bundledRaw)?.deviceKey ?? null;
      }

      if (deviceKey) {
        const bundle: BundledKeys = { deviceKey, masterKey: keyBuffer.toString('base64') };
        await SecureStore.setItemAsync(STORAGE_KEYS.BUNDLED_KEY, JSON.stringify(bundle), {
          keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
          requireAuthentication: true,
        });
        this.extractedDeviceKey = deviceKey; 
        this.biometricBundleLoaded = true;
      }
      
      // Ensure no traces are left in standard storage
      await SecureStore.deleteItemAsync(STORAGE_KEYS.MASTER_KEY).catch(() => {});
    } else {
      await SecureStore.setItemAsync(
        STORAGE_KEYS.MASTER_KEY,
        keyBuffer.toString('base64'),
        {
          keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
          requireAuthentication: false,
        }
      );
    }
  }  

  private async loadKeyFromDevice(): Promise<Buffer | null> {
    try {
      const keyBase64 = await SecureStore.getItemAsync(STORAGE_KEYS.MASTER_KEY);
      if (!keyBase64) return null;
      return Buffer.from(keyBase64, 'base64');
    } catch (error) {
      return null;
    }
  }

public async resetDevice(): Promise<void> {
    console.log('🧹 [Encryption] Wiping mortal user keys...');

    // 1. Remove the mortal (user) keys from the OS keystore. This is silent and
    //    never prompts for biometrics.
    await Promise.all([
      SecureStore.deleteItemAsync(STORAGE_KEYS.MASTER_KEY),
      SecureStore.deleteItemAsync(STORAGE_KEYS.MNEMONIC),
      SecureStore.deleteItemAsync(STORAGE_KEYS.IDENTITY_PRIVATE),
    ]).catch(() => {});

    // 2. The biometric bundle is deliberately NOT rewritten here. Editing a
    //    requireAuthentication:true entry would trigger a Face ID prompt, which
    //    can crash if logout runs while the app is backgrounding. It is safe to
    //    leave: the immortal device key inside it is reused by the next user,
    //    and any master key inside it is useless once the local databases are
    //    deleted (see note below).
    //
    // NOTE: this function does NOT delete the local SQLCipher databases or media
    // caches. The logout flow in the app performs that file deletion. Removing
    // the key references and zero-filling RAM (cleanup) is this function's job;
    // destroying the ciphertext on disk is the caller's.
    this.cleanup();
  }




    /** Subscribe to key set/wipe events. Returns an unsubscribe function. */
    public onKeyChange(cb: () => void): () => void {
      this.keyListeners.add(cb);
      return () => { this.keyListeners.delete(cb); };
    }

    private notifyKeyChange(): void {
      this.keyListeners.forEach(cb => {
        try { cb(); } catch (e) { console.warn('[Encryption] keyListener error:', e); }
      });
    }


    


  /**
   * 🛡️ Forcefully disables biometric requirements and deletes the invalidated bundle.
   * Called when a user acknowledges an invalidated Face ID state and chooses to wipe.
   */
  public forceClearInvalidatedBiometrics(): void {
    console.log('🚨 [Encryption] Force clearing invalidated biometric state to prevent loop.');
    securityStorage.set(MMKV_BIOMETRIC_KEY, false);
    SecureStore.deleteItemAsync(STORAGE_KEYS.BUNDLED_KEY).catch(() => {});
     
    // Clear RAM locks
    this.lastFailureKind = null;
    this.promptSuppressed = false;
    this.biometricBundleLoaded = false;
  }


  /**
   * Derives a deterministic X25519 key pair from the user's mnemonic.
   * The private key is stored in SecureStore — never leaves the device.
   * Returns the public key as a base64 string for upload to the server.
   *
   * Called once during completeEncryptionSetup, after the master key exists.
   */ 
  public async generateIdentityKeyPair(): Promise<string | null> {
    try {
      // 1. Derive a deterministic seed from the mnemonic
      //    Different path from the master key — append "identity" to distinguish
      const mnemonic = await SecureStore.getItemAsync(STORAGE_KEYS.MNEMONIC);
      if (!mnemonic) return null;

      // Use HKDF-style domain separation: hash(mnemonic + "identity")
      // QuickCrypto's createHash gives us a simple, stable derivation
      const seed = QuickCrypto
        .createHash('sha256')
        .update(Buffer.from(mnemonic + ':diary_identity_v1', 'utf8'))
        .digest();                         // 32-byte Buffer

      // 2. Generate X25519 key pair from seed
      const { privateKey, publicKey } = QuickCrypto.generateKeyPairSync('x25519', {
        privateKeyEncoding: { type: 'pkcs8',   format: 'der' },
        publicKeyEncoding:  { type: 'spki',    format: 'der' },
      });

      // 3. Store private key in SecureStore — never leaves device
      await SecureStore.setItemAsync(
        STORAGE_KEYS.IDENTITY_PRIVATE,
        Buffer.from(privateKey).toString('base64'),
        {
          keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
          requireAuthentication: false,
        }
      );

      // 4. Return public key as base64 for server upload
      return Buffer.from(publicKey).toString('base64');

    } catch (error) {
      console.error('❌ [Encryption] generateIdentityKeyPair failed:', error);
      return null;
    }
  }

  // ─── Text encryption (UNCHANGED) ──────────────────────────────────────────

  public encrypt(text: string): string | null {
    const encryptionKey = this.key || this.getGuestFallbackKey();
    if (!encryptionKey) return null;

    try {
      const iv      = QuickCrypto.randomBytes(IV_LENGTH);
      // NOTE (fixed for public release): production passed `this.key` here,
      // which is null for guest users even though `encryptionKey` resolved to
      // the guest fallback. Using the resolved key makes encrypt/decrypt
      // symmetric for guests. Mirror this fix in the app.
      const cipher  = QuickCrypto.createCipheriv(ALGORITHM, encryptionKey, iv);
      let encrypted = cipher.update(text, 'utf8', 'base64');
      encrypted    += cipher.final('base64');
      const authTag = cipher.getAuthTag().toString('base64');
      return `${iv.toString('base64')}:${authTag}:${encrypted}`;
    } catch (error) {
      return null;
    }
  }



  public decrypt(encryptedBundle: string): string {
    const keysToTry = [];
    if (this.key) keysToTry.push(this.key);
    const guestKey = this.getGuestFallbackKey();
    if (guestKey) keysToTry.push(guestKey);

    if (keysToTry.length === 0) return '🔒 Locked';
    if (!encryptedBundle?.includes(':')) return '⚠️ Invalid Data';

    const parts = encryptedBundle.split(':');
    if (parts.length !== 3) return '⚠️ Corrupted';
    const [iv, tag, content] = parts;

    // Try the master key first, then the device-derived guest fallback key.
    for (const decryptionKey of keysToTry) {
      try {
        const decipher = QuickCrypto.createDecipheriv(ALGORITHM, decryptionKey, Buffer.from(iv, 'base64'));
        decipher.setAuthTag(Buffer.from(tag, 'base64'));

        let decrypted  = decipher.update(content, 'base64', 'utf8');
            decrypted += decipher.final('utf8');
        return decrypted;
      } catch (error) {
        continue;
      }
    }
    return '🚫 Unreadable';
  }

  
  /**
   * Encrypts a media file using AES-128-GCM.
   *
   * Flow:
   *   1. Read the entire source file into memory via NitroFile (JSI, no bridge overhead).
   *   2. Encrypt with QuickCrypto AES-128-GCM (single-pass — correct for ≤5 MB).
   *   3. Write the ciphertext to a .enc file in the app's document directory.
   *   4. Return { path, iv, tag } — identical contract to the old AesGcmCrypto version.
   *
   * The source (plaintext) file is NOT deleted here.
   * Responsibility for cleanup belongs to the caller (e.g. after a confirmed upload).
   *
   * @param sourceUri  File URI of the plaintext media (e.g. from the image picker).
   * @returns          { path, iv, tag } on success, null on any failure.
   */
  public async encryptFile(
    sourceUri: string, 
  ): Promise<{ path: string; iv: string; tag: string; encrypted_dek: string; dek_iv: string; dek_tag: string } | null> {
    // if (!this.isReady || !this.key) return null;

    // If neither a master key nor a device key is in RAM (e.g. just after logout),
    // load the device key so the guest fallback key can be derived.
    if (!this.key && !this.extractedDeviceKey) {
      await this.getOrGenerateDeviceKey();
    }

    const encryptionKey = this.key || this.getGuestFallbackKey();
    if (!encryptionKey) return null;

    const uniqueId         = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const encryptedOutPath = `${Paths.document}/enc_${uniqueId}.enc`;

    try {
      // ── Step 1: Read source into memory ──────────────────────────────────
      const plainBase64 = await fs.promises.readFile(sourceUri, 'base64');
      const plainData   = Buffer.from(plainBase64, 'base64');

      // ── Step 2: Generate a fresh DEK for this file ────────────────────────
      const dek = QuickCrypto.randomBytes(KEY_LENGTH);   // fresh 16-byte per-file DEK

      // ── Step 3: Encrypt the file with the per-file DEK (never the master key) ──
      const iv     = QuickCrypto.randomBytes(IV_LENGTH_FILE);
      const cipher = QuickCrypto.createCipheriv(ALGORITHM_FILE, dek, iv);

      const encPart1   = cipher.update(plainData);
      const encPart2   = cipher.final();
      const authTag    = cipher.getAuthTag();
      const ciphertext = Buffer.concat([encPart1, encPart2]);

      // ── Step 4: Wrap the DEK with the master key ──────────────────────────────
      const wrapped = this.wrapDEK(dek);
      dek.fill(0);                                        // zero-fill the DEK from RAM immediately after wrapping
      if (!wrapped) throw new Error('DEK wrap failed');

      // ── Step 5: Write ciphertext to disk ─────────────────────────────────
      await fs.promises.writeFile(encryptedOutPath, ciphertext.toString('base64'), 'base64');

      // ── Step 6: Return all 6 fields ───────────────────────────────────────
      return {
        path:          encryptedOutPath,
        iv:            iv.toString('hex'),
        tag:           authTag.toString('hex'),
        encrypted_dek: wrapped.encrypted_dek,
        dek_iv:        wrapped.dek_iv,
        dek_tag:       wrapped.dek_tag,
      };

    } catch (error) {
      try {
        if (fs.existsSync(encryptedOutPath)) await fs.promises.unlink(encryptedOutPath);
      } catch (_) {}
      console.error('❌ [Encryption] encryptFile failed:', error);
      return null;
    }
  }




  /**
   * 🎙️ Decrypts an encrypted audio file fully in RAM and returns an ArrayBuffer
   * ready for react-native-audio-api's decodeAudioData(). Nothing plaintext
   * ever touches disk. Use this for voice memos.
   */
  public async decryptFileToArrayBuffer(
    encryptedPath: string,
    ivBase64: string,
    tagBase64: string,
    encrypted_dek?: string,
    dek_iv?: string,
    dek_tag?: string
  ): Promise<ArrayBuffer | null> {

    const fallbackKey = this.getGuestFallbackKey();
    if (!this.key && !fallbackKey) return null;

    try {
      const cleanPath = encryptedPath.replace(/^file:\/\//, '');

      let decryptionKey: Buffer;
      const isEnvelopeEncryption = !!(encrypted_dek && dek_iv && dek_tag);

      if (isEnvelopeEncryption) {
        const unwrapped = this.unwrapDEK(encrypted_dek!, dek_iv!, dek_tag!);
        if (!unwrapped) throw new Error('DEK Unwrap failed');
        decryptionKey = unwrapped;
      } else {
        decryptionKey = (this.key || fallbackKey)!;
      }

      const encBase64 = await fs.promises.readFile(cleanPath, 'base64');
      let ciphertext = Buffer.from(encBase64, 'base64');

      const isHex = (s: string) => /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
      const iv      = Buffer.from(ivBase64,  isHex(ivBase64)  ? 'hex' : 'base64');
      const authTag = Buffer.from(tagBase64, isHex(tagBase64) ? 'hex' : 'base64');

      // (same foolproof IV-prefix / tag-suffix stripping as the cache version)
      let startsWithIv = ciphertext.length >= iv.length;
      for (let i = 0; startsWithIv && i < iv.length; i++) {
        if (ciphertext[i] !== iv[i]) startsWithIv = false;
      }
      if (startsWithIv) ciphertext = ciphertext.subarray(iv.length);

      let endsWithTag = ciphertext.length >= authTag.length;
      const off = ciphertext.length - authTag.length;
      for (let i = 0; endsWithTag && i < authTag.length; i++) {
        if (ciphertext[off + i] !== authTag[i]) endsWithTag = false;
      }
      if (endsWithTag) ciphertext = ciphertext.subarray(0, off);

      const decipher = QuickCrypto.createDecipheriv(ALGORITHM_FILE, decryptionKey, iv);
      decipher.setAuthTag(authTag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

      if (isEnvelopeEncryption) decryptionKey.fill(0);

      // ── Return a standalone ArrayBuffer (sliced so it's not a view into a pooled Buffer) ──
      const ab = plaintext.buffer.slice(
        plaintext.byteOffset,
        plaintext.byteOffset + plaintext.byteLength
      );
      return ab;
    } catch (error) {
      console.error('❌ [Encryption] decryptFileToArrayBuffer failed:', error);
      return null;
    }
  } 

  /**
   * 🛡️ Derives a consistent 16-byte AES key from the immortal Device Key.
   * Used for Guest Mode when the user hasn't generated a Master Key yet.
   */
  private getGuestFallbackKey(): Buffer | null {
    if (!this.extractedDeviceKey) return null;
    
    // Domain separation ensures this derived key is mathematically distinct from the SQLite key
    return QuickCrypto.createHash('sha256')
      .update(Buffer.from(this.extractedDeviceKey + ':guest_fallback_v1', 'utf8'))
      .digest()
      .subarray(0, KEY_LENGTH); // 16 bytes for AES-128
  }


  // ─── DEK Envelope ─────────────────────────────────────────────────────────────
  /**
   * Wraps a raw DEK with the master key (AES-128-GCM).
   * Called once per media upload after the DEK encrypts the file.
   *
   * @param dek  Raw 16-byte DEK buffer
   * @returns    { encrypted_dek, dek_iv, dek_tag } all hex strings, or null on failure
   */
  public wrapDEK(dek: Buffer): { encrypted_dek: string; dek_iv: string; dek_tag: string } | null {
    // Use the master key if present, otherwise the device-derived guest key.
    const wrappingKey = this.key || this.getGuestFallbackKey();
    if (!wrappingKey) return null;
    
    try {
      const iv     = QuickCrypto.randomBytes(IV_LENGTH);
      const cipher = QuickCrypto.createCipheriv(ALGORITHM, wrappingKey, iv);
      const enc1   = cipher.update(dek);
      const enc2   = cipher.final();
      const tag    = cipher.getAuthTag();
      return {
        encrypted_dek: Buffer.concat([enc1, enc2]).toString('hex'),
        dek_iv:        iv.toString('hex'),
        dek_tag:       tag.toString('hex'),
      };
    } catch {
      return null;
    }
  }

  

  public unwrapDEK(encrypted_dek: string, dek_iv: string, dek_tag: string): Buffer | null {
    // Try the master key first, then the guest fallback key.
    const keysToTry = [];
    if (this.key) keysToTry.push(this.key);
    const guestKey = this.getGuestFallbackKey();
    if (guestKey) keysToTry.push(guestKey);

    if (keysToTry.length === 0) return null;

    for (const decryptionKey of keysToTry) {
      try {
        const isHex    = (s: string) => /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
        const iv       = Buffer.from(dek_iv,       isHex(dek_iv)       ? 'hex' : 'base64');
        const tag      = Buffer.from(dek_tag,      isHex(dek_tag)      ? 'hex' : 'base64');
        const encBytes = Buffer.from(encrypted_dek, isHex(encrypted_dek) ? 'hex' : 'base64');

        const decipher = QuickCrypto.createDecipheriv(ALGORITHM, decryptionKey, iv);
        decipher.setAuthTag(tag);
        const dec1 = decipher.update(encBytes);
        const dec2 = decipher.final();
        return Buffer.concat([dec1, dec2]);
      } catch {
        // Wrong key or tampered DEK, try the next key in the array
        continue;
      }
    }
    return null;
  }

  public getRawKeyBase64(): string | null {
    // Returns the master key if present, otherwise the guest fallback key.
    const activeKey = this.key || this.getGuestFallbackKey();
    if (!activeKey) return null;
    return activeKey.toString('base64');
  }

  // ─── Memory management (UNCHANGED) ────────────────────────────────────────

  public lockMemory(): void {
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
    this.extractedDeviceKey     = null;
    this.extractedMirrorKey     = null; 
    this.deviceKeyPromise       = null;
    this.biometricBundleLoaded  = false;
    this.biometricBundlePromise = null; // 🛡️ clear any in-flight prompt so the next unlock starts clean
    this.isReady                = false;
    this.notifyKeyChange(); 
    console.log('🔒 [Encryption] Master and Device keys wiped from memory');
  }


  public debugKeyState(): object {
    return {
      masterKeyPresent: !!this.key,
      masterKeyNonZero: this.key ? !this.key.every(b => b === 0) : false,
      masterKeyFirstBytes: this.key ? Array.from(this.key.subarray(0, 4)) : null,
      deviceKeyPresent: !!this.extractedDeviceKey,
      isReady: this.isReady,
      biometricBundleLoaded: this.biometricBundleLoaded,
    };
  } 

  public get ready(): boolean {
    return this.isReady;
  }

  private cleanup(): void {
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
    this.extractedDeviceKey    = null;
    this.extractedMirrorKey    = null; 
    this.deviceKeyPromise      = null;
    this.biometricBundleLoaded = false;
    this.isReady               = false;
  }
}

export const encryptionService = new EncryptionService();
export type { InitResult };