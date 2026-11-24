/*
Here is the comprehensive architectural documentation for your EncryptionMiddleware.ts and the overall security model of your application.

You can use this as your official technical documentation, README, or security whitepaper for the app.

🔐 Encryption Architecture & Middleware Documentation
1. Core Philosophy: The Dual-Key Architecture
To achieve both seamless offline synchronization (via PowerSync) and military-grade user privacy, the application utilizes a strict Dual-Key Architecture. Encryption is handled at two entirely separate layers, utilizing two distinct keys that have different lifecycles.

A. The Device Key (Immortal / Hardware-Tied)

Purpose: Encrypts the local SQLite databases (diary.db and mirror_decrypted.db) at rest using SQLCipher.

Lifecycle: Generated once the very first time the app is opened after installation. It is immortal—it is never deleted or rotated until the user physically uninstalls the app.

Identity: It is tied exclusively to the physical device, not to a specific user.

Why? SQLite and PowerSync require a stable, persistent key to maintain database integrity across app restarts, schema migrations, and user sessions.

B. The Master Key (Mortal / User-Tied)

Purpose: Encrypts the actual diary content, text, notes, and media files at the application level using AES-128-GCM.

Lifecycle: Generated from a BIP-39 12-word mnemonic phrase when a user registers. It is mortal—it is mathematically shredded from RAM and deleted from standard storage the moment a user logs out.

Identity: It is tied exclusively to the user's secure session.

Why? If a user logs out, their local database is physically wiped. However, even if fragments of the database survived on the disk, the data is permanently unreadable because the user's Master Key has been destroyed.

2. Security Modes & Vault Binding
The EncryptionMiddleware operates in two distinct states, depending on the user's preference.

Mode 1: Standard Security (Vault Binding OFF)

Storage: Keys are stored in the iOS/Android Secure Enclave with the policy WHEN_UNLOCKED_THIS_DEVICE_ONLY and requireAuthentication: false.

Behavior: The OS allows the app to read the keys silently in the background as long as the phone itself is unlocked.

Keys: The Device Key and Master Key are stored in separate slots (STORAGE_KEYS.DEVICE_DB_KEY and STORAGE_KEYS.MASTER_KEY).

Mode 2: Maximum Security (Vault Binding ON)

Storage: Keys are stored with the policy requireAuthentication: true. The OS mandates a successful Biometric scan (Face ID / Touch ID) every time the keys are read.

The Bundle: To prevent iOS from prompting the user for Face ID multiple times, the Device Key and Master Key are combined into a single JSON string (The Biometric Bundle) and stored under STORAGE_KEYS.BUNDLED_KEY.

Hardware Enforcement: The plain-text DEVICE_DB_KEY is completely obliterated from standard storage. This means the SQLCipher databases literally cannot be opened by the OS without a successful Face ID scan.

Tamper Proofing: Because the keys are bound to the hardware enclave, if a bad actor attempts to change or disable the device's Face ID in the OS settings, the OS permanently destroys the bundle, locking the database forever.

3. The "Single-Prompt" Coordinator (RAM Caching)
Because SQLCipher needs the Device Key to boot, and the Auth Provider needs the Master Key to show the UI, a race condition occurs on startup that would normally trigger two back-to-back Face ID alerts.

The middleware solves this using the loadBiometricBundleOnce() Promise Lock:

When the app boots, AppDatabase.ts asks for the Device Key.

The middleware triggers Face ID.

Upon success, the middleware extracts both keys from the bundle.

It sets the Master Key into the active AES-GCM class instance.

It caches the Device Key in a pure RAM variable (extractedDeviceKey).

A millisecond later, when the Auth flow asks for the Master Key, the middleware instantly resolves it from RAM without prompting Face ID again.

Security Guarantee: The unencrypted Device Key never touches the disk during this process. If the app is killed, the RAM is cleared, and Face ID is required again.

4. Lifecycle & Session Management
Logging In / Registering (persistKey)

When a user authenticates, a Master Key is created/imported.

If Vault Binding is OFF, it saves to the standard MASTER_KEY slot.

If Vault Binding is ON, it fetches the immortal Device Key, bundles it with the new Master Key, and overwrites the BUNDLED_KEY slot behind Face ID.

Logging Out (resetDevice)

Logging out requires careful handling to avoid background Face ID crashes (which occur if the app requests biometrics while the UI is transitioning/backgrounded).

The app physically deletes the SQLite database files (diary.db, mirror.db) and all local media caches.

The middleware deletes the MASTER_KEY from standard storage.

The Biometric Bundle is left untouched. * Why? Attempting to edit the bundle during logout would trigger a Face ID prompt and crash the app in the background.

Is it secure? Yes. Because the database files are physically destroyed in step 1, the old Master Key left inside the Face ID bundle is rendered completely useless (there is zero data left on the device for it to decrypt).

The immortal Device Key inside that bundle is preserved safely for the next user. When a new user logs in, persistKey simply overwrites the old bundle.

5. Middleware API Reference (encryptionService)
getOrGenerateDeviceKey(): Fetches the immortal DB key. Routes through the Face ID coordinator if Max Security is enabled.

generateMasterKey(): Creates a fresh BIP-39 mnemonic, derives the AES key, and saves it based on current security settings. Returns a verification phrase for the server.

importMasterKey(mnemonic, verifier): Derives a key from an existing 12-word phrase and checks it against the server's verifier.

setKeyProtection(requireBiometric: boolean): The migration function. Safely moves keys between Standard storage and Biometric Bundle storage based on user settings, destroying the plain-text traces when upgrading.

encrypt(text) / decrypt(bundle): Synchronous AES-128-GCM operations for UI data.

encryptFile(uri) / decryptFile(uri): Single-pass AES-128-GCM operations.
  - encryptFile: reads plaintext → encrypts in memory → writes .enc to disk → returns { path, iv, tag }.
    The plaintext source is NOT deleted here; the caller is responsible for
    cleaning up the original (e.g. after a successful upload).
  - decryptFile: reads .enc from disk → decrypts in memory → returns base64 string.
    The caller feeds this directly to <Image> as data:image/jpeg;base64,...
    Nothing plaintext ever touches the disk.

lockMemory(): Zero-fills the this.key buffer and nullifies the RAM caches. Used when the app is thrown into the background to ensure memory scraping cannot reveal the keys.
*/


// ─── Unchanged imports ────────────────────────────────────────────────────────
import QuickCrypto from 'react-native-quick-crypto';
import * as SecureStore from 'expo-secure-store';
// react-native-fs removed — Paths from nitro-file-system replaces RNFS.DocumentDirectoryPath
import { Buffer } from 'buffer';
import * as bip39 from 'bip39';
import { createMMKV } from 'react-native-mmkv';
import { Buffer as NitroBuffer } from 'react-native-nitro-buffer';
// ─── New imports (replaces AesGcmCrypto + expo-file-system/legacy) ────────────
// react-native-nitro-file-system  →  fast, Node.js-compatible JSI file I/O
// react-native-quick-crypto       →  already imported above; now also handles files
import fs, { Paths } from 'react-native-nitro-file-system';
import { appStorage } from '../storage/AppStorage';

// ─── Constants ────────────────────────────────────────────────────────────────
const ALGORITHM     = 'aes-128-gcm';   // text encryption  (unchanged)
const IV_LENGTH     = 12;              // 96-bit IV for GCM (unchanged)
const KEY_LENGTH    = 16;              // 128-bit key       (unchanged)
const AUTH_TAG_LENGTH = 16;            // 128-bit auth tag  (unchanged)

// File encryption — now also AES-128-GCM (was AES-128-CTR).
// Same algorithm & key as text; one consistent primitive across the whole app.
// GCM adds an auth tag so tampered .enc files are rejected before any data leaks.
const ALGORITHM_FILE  = 'aes-128-gcm';
const IV_LENGTH_FILE  = 12;            // 96-bit IV (GCM standard)

const VERIFICATION_PHRASE = 'DIARY_VERIFICATION_v1';

// ─── Types ────────────────────────────────────────────────────────────────────
type ProgressCallback = (progress: number) => void;

// ─── Storage ──────────────────────────────────────────────────────────────────
const securityStorage    = createMMKV({ id: 'security_settings' });
// const MMKV_BIOMETRIC_KEY = 'max_security_enabled';
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
  /** The master key from the latest persistKey() was written into the Face ID bundle (write succeeded). */
  private masterKeySavedInBundle: boolean = false;
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

  /**
   * The background lock (Maximum Security / Vault): the same wipe as lockMemory(), and in Face ID
   * mode no new Face ID may start until the lock screen asks for one (armUnlockAttempt). Without
   * this, a database read still finishing in the background asked for the keys by itself: its
   * Face ID showed on the way back and loaded the keys, but the lock screen hadn't asked, so it
   * stayed (and the next quick return showed no Face ID at all). Nothing stored is touched.
   */
  public lockForBackground(): void {
    this.lockMemory();
    if (this.isBiometricProtectionEnabled()) this.promptSuppressed = true;
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
    let thisRead: Promise<BundledKeys | null> | null = null;
    thisRead = (async () => {
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
            if (bundled.mirrorKey) this.extractedMirrorKey = bundled.mirrorKey;  // ← add
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
        // Only forget THIS read: a lock in between may have started a newer one (the lock
        // screen's), which other callers must keep sharing instead of opening a second Face ID.
        if (this.biometricBundlePromise === thisRead) this.biometricBundlePromise = null;
      }
    })();
    this.biometricBundlePromise = thisRead;

    return thisRead;
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
          this.extractedDeviceKey = plainKey; // ⚡ ADD THIS
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
   * Returns the mirror DB's INDEPENDENT SQLCipher key.
   * Random, separately stored — NOT derived from the device key, so a compromised
   * device key cannot open the (decrypted-content) mirror database.
   */
  public async getOrGenerateMirrorKey(): Promise<string> {
  if (this.extractedMirrorKey) return this.extractedMirrorKey;

  if (this.isBiometricProtectionEnabled()) {
    const bundled = await this.loadBiometricBundleOnce();
    if (bundled?.mirrorKey) {
      this.extractedMirrorKey = bundled.mirrorKey;
      return bundled.mirrorKey;
    }
    // Bundle exists but has no mirror key yet (first run after upgrade) → mint + merge.
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
      void this.removePlainMnemonicAfterSave(); // Maximum Security only; see the method

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
      void this.removePlainMnemonicAfterSave(); // Maximum Security only; see the method

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
        console.log('✅ [Encryption] Biometric ghost vault successfully cleared.');
        return true;
      }
    } catch (error) {
      console.warn('⚠️ [Encryption] User cancelled Face ID during scrub.');
      return false; // Returns false only if they explicitly cancel the Face ID prompt
    }
    
    return true; // Bundle didn't exist or was already clean
  }

  // 🛡️ autoUnlock now handles Verifier Checks and the Fresh Login MMKV Lock
  // public async autoUnlock(expectedVerifier?: string): Promise<boolean> {
  //   try {
  //     // 1. FRESH LOGIN LOCK: Force 12-word entry for new sessions
  //     if (appStorage.getBoolean('fresh_login_lock')) {
  //       console.log('🔒 [Encryption] Fresh login detected. Bypassing auto-unlock.');
  //       return false;
  //     }  

  //     if (this.isBiometricProtectionEnabled()) {
  //       const bundled = await this.loadBiometricBundleOnce();
  //       if (!bundled) {
  //         this.deviceKeyPromise = null;
  //         return false;
  //       }

  //       await SecureStore.deleteItemAsync(STORAGE_KEYS.DEVICE_DB_KEY).catch(() => {});
  //       if (!bundled.masterKey) return false; 

  //       this.key = Buffer.from(bundled.masterKey, 'base64');
  //       this.isReady = true;

  //       // 2. CROSS-ACCOUNT GHOST KEY CHECK
  //       if (expectedVerifier) {
  //         const check = this.decrypt(expectedVerifier);
  //         if (check !== VERIFICATION_PHRASE) {
  //           console.warn('🛑 [Encryption] Cross-Account Ghost Key detected! Rejecting auto-unlock.');
  //           this.lockMemory();
  //           return false;
  //         }
  //       }

  //       console.log('✅ [Encryption] Auto-unlocked securely');
  //       return true;

  //     } else {
  //       const storedKey = await this.loadKeyFromDevice();
  //       if (storedKey) {
  //         this.key = storedKey;
  //         this.isReady = true;
          
  //         if (expectedVerifier) {
  //           const check = this.decrypt(expectedVerifier);
  //           if (check !== VERIFICATION_PHRASE) {
  //             console.warn('🛑 [Encryption] Cross-Account Ghost Key detected! Rejecting auto-unlock.');
  //             this.lockMemory();
  //             return false;
  //           }
  //         }
  //         return true;
  //       }
  //       return false;
  //     }
  //   } catch (error) {
  //     this.deviceKeyPromise = null;
  //     return false;
  //   }
  // }

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

      // Cache device + mirror keys from the bundle before touching the standalone slot.
      this.extractedDeviceKey = bundled.deviceKey;
      this.extractedMirrorKey = bundled.mirrorKey ?? null;

      await SecureStore.deleteItemAsync(STORAGE_KEYS.DEVICE_DB_KEY).catch(() => {});

      // Guest-with-vault: Face ID succeeded, device key present, no master key yet.
      if (!bundled.masterKey) {
        this.biometricBundleLoaded = true;
        console.log('🔑 [Encryption] Vault guest unlocked (no master key yet).');
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
      void this.removePlainMnemonicIfVaulted(); // in the background, never blocks the unlock
      return true;

    } else {
      // Standard mode: ensure device key is in RAM (needed for guests + mirror).
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
        this.notifyKeyChange(); // 🟢 THE FIX: You were missing the signal here!
        return true;
      }

      // Standard guest: has a device key, no master key → valid unlocked state.
      if (this.extractedDeviceKey) {
        console.log('🔑 [Encryption] Standard guest unlocked (device key only).');
        this.notifyKeyChange(); // 🟢 THE FIX: You were missing the signal here too!
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
   * Adds a mirror key into the EXISTING biometric bundle, preserving device+master.
   * Used when an older bundle (pre-mirror-key) is opened in Max mode.
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
    // best-effort: remove any stray standalone mirror slot so there's one source of truth
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
      // const bundle: BundledKeys = { deviceKey, masterKey: masterKeyB64 };
      // await SecureStore.setItemAsync(STORAGE_KEYS.BUNDLED_KEY, JSON.stringify(bundle), {
      //   keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
      //   requireAuthentication: true,
      // });

      const bundle: BundledKeys = { deviceKey, masterKey: masterKeyB64, mirrorKey };  // ← add mirrorKey
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
      void this.removePlainMnemonicIfVaulted();

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

      // 6. Standard mode keeps the 12 words in the Keychain, as before: restore them if
      //    Maximum Security had removed the plain copy. (Write only; nothing is deleted.)
      try {
        const hasPlain = await SecureStore.getItemAsync(STORAGE_KEYS.MNEMONIC).catch(() => null);
        const words = hasPlain ? null : this.mnemonicFromMasterKey();
        if (words) {
          await SecureStore.setItemAsync(STORAGE_KEYS.MNEMONIC, words, {
            keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
            requireAuthentication: false,
          });
        }
      } catch {}
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
      const stored = await SecureStore.getItemAsync(STORAGE_KEYS.MNEMONIC);
      if (stored) return stored;
    } catch (error) {
      // fall through to the key in memory
    }
    // Maximum Security: no plain copy is kept – the 12 words are the master key itself
    // (BIP-39 entropy), so they're rebuilt from the key that Face ID unlocked.
    return this.mnemonicFromMasterKey();
  }

  /**
   * The 12-word phrase for the master key in memory. The master key IS the phrase's BIP-39
   * entropy (see generateMasterKey / importMasterKey), so this gives back exactly the same words.
   * null when no 16-byte master key is loaded.
   */
  private mnemonicFromMasterKey(): string | null {
    try {
      if (!this.key || this.key.length !== 16) return null;
      return bip39.entropyToMnemonic(this.key.toString('hex'));
    } catch {
      return null;
    }
  }

  /**
   * Maximum Security / Vault mode: the plain copy of the 12 words would let anyone who reads the
   * Keychain of an unlocked phone rebuild the master key without Face ID. Remove it – but only
   * when it's provably redundant:
   *   • biometric protection is on and the master key was just read from the Face ID bundle;
   *   • the words rebuilt from that key are EXACTLY the stored words.
   * Nothing is written and the bundle is never touched, so this can't lock anyone out: unlocking
   * never used the plain phrase. "Show recovery key" and the identity key rebuild it from the key.
   */
  /**
   * Right after signing in / restoring in Maximum Security: same cleanup, but ONLY if this very
   * key was just written into the Face ID bundle by persistKey(). (If persistKey couldn't write it
   * – e.g. no device key found – the plain phrase may be the only saved copy: it's kept.)
   */
  private async removePlainMnemonicAfterSave(): Promise<void> {
    if (!this.masterKeySavedInBundle) return;
    await this.removePlainMnemonicIfVaulted();
  }

  private async removePlainMnemonicIfVaulted(): Promise<void> {
    try {
      if (!this.isBiometricProtectionEnabled() || !this.biometricBundleLoaded || !this.key) return;
      const stored = await SecureStore.getItemAsync(STORAGE_KEYS.MNEMONIC).catch(() => null);
      if (!stored) return;
      const rebuilt = this.mnemonicFromMasterKey();
      if (!rebuilt || rebuilt !== stored) return; // not provably the same: keep it
      await SecureStore.deleteItemAsync(STORAGE_KEYS.MNEMONIC);
      console.log('🔐 [Encryption] Plain recovery phrase removed (protected by the Face ID bundle).');
    } catch {
      // best effort – never affects unlocking
    }
  }

  // private async persistKey(keyBuffer: Buffer): Promise<void> {
  //   await SecureStore.setItemAsync(
  //     STORAGE_KEYS.MASTER_KEY,
  //     keyBuffer.toString('base64'),
  //     {
  //       keychainAccessible:    SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  //       requireAuthentication: false,
  //     }
  //   );
  // }

  private async persistKey(keyBuffer: Buffer): Promise<void> {
    this.masterKeySavedInBundle = false;
    if (this.isBiometricProtectionEnabled()) {
      // 🛡️ FIX 3: Write new keys to the Vault if Vault Binding is active
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
        // The Keychain accepted the write (it throws otherwise): this key is in the bundle.
        this.masterKeySavedInBundle = keyBuffer.equals(this.key ?? Buffer.alloc(0));
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

  // public async resetDevice(): Promise<void> {
  //   await Promise.all([
  //     SecureStore.deleteItemAsync(STORAGE_KEYS.MASTER_KEY),
  //     // SecureStore.deleteItemAsync(STORAGE_KEYS.BUNDLED_KEY),
  //   ]).catch(() => {});
  //   this.cleanup();
  // }

public async resetDevice(): Promise<void> {
    console.log('🧹 [Encryption] Wiping mortal user keys...');

    // 1. Delete standard storage keys (Always works silently, no Face ID required)
    await Promise.all([
      SecureStore.deleteItemAsync(STORAGE_KEYS.MASTER_KEY),
      SecureStore.deleteItemAsync(STORAGE_KEYS.MNEMONIC),
      SecureStore.deleteItemAsync(STORAGE_KEYS.IDENTITY_PRIVATE),
    ]).catch(() => {});

    // 2. Scrub the Biometric Bundle (Keep Device Key, drop Master Key)
    // THIS IS REQUIRED so hasExistingMasterKey() doesn't get blocked by a ghost key!
    // if (this.isBiometricProtectionEnabled()) {
    //   try {
    //     const bundledRaw = await SecureStore.getItemAsync(STORAGE_KEYS.BUNDLED_KEY);
    //     const bundled = parseBundledKeys(bundledRaw);

    //     if (bundled?.deviceKey) {
    //       // Overwrite the bundle: keep the immortal deviceKey, but shred the masterKey
    //       const cleanBundle = { deviceKey: bundled.deviceKey, masterKey: null };
    //       await SecureStore.setItemAsync(STORAGE_KEYS.BUNDLED_KEY, JSON.stringify(cleanBundle), {
    //         keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    //         requireAuthentication: true,
    //       });
    //       console.log('✅ [Encryption] Biometric bundle successfully scrubbed.');
    //     }
    //   } catch (error) {
    //     console.warn('⚠️ [Encryption] Could not scrub biometric bundle (likely cancelled).');
    //   }
    // } 

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
      const mnemonic = (await SecureStore.getItemAsync(STORAGE_KEYS.MNEMONIC).catch(() => null))
        ?? this.mnemonicFromMasterKey(); // Maximum Security: rebuilt from the key (identical words)
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
    // if (!this.isReady || !this.key) return null;
    const encryptionKey = this.key || this.getGuestFallbackKey();
    if (!encryptionKey) return null;

    try {
      const iv      = QuickCrypto.randomBytes(IV_LENGTH);
      const cipher  = QuickCrypto.createCipheriv(ALGORITHM, this.key, iv);
      let encrypted = cipher.update(text, 'utf8', 'base64');
      encrypted    += cipher.final('base64');
      const authTag = cipher.getAuthTag().toString('base64');
      return `${iv.toString('base64')}:${authTag}:${encrypted}`;
    } catch (error) {
      return null;
    }
  }

  // public decrypt(encryptedBundle: string): string {
  //   if (!this.isReady || !this.key) return '🔒 Locked';
  //   if (!encryptedBundle?.includes(':'))  return '⚠️ Invalid Data';

  //   try {
  //     const parts = encryptedBundle.split(':');
  //     if (parts.length !== 3) return '⚠️ Corrupted';
  //     const [iv, tag, content] = parts;

  //     const decipher = QuickCrypto.createDecipheriv(ALGORITHM, this.key, Buffer.from(iv, 'base64'));
  //     decipher.setAuthTag(Buffer.from(tag, 'base64'));

  //     let decrypted  = decipher.update(content, 'base64', 'utf8');
  //         decrypted += decipher.final('utf8');
  //     return decrypted;
  //   } catch (error) {
  //     return '🚫 Unreadable';
  //   }
  // }

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

    // ⚡ FIX: Try Master Key, then Guest Key
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

  // ─── File encryption (REWRITTEN) ──────────────────────────────────────────
  //
  // What changed vs the old implementation:
  //   • Removed: AesGcmCrypto  (react-native-aes-gcm-crypto)
  //   • Removed: expo-file-system/legacy  (FileSystem.copyAsync, writeAsStringAsync, etc.)
  //   • Removed: react-native-fs (RNFS.stat, RNFS.exists, RNFS.unlink)
  //   • Added:   react-native-nitro-file-system  (NitroFile — fast JSI reads/writes)
  //   • Added:   QuickCrypto already present above; now also used for file ops
  //   • Algorithm: AES-128-CTR → AES-128-GCM  (tamper-evident auth tag on every file)
  //   • Strategy:  single-pass in-memory (correct for ≤5 MB photos/audio in v0)
  //
  // Return contract is IDENTICAL to the old version:
  //   encryptFile → { path: string; iv: string; tag: string } | null
  //   decryptFile → base64 string | null   (NEW: was boolean; caller now gets data URI)
  //
  // Callers that previously used:
  //   file.cryptoResult.iv  /  file.cryptoResult.tag
  // require NO changes — the field names are the same.
  //
  // The decryptFile return type changes from boolean to string | null.
  // Update the call site to:
  //   const base64 = await encryptionService.decryptFile(path, iv, tag);
  //   if (base64) { uri = `data:image/jpeg;base64,${base64}`; }

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

    // 🟢 THE FIX: If there is no Master Key and no Device Key in RAM (e.g. freshly logged out),
    // aggressively fetch the Device Key back into RAM so the Guest Fallback key can generate.
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
      const dek = QuickCrypto.randomBytes(KEY_LENGTH);   // ← NEW: 16-byte DEK

      // ── Step 3: Encrypt file with DEK (not master key) ────────────────────
      const iv     = QuickCrypto.randomBytes(IV_LENGTH_FILE);
      const cipher = QuickCrypto.createCipheriv(ALGORITHM_FILE, dek, iv);  // ← dek, not this.key

      const encPart1   = cipher.update(plainData);
      const encPart2   = cipher.final();
      const authTag    = cipher.getAuthTag();
      const ciphertext = Buffer.concat([encPart1, encPart2]);

      // ── Step 4: Wrap DEK with master key ──────────────────────────────────
      const wrapped = this.wrapDEK(dek);                 // ← NEW
      dek.fill(0);                                        // ← NEW: zero-fill DEK from RAM immediately
      if (!wrapped) throw new Error('DEK wrap failed');

      // ── Step 5: Write ciphertext to disk ─────────────────────────────────
      await fs.promises.writeFile(encryptedOutPath, ciphertext.toString('base64'), 'base64');

      // ── Step 6: Return all 6 fields ───────────────────────────────────────
      return {
        path:          encryptedOutPath,
        iv:            iv.toString('hex'),
        tag:           authTag.toString('hex'),
        encrypted_dek: wrapped.encrypted_dek,            // ← NEW
        dek_iv:        wrapped.dek_iv,                   // ← NEW
        dek_tag:       wrapped.dek_tag,                  // ← NEW
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
   * Decrypts a .enc media file into a base64 string — nothing is written to disk.
   *
   * Flow:
   *   1. Read the entire .enc file into memory via NitroFile.
   *   2. Verify & decrypt with QuickCrypto AES-128-GCM (GCM auth tag prevents
   *      tampered files from returning any data — it throws before decrypting).
   *   3. Return the plaintext as a base64 string.
   *
   * Caller usage:
   *   const base64 = await encryptionService.decryptFile(path, iv, tag);
   *   if (base64) {
   *     const uri = `data:image/jpeg;base64,${base64}`;
   *     // Pass uri to <Image source={{ uri }} /> — no temp file, zero disk exposure.
   *   }
   *
   * ⚠️  Return type changed from boolean → string | null.
   *     Update the call site accordingly (see comment above).
   *
   * @param encryptedPath  Path to the .enc file on disk.
   * @param ivBase64       IV returned by encryptFile (base64 string).
   * @param tagBase64      Auth tag returned by encryptFile (base64 string).
   * @returns              Base64-encoded plaintext on success, null on failure/tamper.
   */
  /**
   * Decrypts a .enc media file into a base64 string — nothing is written to disk.
   */
  public async decryptFile(
    encryptedPath: string,
    ivHex: string,
    tagHex: string,
    encrypted_dek?: string,   // ← Make optional for legacy support
    dek_iv?: string,          // ← Make optional
    dek_tag?: string,         // ← Make optional
  ): Promise<string | null> {
    if (!this.isReady || !this.key) return null;

    try {
      // ── Step 1: Resolve the Decryption Key (Envelope vs Legacy) ──────────
      let decryptionKey: Buffer;
      const isEnvelopeEncryption = !!(encrypted_dek && dek_iv && dek_tag);

      if (isEnvelopeEncryption) {
        const unwrapped = this.unwrapDEK(encrypted_dek, dek_iv, dek_tag);
        if (!unwrapped) {
          console.error('❌ [Encryption] DEK unwrap failed — tampered or wrong key');
          return null;
        }
        decryptionKey = unwrapped;
      } else {
        // Fallback for media uploaded before Envelope Encryption was released
        decryptionKey = this.key; 
      }

      // ── Step 2: Read .enc file into memory ───────────────────────────────
      const encBase64  = await fs.promises.readFile(encryptedPath, 'base64');
      const ciphertext = Buffer.from(encBase64, 'base64');

      // ── Step 3: Decrypt with resolved key ─────────────────────────────────
      const isHex   = (s: string) => /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
      const iv      = Buffer.from(ivHex,  isHex(ivHex)  ? 'hex' : 'base64');
      const authTag = Buffer.from(tagHex, isHex(tagHex) ? 'hex' : 'base64');

      const decipher = QuickCrypto.createDecipheriv(ALGORITHM_FILE, decryptionKey, iv);  
      decipher.setAuthTag(authTag);

      const decPart1  = decipher.update(ciphertext);
      const decPart2  = decipher.final();
      const plaintext = Buffer.concat([decPart1, decPart2]);

      // ── Step 4: Safely Zero-fill DEK from RAM ───────────────────────────
      // CRITICAL: Only zero-fill if it's a temporary DEK. 
      // If we used the Master Key, doing .fill(0) will wipe the user's active session!
      if (isEnvelopeEncryption) {
        decryptionKey.fill(0);                                                    
      }

      return plaintext.toString('base64');

    } catch (error) {
      console.error('❌ [Encryption] decryptFile failed:', error);
      return null;
    }
  }


  public async decryptFileToRollingCache(
    encryptedPath: string,
    ivBase64: string,
    tagBase64: string,
    mediaId: string,
    encrypted_dek?: string, 
    dek_iv?: string,       
    dek_tag?: string,
    extension: string = 'jpg'
  ): Promise<string | null> {
    
    // 🟢 Ensure RAM is populated
    if (!this.key && !this.extractedDeviceKey) {
      await this.getOrGenerateDeviceKey();
    }

    // 🚀 FIX 1: Allow Guest Mode. Fetch the fallback key if the master key is missing.
    const fallbackKey = this.getGuestFallbackKey();
    if (!this.key && !fallbackKey) return null; // Only abort if BOTH are missing

    try {
      // ── Step 1: Clean the file path for NitroFS ──────────
      const cleanPath = encryptedPath.replace(/^file:\/\//, '');

      // ── Step 2: Resolve the Decryption Key (Envelope vs Legacy) ──────────
      let decryptionKey: Buffer;
      const isEnvelopeEncryption = !!(encrypted_dek && dek_iv && dek_tag);

      if (isEnvelopeEncryption) {
        // unwrapDEK already handles trying BOTH the Master Key and Guest Key!
        const unwrapped = this.unwrapDEK(encrypted_dek!, dek_iv!, dek_tag!);  
        if (!unwrapped) throw new Error("DEK Unwrap failed");
        decryptionKey = unwrapped;
      } else {
        // 🚀 FIX 2: Legacy fallback must also use the Guest Key if Master is null
        decryptionKey = (this.key || fallbackKey)!; 
      }

      // ── Step 3: Read File via Fast Nitro FS ─────────
      const encBase64 = await fs.promises.readFile(cleanPath, 'base64');
      let ciphertext = Buffer.from(encBase64, 'base64');

      const isHex   = (s: string) => /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
      const iv      = Buffer.from(ivBase64,  isHex(ivBase64)  ? 'hex' : 'base64');
      const authTag = Buffer.from(tagBase64, isHex(tagBase64) ? 'hex' : 'base64');

      // ── Step 4: RESTORE FOOLPROOF LEGACY CHECKS ──────────
      let startsWithIv = true;
      if (ciphertext.length >= iv.length) {
        for(let i = 0; i < iv.length; i++) {
          if (ciphertext[i] !== iv[i]) { startsWithIv = false; break; }
        }
      } else { startsWithIv = false; }
      
      if (startsWithIv) {
         ciphertext = ciphertext.subarray(iv.length);
      }

      let endsWithTag = true;
      if (ciphertext.length >= authTag.length) {
        const offset = ciphertext.length - authTag.length;
        for(let i = 0; i < authTag.length; i++) {
          if (ciphertext[offset + i] !== authTag[i]) { endsWithTag = false; break; }
        }
      } else { endsWithTag = false; }
      
      if (endsWithTag) {
         ciphertext = ciphertext.subarray(0, ciphertext.length - authTag.length);
      }

      // ── Step 5: Decrypt Data ────────────────────────────────────────────
      const decipher = QuickCrypto.createDecipheriv(ALGORITHM_FILE, decryptionKey, iv); 
      decipher.setAuthTag(authTag);

      const decPart1 = decipher.update(ciphertext); 
      const decPart2 = decipher.final();
      const plaintext = Buffer.concat([decPart1, decPart2]);

      // ── Step 6: Safely Zero-fill DEK (AFTER decryption!) ────────────────
      if (isEnvelopeEncryption) {
        decryptionKey.fill(0);
      }

      // ── Step 7: Write to Cache with proper Extension ──────────────
      const ephemeralPath = `${Paths.cache}/dec_${mediaId}.${extension}`;
      await fs.promises.writeFile(ephemeralPath, plaintext.toString('base64'), 'base64');

      return `file://${ephemeralPath}`;
    } catch (error) {
      console.error('❌ [Encryption] decryptFileToRollingCache failed:', error);
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
  // public wrapDEK(dek: Buffer): { encrypted_dek: string; dek_iv: string; dek_tag: string } | null {
  //   if (!this.isReady || !this.key) return null;
  //   try {
  //     const iv     = QuickCrypto.randomBytes(IV_LENGTH);           // fresh 12-byte IV
  //     const cipher = QuickCrypto.createCipheriv(ALGORITHM, this.key, iv);
  //     const enc1   = cipher.update(dek);
  //     const enc2   = cipher.final();
  //     const tag    = cipher.getAuthTag();
  //     return {
  //       encrypted_dek: Buffer.concat([enc1, enc2]).toString('hex'),
  //       dek_iv:        iv.toString('hex'),
  //       dek_tag:       tag.toString('hex'),
  //     };
  //   } catch {
  //     return null;
  //   }
  // }

  public wrapDEK(dek: Buffer): { encrypted_dek: string; dek_iv: string; dek_tag: string } | null {
    // ⚡ FIX: Fallback to the Guest Key
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

  /**
   * Unwraps an encrypted DEK using the master key.
   * Called before decrypting a media file.
   *
   * @returns  Raw DEK buffer, or null on failure/tamper
   */
  // public unwrapDEK(encrypted_dek: string, dek_iv: string, dek_tag: string): Buffer | null {
  //   if (!this.isReady || !this.key) return null;
  //   try {
  //     const isHex    = (s: string) => /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0;
  //     const iv       = Buffer.from(dek_iv,       isHex(dek_iv)       ? 'hex' : 'base64');
  //     const tag      = Buffer.from(dek_tag,      isHex(dek_tag)      ? 'hex' : 'base64');
  //     const encBytes = Buffer.from(encrypted_dek, isHex(encrypted_dek) ? 'hex' : 'base64');

  //     const decipher = QuickCrypto.createDecipheriv(ALGORITHM, this.key, iv);
  //     decipher.setAuthTag(tag);
  //     const dec1 = decipher.update(encBytes);
  //     const dec2 = decipher.final();
  //     return Buffer.concat([dec1, dec2]);
  //   } catch {
  //     return null;
  //   }
  // }

  public unwrapDEK(encrypted_dek: string, dek_iv: string, dek_tag: string): Buffer | null {
    // ⚡ FIX: Prioritize Master Key, fallback to Guest Key seamlessly
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

  // public getRawKeyBase64(): string | null {
  //   if (!this.isReady || !this.key) return null;
  //   return this.key.toString('base64');
  // }

  public getRawKeyBase64(): string | null {
    // ⚡ FIX: Return either the Master Key or the Guest Fallback Key
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

  /**
   * Can the journal databases be opened right now WITHOUT a Face ID prompt? Standard mode: always
   * (the keys are read silently). Maximum Security / Vault: only once the Face ID bundle has been
   * unlocked (after a background wipe it hasn't – opening a database would prompt by itself).
   */
  public get canOpenJournalSilently(): boolean {
    if (!this.isBiometricProtectionEnabled()) return true;
    return this.biometricBundleLoaded || !!this.extractedMirrorKey;
  }

  /**
   * Keys for the native mirror fill (modules/wispday-mirror-fill), only while unlocked and only
   * from memory – never prompts Face ID, never reads the keychain. The native side uses them for
   * one pass and keeps nothing. Missing anything → null, and the JS path is used instead.
   */
  public async getKeysForNativeMirror(): Promise<{
    deviceKey: string; mirrorKey: string; masterKey: string | null; guestKey: string | null;
  } | null> {
    try {
      const deviceKey = this.extractedDeviceKey ?? (this.deviceKeyPromise ? await this.deviceKeyPromise : null);
      const mirrorKey = this.extractedMirrorKey;
      if (!deviceKey || !mirrorKey) return null;
      const guest = this.getGuestFallbackKey();
      const masterKey = this.key ? Buffer.from(this.key).toString('base64') : null;
      const guestKey = guest ? Buffer.from(guest).toString('base64') : null;
      if (!masterKey && !guestKey) return null;
      return { deviceKey, mirrorKey, masterKey, guestKey };
    } catch {
      return null;
    }
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