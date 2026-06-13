/**
 * WispDay — AppStorage
 * =====================================================================
 * An encrypted key-value store (MMKV) for app-level state. It is included
 * here so a reviewer can confirm two things:
 *
 *   1. The store is ENCRYPTED. MMKV is created with an `encryptionKey`, so
 *      its on-disk contents are not readable without that key.
 *
 *   2. It is encrypted with the DEVICE KEY, not the user's master key.
 *      The device key is the per-install key (see EncryptionService) that
 *      is available at boot, before any user unlock. This store must be
 *      readable that early (it holds flags the boot path needs), so it
 *      cannot depend on the master key.
 *
 * Consequence / invariant (important):
 *   Because this store is protected at the device-key level — a weaker
 *   tier than diary entries, which are protected by the user's master key
 *   — it MUST NOT hold diary content or anything that belongs behind the
 *   user's key. It holds only non-content app/session state (lock flags,
 *   session ids, lightweight preferences). Diary text, notes, categories
 *   and media never pass through here; those go through the encrypted
 *   databases keyed by the master key.
 *
 * The key fetch piggybacks on the same single-prompt coordinator used to
 * open the SQLCipher databases (see EncryptionService.getOrGenerateDeviceKey
 * / loadBiometricBundleOnce), so enabling encryption here does not add an
 * extra biometric prompt at boot.
 */

import { createMMKV, MMKV } from 'react-native-mmkv';
import { encryptionService } from '../middleware/EncryptionMiddleware';

class AppStorage {
  private store: MMKV | null = null;
  private initPromise: Promise<void> | null = null;

  // ─── BOOT (call once during app/database init) ────────────────────────────
  async init(): Promise<void> {
    if (this.store) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      try {
        // The device key is already being fetched during DB init for SQLCipher;
        // the single-prompt coordinator means this reuses the same cached
        // result from RAM rather than triggering a second biometric prompt.
        const deviceKey = await encryptionService.getOrGenerateDeviceKey();
        this.store = createMMKV({
          id: 'app_global_storage',
          encryptionKey: deviceKey,
        });
      } finally {
        this.initPromise = null;
      }
    })();

    return this.initPromise;
  }

  // ─── SYNC API (identical surface to raw MMKV) ─────────────────────────────
  // Safe to call anywhere AFTER init() has resolved. Returns undefined
  // silently if called before init (same as MMKV returning undefined for a
  // missing key — no crash, no data corruption).

  getString(key: string): string | undefined {
    return this.store?.getString(key);
  }

  getNumber(key: string): number | undefined {
    return this.store?.getNumber(key);
  }

  getBoolean(key: string): boolean | undefined {
    return this.store?.getBoolean(key);
  }

  set(key: string, value: string | number | boolean): void {
    this.store?.set(key, value);
  }

  delete(key: string): void {
    this.store?.remove(key);
  }

  contains(key: string): boolean {
    return this.store?.contains(key) ?? false;
  }

  getAllKeys(): string[] {
    return this.store?.getAllKeys() ?? [];
  }

  clearAll(): void {
    this.store?.clearAll();
  }

  // ─── READINESS ────────────────────────────────────────────────────────────
  get isReady(): boolean {
    return this.store !== null;
  }
}

// One instance, used everywhere.
export const appStorage = new AppStorage();