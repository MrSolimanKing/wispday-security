import { createMMKV, MMKV } from 'react-native-mmkv';
import { encryptionService } from '../middleware/EncryptionMiddleware';

class AppStorage { 
  private store: MMKV | null = null;
  private initPromise: Promise<void> | null = null;

  // ─── BOOT (call once inside initializePowerSync) ──────────────────────────
  async init(): Promise<void> {
    if (this.store) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      try {
        // Device key is already being fetched by initializePowerSync for
        // SQLCipher — loadBiometricBundleOnce ensures it's a single prompt,
        // and this piggybacks on the same cached result from RAM.
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
    // this.store?.delete(key);
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

// One instance, used everywhere — replaces the plain `storage` from App.tsx
export const appStorage = new AppStorage();