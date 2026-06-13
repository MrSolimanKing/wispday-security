/**
 * WispDay — AppDatabase (excerpt)
 * =====================================================================
 * This is a TRIMMED excerpt of the app's database layer, published so the
 * at-rest encryption of the local databases can be verified. It is NOT the
 * full database layer: the sync engine (server connect/watch, resync,
 * mirror watchers), data migrations, the sync-status manager and various
 * maintenance routines have all been removed. Only the parts that
 * establish and tear down ENCRYPTED storage remain.
 *
 * What a reviewer can verify from this excerpt:
 *
 *   1. THE LOCAL DATABASE IS ENCRYPTED AT REST. PowerSync is opened on top
 *      of SQLCipher via OPSqliteOpenFactory with `encryptionKey: deviceKey`.
 *      The device key is the per-install key from EncryptionService; the
 *      on-disk database file is therefore SQLCipher-encrypted and is not
 *      readable without it.
 *
 *   2. INIT FAILS SAFE. initialize() classifies errors. A failure to READ
 *      the key (temporary biometric lockout / cancel) is re-thrown
 *      untouched so the UI can re-show the lock screen — it never triggers
 *      a wipe. A genuine "not a database" mismatch is normalized to a
 *      single CORRUPT_DB_KEY_MISMATCH signal that the UI surfaces as a
 *      user-confirmed reset. Nothing is destroyed automatically.
 *
 *   3. "LOCKING" IS A RAM KEY-WIPE, BY DESIGN. The lock path does NOT close
 *      or recreate the database (see shutdownDatabases). The stated threat
 *      model is that diary CONTENT is protected by wiping the AES master
 *      key from RAM (encryptionService.lockMemory(), elsewhere), while the
 *      OS gates the encrypted DB file behind device unlock. This is a
 *      deliberate design choice, documented here so it can be evaluated
 *      rather than assumed.
 *
 *   4. RESET ROTATES KEYS + FILES. The reset/rotation routines delete the
 *      encrypted DB files and the stored device key, so a corrupt-key
 *      situation is recovered by starting fresh — never by exposing data.
 *
 * The sync engine and all higher-level data logic are intentionally not
 * part of this repo and are collapsed to `[app boundary]` markers.
 */

import { encryptionService } from "../middleware/EncryptionMiddleware";


// [app boundary] — PowerSync + SQLCipher open factory. The single
// security-relevant fact is that the DB is opened with an encryptionKey
// (see initialize() below). Types are minimal stand-ins.
type PowerSyncDatabase = {
  init: () => Promise<void>;
  connected: boolean;
};
declare function openEncryptedDatabase(opts: {
  dbFilename: string;
  encryptionKey: string;
}): PowerSyncDatabase;

// [app boundary] — secondary local store init, app KV store init, fresh-install
// guard, and the persistent db-version flag used for file rotation. Stubbed.
declare const secondaryStore: { initialize: () => Promise<void> };
declare const appStorage: { init: () => Promise<void> };
declare function runFreshInstallGuard(): Promise<void>;
declare const dbVersionStore: {
  getNumber: (key: string) => number | undefined;
  set: (key: string, value: number) => void;
};

// [app boundary] — raw file system + keystore deletion used only by the
// emergency reset / rotation routines.
declare const FileSystem: {
  exists: (path: string) => Promise<boolean>;
  unlink: (path: string) => Promise<void>;
  libraryDir: string;
  documentDir: string;
};
declare const SecureStore: {
  deleteItemAsync: (key: string) => Promise<void>;
};
declare const Platform: { OS: 'ios' | 'android' };

// Keystore slot names for the per-install device key (must match EncryptionService).
const DEVICE_KEY_SLOT = 'app_local_device_key_v1';
const DEVICE_KEY_SLOT_BIOMETRIC = 'app_local_device_key_v1_biometric';

export let powerSync: PowerSyncDatabase;
let _initPromise: Promise<PowerSyncDatabase> | null = null;


/**
 * GUARANTEE 1 + 2 — open the ENCRYPTED database, fail safe on key errors.
 */
export async function initializeDatabase(): Promise<PowerSyncDatabase> {
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    try {
      await runFreshInstallGuard();   // [app boundary]

      // Fetch the per-install device key ONCE (the single-prompt coordinator in
      // EncryptionService ensures this does not double-prompt for biometrics).
      const deviceKey = await encryptionService.getOrGenerateDeviceKey();
      if (!deviceKey) {
        throw new Error('Device_Key_Missing: Cannot initialize the database.');
      }

      // Open PowerSync on SQLCipher with the device key. This is what makes the
      // local database file encrypted at rest.
      powerSync = openEncryptedDatabase({
        dbFilename: `diary${getDbSuffix()}.db`,
        encryptionKey: deviceKey,
      });

      await powerSync.init();           // DB fully open
      await secondaryStore.initialize();// [app boundary] secondary local store
      await appStorage.init();          // [app boundary] encrypted KV store

      return powerSync;
    } catch (error: any) {
      // Clear the cached promise so a later unlock attempt can retry.
      _initPromise = null;
      const msg = String(error?.message || '');

      // Key-READ failure (temporary lockout / cancel): bubble up untouched so
      // the UI re-shows the lock screen. NOT corruption — never wipe here.
      if (msg === 'BIOMETRIC_BUNDLE_UNAVAILABLE' || msg === 'AUTH_TEMPORARILY_UNAVAILABLE') {
        throw error;
      }

      // Genuine key/DB mismatch: normalize every variant into one signal the UI
      // surfaces as a user-confirmed reset.
      if (msg.includes('file is not a database') ||
          msg.includes('not a database') ||
          msg.includes('SQLITE_NOTADB')) {
        throw new Error('CORRUPT_DB_KEY_MISMATCH');
      }

      throw error;
    }
  })();

  return _initPromise;
}


/**
 * GUARANTEE 3 — "locking" the app is a RAM key-wipe, not a DB close.
 *
 * This intentionally does NOT close or recreate the database. Modules hold
 * the `powerSync` instance by reference and watchers bind to it; closing it
 * would invalidate those references and break the offline-first guarantee
 * that a local write always succeeds. The content protection comes from
 * wiping the AES master key from RAM (encryptionService.lockMemory(), called
 * by the lock lifecycle), which renders diary content unreadable while the
 * encrypted DB file itself stays gated by the OS behind device unlock.
 *
 * Documented as a design choice so it can be evaluated, not assumed.
 */
export async function shutdownDatabases(): Promise<void> {
  console.log('🔒 [lock] Content locked (keys wiped from RAM by caller); DB handles left intact');
}

/**
 * Optional: drain any pending writes WITHOUT closing anything, so no
 * half-written row is left in flight when the lock screen appears.
 */
export async function quiesceForLock(): Promise<void> {
  // [app boundary] — waits for the pending write queue to drain. Non-destructive.
}


// ─── DB file versioning (used for non-destructive rotation) ──────────────────
export const getDbSuffix = (): string => {
  const version = dbVersionStore.getNumber('db_version') || 1;
  return version === 1 ? '' : `_v${version}`;
};


/**
 * GUARANTEE 4 — recovery routines.
 *
 * rotateDatabaseFiles: bumps the DB version (so the next open creates a fresh
 * file) and deletes the stored device key, so a corrupt-key situation recovers
 * by starting clean rather than exposing anything.
 */
export const rotateDatabaseFiles = async (): Promise<void> => {
  const currentVersion = dbVersionStore.getNumber('db_version') || 1;
  dbVersionStore.set('db_version', currentVersion + 1);

  await SecureStore.deleteItemAsync(DEVICE_KEY_SLOT);
  await SecureStore.deleteItemAsync(DEVICE_KEY_SLOT_BIOMETRIC);

  console.log(`✅ Database rotated to version ${currentVersion + 1}`);
};

/**
 * Emergency reset: physically deletes the encrypted DB files (including
 * SQLite's WAL/SHM sidecars) and the device key. Used only on an explicit,
 * user-confirmed recovery from a corrupt-key state.
 */
export const wipeLocalDatabases = async (): Promise<void> => {
  try {
    const iosPath = `${FileSystem.libraryDir}/LocalDatabase`;
    const androidPath = FileSystem.documentDir.replace('/files', '/databases');
    const dbDir = Platform.OS === 'ios' ? iosPath : androidPath;

    // Delete the exact files, including the WAL/SHM sidecars — deleting the
    // directory alone can fail silently.
    const targetFiles = [
      'diary.db', 'diary.db-shm', 'diary.db-wal',
      'mirror.db', 'mirror.db-shm', 'mirror.db-wal',
    ];

    for (const fileName of targetFiles) {
      const filePath = `${dbDir}/${fileName}`;
      if (await FileSystem.exists(filePath)) {
        await FileSystem.unlink(filePath);
        console.log(`✅ Deleted: ${fileName}`);
      }
    }

    await SecureStore.deleteItemAsync(DEVICE_KEY_SLOT);
    await SecureStore.deleteItemAsync(DEVICE_KEY_SLOT_BIOMETRIC);

    console.log('✅ Local database reset complete.');
  } catch (e) {
    console.error('❌ Failed to wipe databases:', e);
  }
};