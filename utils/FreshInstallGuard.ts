import * as SecureStore from 'expo-secure-store';
import { createMMKV } from 'react-native-mmkv';
import RNFS from 'react-native-fs';
import { Platform } from 'react-native';
import QuickCrypto from 'react-native-quick-crypto';
import { getDbSuffix } from '../database/AppDatabase';
import { ALL_KEY_STORAGE_SLOTS } from '../middleware/EncryptionMiddleware';

const guardStorage = createMMKV({ id: 'install_guard' });

const MMKV_TOKEN_KEY     = 'app_install_sandbox_token_v1';   // sandbox — wiped on uninstall
const KEYCHAIN_TOKEN_KEY = 'app_install_keychain_token_v1';  // keychain — survives uninstall

// const KEYCHAIN_KEYS_TO_WIPE = [
//   'app_local_device_key_v1',
//   'diary_master_key_v1',
//   'app_local_device_key_v1_biometric', 
//   'app_bundled_keys_v1',
//   'diary_mnemonic_words_v1',
//   'diary_identity_private_v1', 
//   'app_mirror_db_key_v1', 
//   'app_install_keychain_token_v1',
// ];

const KEYCHAIN_KEYS_TO_WIPE = [
  ...ALL_KEY_STORAGE_SLOTS,
  'app_install_keychain_token_v1',
];

type GuardResult = 'first_install' | 'reinstall' | 'tampered_mmkv' | 'tampered_both' | 'ok';

function generateToken(): string {
  return QuickCrypto.randomBytes(32).toString('hex');
}

async function dbExists(): Promise<boolean> {
  try {
    const suffix = getDbSuffix();
    const dbName = `diary${suffix}.db`;
    const path = Platform.OS === 'ios'
      ? `${RNFS.LibraryDirectoryPath}/LocalDatabase/${dbName}`
      : `${RNFS.DocumentDirectoryPath.replace('/files', '/databases')}/${dbName}`;
    return await RNFS.exists(path);
  } catch { 
    return false;
  }
}

async function evaluate(): Promise<GuardResult> {
  const mmkvToken     = guardStorage.getString(MMKV_TOKEN_KEY) ?? null;
  const keychainToken = await SecureStore.getItemAsync(KEYCHAIN_TOKEN_KEY).catch(() => null);

  // Both missing → clean first install
  if (!mmkvToken && !keychainToken) return 'first_install';

  // MMKV wiped but Keychain survived → reinstall
  // Verify with DB check to rule out OS anomaly
  if (!mmkvToken && keychainToken) {
    const hasDb = await dbExists();
    // DB still exists but MMKV gone = OS flushed MMKV only (rare edge case)
    // Don't wipe — just resync tokens
    if (hasDb) return 'tampered_mmkv';
    return 'reinstall';
  }

  // Both exist but don't match → something was altered
  if (mmkvToken !== keychainToken) {
    const hasDb = await dbExists();
    // DB exists → MMKV was likely altered (jailbreak wrote wrong token)
    // DB missing → both were altered after a reinstall
    return hasDb ? 'tampered_mmkv' : 'tampered_both';
  }

  return 'ok';
}

async function writeTokens(): Promise<void> {
  const token = generateToken();
  guardStorage.set(MMKV_TOKEN_KEY, token);
  await SecureStore.setItemAsync(KEYCHAIN_TOKEN_KEY, token, {
    keychainAccessible: SecureStore.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
  });
}

async function wipeKeychain(): Promise<void> {
  await Promise.allSettled(
    KEYCHAIN_KEYS_TO_WIPE.map(key => SecureStore.deleteItemAsync(key))
  );
}

export async function runFreshInstallGuard(): Promise<void> {
  try {
    const result = await evaluate();
    console.log(`🔐 [InstallGuard] Status: ${result}`);

    switch (result) {
      case 'ok':
        return;

      case 'first_install':
        await writeTokens();
        return;

      case 'reinstall':
        // Ghost keys from previous install — wipe and start clean
        console.warn('🔄 [InstallGuard] Reinstall detected — purging stale keys');
        await wipeKeychain();
        await writeTokens();
        return;

      case 'tampered_mmkv':
        // DB exists, Keychain token is the truth — just resync MMKV to match
        // Do NOT wipe — user's data is intact, this is an OS anomaly or
        // someone wrote a wrong MMKV value (harmless, Keychain wins)
        console.warn('⚠️ [InstallGuard] Token mismatch with DB present — resyncing tokens');
        const keychainToken = await SecureStore.getItemAsync(KEYCHAIN_TOKEN_KEY).catch(() => null);
        if (keychainToken) {
          guardStorage.set(MMKV_TOKEN_KEY, keychainToken); // restore MMKV from Keychain
        } else {
          await writeTokens(); // fallback: write fresh pair
        }
        return;

      case 'tampered_both':
        // No DB, both tokens wrong — treat as dirty reinstall
        console.warn('⚠️ [InstallGuard] Both tokens invalid, no DB — purging');
        await wipeKeychain();
        await writeTokens();
        return;
    }
  } catch (error) {
    console.warn('⚠️ [InstallGuard] Failed (non-fatal):', error);
  }
}