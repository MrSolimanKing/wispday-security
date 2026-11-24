/**
 * Sign-out wipe of everything this account left on the phone (logout, soft logout, "signed out from
 * another device"). Encryption keys are NOT touched here – AuthProvider handles them exactly as before.
 *
 * Why this exists: the wipe used to run only when the databases were open ("ready"). Signed out while
 * the app was locked / still starting, nothing was cleared – and the decrypted mirror (its own key,
 * which sign-out keeps) showed every entry again on the next launch. Even when open, the mirror could
 * be refilled from PowerSync in the moment between clearing one and the other.
 *
 * Now:
 *   1. a "wipe pending" flag is saved first – if anything fails or the app is killed midway, the wipe
 *      finishes at the next launch, before any screen can read the old data;
 *   2. the mirror is stopped (no watcher / timer / native fill can write), in-flight writes drain;
 *   3. PowerSync (the source) is cleared, then the mirror rows; the mirror connection is closed and its
 *      files (+ WAL) are DELETED, so no deleted rows linger in free pages either;
 *   4. the background-processor database files, the entry similarity vectors, the upload queue and
 *      the account's sync history / prompt / category caches are removed.
 * Untouched: keys, the app lock, language, theme, fonts, onboarding flags.
 */
import { IOS_LIBRARY_PATH } from '@op-engineering/op-sqlite';
import fs from 'react-native-nitro-file-system';
import { createMMKV } from 'react-native-mmkv';
import { Platform } from 'react-native';
import { powerSync } from './AppDatabase';
import { mirrorDb } from './MirrorDatabase';
import { closeSharedMirrorDbAsync, isSharedMirrorOpen, waitForSharedQueue } from './SharedMirrorConnection';
import { logStartup } from '../utils/startupTimings';

const wipeState = createMMKV({ id: 'wipe_state' });
const PENDING = 'pending_local_wipe';

// Files in <Library>/default/ that belong to the signed-out account (any version suffix).
const DEFAULT_DIR_PREFIXES = ['mirror_decrypted', 'diary_processor_v'];

// Plain account-content keys in the shared default MMKV store.
const DEFAULT_STORE_KEYS = [
  'user.customCategories', 'wispday_prompt_state', 'wispday_prompt_queues',
  'last_item_date', 'last_item_count', 'notification_engagement', 'wispday_notification_override',
  'hashtag_index_hint', 'streak_celebrated_day', 'memories_seen_day',
];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function deleteAccountDbFiles(): Promise<number> {
  if (Platform.OS !== 'ios' || !IOS_LIBRARY_PATH) return 0;
  if (isSharedMirrorOpen()) return 0; // never delete an open database; the next launch finishes it
  const dir = `${IOS_LIBRARY_PATH}/default`;
  let n = 0;
  try {
    if (!fs.existsSync(dir)) return 0;
    for (const name of await fs.promises.readdir(dir)) {
      if (!DEFAULT_DIR_PREFIXES.some((p) => name.startsWith(p))) continue;
      try { await fs.promises.unlink(`${dir}/${name}`); n++; } catch {}
    }
  } catch (e) {
    console.warn('[Wipe] file delete failed', e);
  }
  return n;
}

function clearStores() {
  try { createMMKV({ id: 'upload-queue-storage' }).clearAll(); } catch {}
  try { createMMKV({ id: 'sync_state' }).remove('has_ever_synced'); } catch {}
  try { createMMKV({ id: 'db_settings' }).remove('heal_null_media_uris_last_run'); } catch {}
  try {
    const main = createMMKV();
    for (const k of DEFAULT_STORE_KEYS) main.remove(k);
  } catch {}
}

async function clearVectors() {
  try {
    const { clearItemVectors } = require('../managers/itemVectorManager');
    await clearItemVectors();
  } catch (e) {
    console.warn('[Wipe] vectors not cleared', e);
  }
}

/**
 * Full sign-out wipe. Call after the signed-in UI has unmounted. Never throws.
 * Returns true when everything was cleared now (false = the rest finishes at the next launch).
 */
export async function wipeLocalUserData(): Promise<boolean> {
  wipeState.set(PENDING, true);
  let complete = true;

  // 1. Nothing writes the mirror any more; let a running fill finish.
  try { mirrorDb.suspend(); } catch {}
  try { await Promise.race([waitForSharedQueue(), sleep(8000)]); } catch {}

  // 2. Source first, so nothing can be copied back.
  try {
    if (!powerSync) complete = false;
    else {
      // A closed database (app locked) can make this wait forever: give it 10 s, else finish at launch.
      const ok = await Promise.race([powerSync.disconnectAndClear().then(() => true), sleep(10_000).then(() => false)]);
      if (!ok) complete = false;
    }
  } catch (e) {
    console.warn('[Wipe] PowerSync not cleared now – finishing at next launch', e);
    complete = false;
  }

  // 3. Mirror rows (habits / goals live in the same file), then close and delete the files.
  try { await mirrorDb.reset(); } catch {}
  try { await closeSharedMirrorDbAsync(); } catch {}
  await deleteAccountDbFiles();
  if (isSharedMirrorOpen()) complete = false;

  // 4. Derived data and account caches.
  await clearVectors();
  clearStores();

  if (complete) wipeState.remove(PENDING);
  try { mirrorDb.resume(); } catch {}
  // Every list / overview screen drops what it shows and loads again (from the empty mirror).
  try { mirrorDb.announceReset(); } catch {}
  return complete;
}

/**
 * At launch, right after PowerSync opens and BEFORE the mirror opens: finish a sign-out wipe that
 * couldn't complete (signed out while locked / starting, app killed midway). Never throws.
 */
export async function finishPendingWipe(): Promise<void> {
  if (!wipeState.getBoolean(PENDING)) return;
  const t0 = Date.now();
  try { if (powerSync) await powerSync.disconnectAndClear(); } catch (e) { console.warn('[Wipe] pending PowerSync clear failed', e); return; }
  if (isSharedMirrorOpen()) {
    // Already open (e.g. reopened after unlock): empty it, then close it so the files can go.
    try { await mirrorDb.reset(); } catch {}
    try { await closeSharedMirrorDbAsync(); } catch {}
  }
  const files = await deleteAccountDbFiles();
  await clearVectors();
  clearStores();
  wipeState.remove(PENDING);
  logStartup(`Sign-out wipe finished at launch (${files} database files removed) – ${Date.now() - t0} ms`);
}

export const isWipePending = () => !!wipeState.getBoolean(PENDING);
