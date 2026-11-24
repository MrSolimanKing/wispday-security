import { markWork, startSpan } from '../utils/startupTimings';
/**
 * SharedMirrorConnection.ts
 *
 * Single source of truth for the mirror_decrypted.db connection.
 * 
 * WHY THIS EXISTS:
 * MirrorDatabase (items) and HabitMirrorDatabase both open the same
 * mirror_decrypted.db file. SQLite allows only one writer at a time.
 * When both write simultaneously they get "database is locked".
 *
 * This module owns ONE connection and ONE write queue. Both databases
 * call getSharedMirrorDb() to get the connection and enqueueSharedWrite()
 * to serialize their writes — so they can never conflict.
 */

import { open, DB } from '@op-engineering/op-sqlite';
import { getDbSuffix } from './AppDatabase';
import { encryptionService } from '../middleware/EncryptionMiddleware';
import { mirrorDb } from './MirrorDatabase';
import { habitMirrorDb } from '../mirrors-database/habits/HabitMirrorDatabase';
import { goalMirrorDb } from '../mirrors-database/goals/GoalMirrorDatabase';
import { BackgroundItemProcessor } from '../processors/BackgroundItemProcessor';

let sharedDb: DB | null = null;
let initPromise: Promise<DB> | null = null;

// Single global write queue — serializes ALL writes from ALL mirror databases
// The write queue: one job at a time. Your own actions (star, delete, edits, photos) go ahead of
// waiting background jobs (a mirror check of a 20k journal holds the queue ~3 s), so what you just
// did is written first. A running job is never interrupted.
type QueuedJob = { fn: () => Promise<void>; label: string; timeoutMs: number };
const userJobs: QueuedJob[] = [];
const backgroundJobs: QueuedJob[] = [];
let jobRunning = false;
let idleWaiters: Array<() => void> = [];

/**
 * Returns the shared DB connection, initializing it on first call.
 * Subsequent calls return the same instance immediately.
 */
// export async function getSharedMirrorDb(): Promise<DB> {
//   if (sharedDb) return sharedDb;
//   if (initPromise) return initPromise;

//   initPromise = (async () => {
//     const deviceKey = await encryptionService.getOrGenerateMirrorKey();
//     if (!deviceKey) throw new Error('[SharedMirrorConnection] Device key missing');

//     const dbName = `mirror_decrypted${getDbSuffix()}.db`;
//     sharedDb = open({ name: dbName, location: 'default', encryptionKey: deviceKey });
//     console.log('✅ [SharedMirrorConnection] Opened:', dbName);
//     return sharedDb;
//   })();

//   return initPromise; 
// }


export async function getSharedMirrorDb(): Promise<DB> {
  if (sharedDb) return sharedDb;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const mirrorKey = await encryptionService.getOrGenerateMirrorKey();
      if (!mirrorKey) throw new Error('[SharedMirrorConnection] Mirror key missing');

      const dbName = `mirror_decrypted${getDbSuffix()}.db`;
      markWork('mirror database opening');
      sharedDb = open({ name: dbName, location: 'default', encryptionKey: mirrorKey });
      console.log('✅ [SharedMirrorConnection] Opened with independent key:', dbName);
      return sharedDb;
    } catch (e) {
      // CRITICAL: clear initPromise so a future call can retry after unlock.
      // Without this, a single failure (e.g. BIOMETRIC_BUNDLE_UNAVAILABLE) caches
      // a rejected promise and the mirror can NEVER reopen this session.
      initPromise = null;
      sharedDb = null;
      throw e;
    }
  })();

  return initPromise;
}

/**
 * Enqueue a write function into the single global write queue.
 * This guarantees MirrorDatabase and HabitMirrorDatabase writes
 * never run concurrently, eliminating "database is locked" errors.
 */
/**
 * Watchdog: one write that never finishes used to hold up every write after it until the app was
 * restarted (an optimistic delete stayed on screen, the overview screens stopped updating). A job
 * that takes longer than `timeoutMs` keeps running, but the queue moves on – and the report says so.
 */
export function enqueueSharedWrite(
  fn: () => Promise<void>,
  label = 'write',
  timeoutMs = 20_000,
  opts: { priority?: boolean } = {},
): void {
  (opts.priority ? userJobs : backgroundJobs).push({ fn, label, timeoutMs });
  pumpQueue();
}

function pumpQueue() {
  if (jobRunning) return;
  const job = userJobs.shift() ?? backgroundJobs.shift();
  if (!job) {
    const waiters = idleWaiters;
    idleWaiters = [];
    waiters.forEach((w) => { try { w(); } catch (_) {} });
    return;
  }
  jobRunning = true;
  runQueuedJob(job).finally(() => {
    jobRunning = false;
    pumpQueue();
  });
}

function runQueuedJob({ fn, label, timeoutMs }: QueuedJob): Promise<void> {
  const started = Date.now();
  let timer: ReturnType<typeof setTimeout> | null = null;
  const endSpan = startSpan(`mirror queue: ${label}`);
  const job = Promise.resolve().then(fn).catch((err) => {
    console.warn('[SharedMirrorConnection] Queued write failed:', err);
  }).finally(() => {
    endSpan();
    if (timer) clearTimeout(timer);
    const ms = Date.now() - started;
    if (ms > timeoutMs) logQueue(`Mirror queue: "${label}" finished after ${Math.round(ms / 1000)} s`);
  });
  const watchdog = new Promise<void>((resolve) => {
    timer = setTimeout(() => {
      logQueue(`Mirror queue: "${label}" still running after ${Math.round(timeoutMs / 1000)} s – continuing without waiting`);
      resolve();
    }, timeoutMs);
  });
  return Promise.race([job, watchdog]);
}

/** Resolves once every job queued so far has run (the queue is idle). */
function queueIdle(): Promise<void> {
  if (!jobRunning && !userJobs.length && !backgroundJobs.length) return Promise.resolve();
  return new Promise((resolve) => idleWaiters.push(resolve));
}

function logQueue(line: string) {
  console.warn(`[SharedMirrorConnection] ${line}`);
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    require('../utils/startupTimings').logStartup(line);
  } catch {}
}

/**
 * Called on logout / DB rotation to reset the connection.
 * Both mirror databases must reinitialize after this.
 */
export function closeSharedMirrorDb(): void {
  if (sharedDb) {
    try { sharedDb.close(); } catch (_) {}
    sharedDb = null;
  }
  initPromise   = null;
  console.log('✅ [SharedMirrorConnection] Closed');
}


export async function closeSharedMirrorDbAsync(stillWanted?: () => boolean): Promise<void> {
  // Drain any in-flight or queued writes before closing
  try { await queueIdle(); } catch (_) {}

  // The lock's close: if the app was unlocked again while the queue drained, the databases stay
  // open (closing now would close them under the unlocked app).
  if (stillWanted && !stillWanted()) {
    console.log('[SharedMirrorConnection] Close skipped – unlocked again');
    return;
  }

  if (sharedDb) {
    try { sharedDb.close(); } catch (_) {}
    sharedDb = null;
  }
  initPromise = null;
  console.log('✅ [SharedMirrorConnection] Closed (async, queue drained)');

  // try { mirrorDb.closeHandle(); } catch(e) {}
  try { mirrorDb.closeHandle(); } catch(e) {}
  try { habitMirrorDb.closeHandle(); } catch(e) {}
  try { goalMirrorDb.closeHandle(); } catch(e) {}
  try { BackgroundItemProcessor.getInstance().closeHandle(); } catch (e) {}
} 


/** True while the mirror database file is open (the sign-out wipe deletes it only when closed). */
export function isSharedMirrorOpen(): boolean {
  return !!sharedDb;
}

export function waitForSharedQueue(): Promise<void> {
  return queueIdle();
}



/**
 * Reopen every mirror consumer after the shared connection was closed.
 * The first reopen reopens the shared connection; the rest reuse it.
 * Each call re-grabs the new handle and re-arms its watcher.
 */
export async function reopenAllMirrors(): Promise<void> {
  const results = await Promise.allSettled([
    mirrorDb.reopen(),
    habitMirrorDb.reopen(),
    goalMirrorDb.reopen(),
    BackgroundItemProcessor.getInstance().reopen(),  
  ]);  

  results.forEach((r, i) => {
    if (r.status === 'rejected') {
      const name = ['items', 'habits', 'goals'][i];
      console.warn(`[SharedMirror] ${name} mirror reopen failed:`, r.reason);
    }
  });
}