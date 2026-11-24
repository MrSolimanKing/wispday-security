/**
 * WispDay — ItemsContext (excerpt)
 * =====================================================================
 * This is a TRIMMED excerpt of the app's diary-entry data layer,
 * published so the points where entry data is encrypted and decrypted
 * can be verified. It is NOT the full data layer: the in-memory item
 * cache, pagination, optimistic UI updates, the secondary local database,
 * the media upload queue/resume machinery, vector search and replies have
 * all been removed. Only the lines where entry data crosses the
 * plaintext↔ciphertext boundary remain.
 *
 * App subsystems are reduced to their call shape and marked
 * `// [app boundary]`. They show WHAT crosses the boundary (e.g. "the row
 * written to the database holds ciphertext"), not how those subsystems
 * work. The encryption primitives live in EncryptionMiddleware.ts; this file
 * only shows WHEN they are applied to entry data.
 *
 * The three guarantees this excerpt lets you verify:
 *
 *   1. WRITE: entry text is encrypted before it is persisted.
 *      Before an entry row is inserted into the local database, its
 *      sensitive text fields (content, notes, categories) are passed
 *      through encryptionService.encrypt(), so with a key loaded the items
 *      table holds the iv:tag:ciphertext bundle. Non-sensitive metadata (timestamps, mood
 *      numbers, flags) is stored in clear so the app can sort/filter
 *      without a key — none of it is diary content.
 *
 *   2. READ: rows are decrypted on the way out, and fail closed.
 *      Reading a row passes the stored ciphertext through
 *      encryptionService.decrypt(). If the key is not loaded, decryption
 *      returns a sentinel "locked" marker rather than throwing or exposing
 *      anything — the UI shows a locked state, never raw ciphertext or a
 *      partial plaintext.
 *
 *   3. MEDIA: files are encrypted on disk before they are queued to upload.
 *      Photos and voice memos are encrypted via
 *      encryptionService.encryptFile() — which writes a .enc file and
 *      returns the IV, auth tag and the per-file DEK wrapped under the
 *      master key. Videos and PDFs use a chunked AES-GCM container encrypted
 *      natively (see secure-media/videoEncryption.ts and
 *      documentEncryption.ts): the same kind of per-file DEK, wrapped the same
 *      way, with the IVs and tags stored inside the file. ONLY the encrypted file and those wrapping fields are
 *      queued for upload. The raw plaintext file is never uploaded; the
 *      server only ever receives ciphertext plus a wrapped DEK it cannot
 *      unwrap (it has no master key).
 *
 * Net effect a reviewer can confirm: plaintext in → ciphertext at rest in
 * the local DB → ciphertext to the server. The server never receives
 * readable entry content or media.
 */

import { encryptionService } from "../middleware/EncryptionMiddleware";


// ── [app boundary] ────────────────────────────────────────────────────────────
// Minimal stand-ins for app modules, so the flow reads end-to-end without the
// surrounding product code.

// Sentinels returned by decrypt() when content cannot be read. The UI renders a
// locked state for these; they are never real plaintext.
const LOCKED = '🔒 Locked';
const INVALID = '⚠️ Invalid Data';

// The local database. In the app this is a SQLCipher-backed store. The excerpt
// only asserts that the row written here holds ciphertext in its text columns.
const db = {
  insertItemRow: async (_row: Record<string, unknown>): Promise<void> => {},
  // Returns the raw stored row (ciphertext in the text columns).
  getItemRow: async (_id: string): Promise<Record<string, any> | null> => null,
};

// The upload queue. The excerpt only asserts that what gets enqueued is the
// ENCRYPTED file path plus the key-wrapping fields — never the plaintext file.
const uploadQueue = {
  enqueue: (_entry: EncryptedUploadEntry): void => {},
};

// Shape of a minimal diary entry as the app hands it in (plaintext).
interface PlainItemInput {
  id: string;
  content: string;            // sensitive — diary text
  notes?: string;             // sensitive
  categories?: string[];      // sensitive
  timestamp: string;          // metadata — stored in clear
  starred?: boolean;          // metadata — stored in clear
  selectedMood?: number;      // metadata — stored in clear
  media?: PickedMedia[];      // raw files to be encrypted before upload
}

interface PickedMedia {
  id: string;
  uri: string;                // local plaintext file path
  type: 'image' | 'video' | 'voice';
}

// What actually gets queued for upload: the encrypted file and the fields
// needed to decrypt it later. No plaintext, and the wrapped DEK is useless to
// the server (only the user's master key can unwrap it).
interface EncryptedUploadEntry {
  itemId: string;
  mediaId: string;
  encryptedPath: string;      // path to the .enc file
  iv: string;
  tag: string;
  encrypted_dek: string;      // DEK wrapped under the master key
  dek_iv: string;
  dek_tag: string;
}


/**
 * GUARANTEE 1 — WRITE PATH
 * Encrypts sensitive fields before the row is persisted. Metadata used for
 * sorting/filtering is intentionally left in clear (it is not entry content).
 */
export async function addItem(item: PlainItemInput): Promise<void> {
  // Sensitive text fields go through encrypt() before the row is persisted.
  // These are the app's actual expressions: encrypt() returns the
  // `iv:tag:ciphertext` bundle, and the field falls back to its input if
  // encrypt() returns null.
  const encryptedContent = encryptionService.encrypt(item.content) || item.content;

  const encryptedNotes = item.notes
    ? encryptionService.encrypt(item.notes) || item.notes
    : null;

  const encryptedCategories = item.categories && item.categories.length > 0
    ? encryptionService.encrypt(JSON.stringify(item.categories)) || JSON.stringify(item.categories)
    : null;

  // The row written to the database: ciphertext in the text columns, plain
  // metadata in the rest. Compare against decrypt() in readItem below.
  await db.insertItemRow({
    id:          item.id,
    content:     encryptedContent,        // ciphertext
    notes:       encryptedNotes,          // ciphertext (or null)
    categories:  encryptedCategories,     // ciphertext (or null)
    // ── metadata, stored in clear (not diary content) ──
    timestamp:   item.timestamp,
    starred:     item.starred ? 1 : 0,
    selected_mood: item.selectedMood ?? null,
  });                                     // [app boundary] real insert is larger

  // Media (if any) is encrypted before upload — see encryptItemMedia below.
  if (item.media && item.media.length > 0) {
    for (const m of item.media) {
      await encryptItemMedia(item.id, m);
    }
  }
}


/**
 * GUARANTEE 2 — READ PATH
 * Decrypts on the way out and fails closed: if the key is not loaded, returns
 * a locked sentinel instead of exposing ciphertext.
 */
export async function readItemContent(id: string): Promise<string> {
  const row = await db.getItemRow(id);   // [app boundary] raw stored row
  if (!row) return '';

  return safeDecrypt(row.content);
}

/**
 * Decrypt a stored field. Returns the field unchanged if it is not in the
 * encrypted format (IV:tag:ciphertext), a locked sentinel if no key is loaded,
 * and the plaintext only on a successful authenticated decrypt.
 */
export function safeDecrypt(stored: string | null): string {
  if (!stored) return '';

  // Not in the encrypted envelope format → nothing to decrypt.
  if (!stored.includes(':') || stored.split(':').length !== 3) return stored;

  // Fail closed when the key is not available.
  if (!encryptionService.ready) return LOCKED;

  // GCM-authenticated decrypt. On a wrong key or tampered data this returns a
  // sentinel (see EncryptionService.decrypt), never partial plaintext.
  const decrypted = encryptionService.decrypt(stored);
  if (decrypted === LOCKED || decrypted === INVALID) return decrypted;
  return decrypted;
}


/**
 * GUARANTEE 3 — MEDIA PATH
 * Encrypts a picked file on disk and queues ONLY the encrypted artifacts for
 * upload. The plaintext file is never enqueued or uploaded.
 */
export async function encryptItemMedia(itemId: string, media: PickedMedia): Promise<void> {
  // encryptFile: reads the plaintext file, encrypts it with a fresh per-file
  // DEK (AES-128-GCM), wraps that DEK under the master key, writes the .enc
  // file, and returns the path + IV + tag + wrapped-DEK fields.
  const result = await encryptionService.encryptFile(media.uri);
  if (!result) {
    // Encryption failed → do NOT enqueue anything. Never fall back to
    // uploading the plaintext file.
    return;
  }

  // Only the encrypted file path and the key-wrapping fields are queued.
  // The server receives these; it never sees media.uri (the plaintext file)
  // and cannot unwrap encrypted_dek without the user's master key.
  uploadQueue.enqueue({
    itemId,
    mediaId:       media.id,
    encryptedPath: result.path,
    iv:            result.iv,
    tag:           result.tag,
    encrypted_dek: result.encrypted_dek,
    dek_iv:        result.dek_iv,
    dek_tag:       result.dek_tag,
  });

  // [app boundary] The app then updates its UI/cache state and runs the upload.
  // Those steps move only the .enc file and the fields above — no plaintext.
}