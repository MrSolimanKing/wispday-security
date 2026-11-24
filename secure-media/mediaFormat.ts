/**
 * Media storage formats. Helpers with no top-level imports — safe to use anywhere
 * (ItemsContext, queue, renderers) without circular-dependency risk.
 *
 *   (no encFormat) → legacy single-blob AES-GCM: needs iv + tag + DEK envelope.
 *   'wdc2'         → chunked AES-GCM (videos): nonce + tags live inside the file,
 *                    so only the DEK envelope is stored. NEVER pass these files
 *                    to encryptionService.encryptFile/decryptFile*.
 */
export const WDC2_FORMAT = 'wdc2' as const;
export type EncFormat = typeof WDC2_FORMAT;

type HasFormat = { encFormat?: string | null } | null | undefined;

export function isWdc2(m: HasFormat): boolean {
  return (m as any)?.encFormat === WDC2_FORMAT;
}

/** Upload-queue entry already encrypted on disk (must NOT be encrypted again). */
export function queueEntryIsEncrypted(e: any): boolean {
  if (isWdc2(e)) return !!e?.encrypted_dek;
  return !!(e?.iv && e?.tag && e?.encrypted_dek);
}

/**
 * Upload-queue entry that may be uploaded now.
 * WDC2 videos upload through their own direct-to-S3 path (secure-media/videoUpload.ts),
 * and only while encrypted video is enabled; otherwise they stay queued locally.
 */
export function queueEntryIsUploadable(e: any): boolean {
  if (isWdc2(e)) return !!e?.encrypted_dek && videoUploadsEnabled();
  return !!(e?.iv && e?.tag && e?.encrypted_dek);
}

// Late-bound so this file stays import-free (no cycles from ItemsContext).
function videoUploadsEnabled(): boolean {
  try {
    return require('./videoFlags').isEncryptedVideoEnabled() === true;
  } catch {
    return false;
  }
}
