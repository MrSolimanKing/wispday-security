import { useCallback, useEffect, useState } from 'react';
import { encryptionService } from '../middleware/EncryptionMiddleware';

/** The envelope fields stored on a media item (same names as photos). */
export type MediaKeyEnvelope = {
  encryptedDek?: string | null;
  dekIv?: string | null;
  dekTag?: string | null;
};

/**
 * Unwraps a media item's DEK with the master (or guest) key and returns it as
 * base64 for the native view. Re-resolves on every key change, so locking the
 * app (lockMemory → notifyKeyChange) returns null and the native player tears
 * itself down.
 *
 * Unlike photos there is NO legacy fallback to the master key: every WDC2 file
 * has its own DEK.
 */
export function useMediaDecryptionKey(media: MediaKeyEnvelope | null | undefined): string | null {
  const [keyBase64, setKeyBase64] = useState<string | null>(null);
  const encryptedDek = media?.encryptedDek ?? null;
  const dekIv = media?.dekIv ?? null;
  const dekTag = media?.dekTag ?? null;

  const resolve = useCallback(() => {
    if (!encryptedDek || !dekIv || !dekTag) {
      setKeyBase64(null);
      return;
    }
    const dek = encryptionService.unwrapDEK(encryptedDek, dekIv, dekTag);
    if (!dek) {
      setKeyBase64(null);
      return;
    }
    const b64 = dek.toString('base64');
    dek.fill(0);
    setKeyBase64(b64);
  }, [encryptedDek, dekIv, dekTag]);

  useEffect(() => {
    resolve();
    return encryptionService.onKeyChange(resolve);
  }, [resolve]);

  return keyBase64;
}

/** Local .enc path for the native views, or null if the file isn't on disk yet. */
export function localEncryptedPath(uri: string | null | undefined): string | null {
  if (!uri) return null;
  const path = uri.replace(/^file:\/\//, '');
  return path.startsWith('/') ? path : null; // remote (http) URIs aren't playable yet
}
