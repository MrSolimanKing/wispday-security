import QuickCrypto from 'react-native-quick-crypto';
import { Buffer } from 'buffer';
import { encryptionService } from '../middleware/EncryptionMiddleware';
import {
  addEncryptProgressListener,
  clearFrameCache,
  encryptVideoNative,
  type EncryptVideoResult,
} from '../../modules/wispday-secure-media';

export type EncryptedVideoFile = EncryptVideoResult & {
  // Same envelope field names the upload queue already uses for photos.
  encrypted_dek: string;
  dek_iv: string;
  dek_tag: string;
};

/**
 * Encrypts a video into WDC2 format.
 *
 *  1. Generates a fresh 16-byte DEK in JS (QuickCrypto).
 *  2. Wraps it with the master/guest key via encryptionService.wrapDEK() —
 *     identical envelope to photos, so the guest→master migration re-wraps it
 *     with no changes.
 *  3. Hands the raw DEK to native, which streams the file chunk by chunk
 *     (the video never passes through JS memory).
 *
 * Used when a video is added to an entry and by the Day One importer.
 */
export async function encryptVideoFile(
  sourceUri: string,
  destinationPath: string,
  opts: {
    deleteSource?: boolean;
    optimizeForStreaming?: boolean;
    onProgress?: (progress: number) => void;
  } = {},
): Promise<EncryptedVideoFile> {
  // Same guard as encryptFile(): make sure a wrapping key is in RAM.
  if (!encryptionService.getRawKeyBase64()) {
    await encryptionService.getOrGenerateDeviceKey();
  }

  const dek = QuickCrypto.randomBytes(16);
  const wrapped = encryptionService.wrapDEK(dek as any);
  if (!wrapped) {
    dek.fill(0);
    throw new Error('[DEK_WRAP_FAILED] No key available to protect the video.');
  }
  const keyBase64 = Buffer.from(dek).toString('base64');
  dek.fill(0);

  const sub = opts.onProgress ? addEncryptProgressListener(destinationPath, opts.onProgress) : null;
  try {
    const result = await encryptVideoNative({
      sourcePath: sourceUri,
      destinationPath,
      keyBase64,
      deleteSource: opts.deleteSource ?? false,
      optimizeForStreaming: opts.optimizeForStreaming ?? false,
    });
    return {
      ...result,
      encrypted_dek: wrapped.encrypted_dek,
      dek_iv: wrapped.dek_iv,
      dek_tag: wrapped.dek_tag,
    };
  } finally {
    sub?.remove();
  }
}

/**
 * Call once at startup. When the keys are wiped (lock / logout), decrypted
 * first-frame images are dropped from native memory too.
 */
export function installSecureMediaLockHandler(): () => void {
  return encryptionService.onKeyChange(() => {
    if (!encryptionService.getRawKeyBase64()) clearFrameCache();
  });
}
