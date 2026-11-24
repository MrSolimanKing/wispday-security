import QuickCrypto from 'react-native-quick-crypto';
import { Buffer } from 'buffer';
import { encryptionService } from '../middleware/EncryptionMiddleware';
import { encryptFileNative, type EncryptFileResult } from '../../modules/wispday-secure-media';

/** Largest PDF accepted. Must match SecureDocuments.maxPdfBytes (native). */
export const PDF_MAX_BYTES = 100 * 1024 * 1024;

export type EncryptedDocumentFile = EncryptFileResult & {
  encrypted_dek: string;
  dek_iv: string;
  dek_tag: string;
};

/**
 * Encrypts a PDF into WDC2 (same container and key envelope as videos):
 * a fresh per-file DEK, wrapped by the master/guest key; the file is
 * streamed natively and never passes through JS memory. The PDF is
 * validated first (readable, not password-protected, ≤ 100 MB).
 */
export async function encryptDocumentFile(
  sourceUri: string,
  destinationPath: string,
  opts: { deleteSource?: boolean } = {},
): Promise<EncryptedDocumentFile> {
  if (!encryptionService.getRawKeyBase64()) {
    await encryptionService.getOrGenerateDeviceKey();
  }

  const dek = QuickCrypto.randomBytes(16);
  const wrapped = encryptionService.wrapDEK(dek as any);
  if (!wrapped) {
    dek.fill(0);
    throw new Error('[DEK_WRAP_FAILED] No key available to protect the document.');
  }
  const keyBase64 = Buffer.from(dek).toString('base64');
  dek.fill(0);

  const result = await encryptFileNative({
    sourcePath: sourceUri.replace(/^file:\/\//, ''),
    destinationPath: destinationPath.replace(/^file:\/\//, ''),
    keyBase64,
    deleteSource: opts.deleteSource ?? false,
    contentKind: 'pdf',
  });
  return {
    ...result,
    encrypted_dek: wrapped.encrypted_dek,
    dek_iv: wrapped.dek_iv,
    dek_tag: wrapped.dek_tag,
  };
}
