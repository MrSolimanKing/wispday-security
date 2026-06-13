/**
 * WispDay — EncryptedImage (native bridge)
 * =====================================================================
 * This is the JavaScript side of encrypted-image rendering. It does NOT
 * decrypt anything itself — it resolves the correct decryption key and
 * hands it, with the file's IV and auth tag, to a native view
 * (`WispdayEncryptedImageView`) that performs the AES-128-GCM decrypt in
 * memory, decodes/downsamples the bitmap, and displays it via ImageIO.
 * No plaintext image is ever written back to disk, and large decoded
 * bitmaps never cross the JS bridge.
 *
 * Why this file is worth reviewing:
 *
 *   - It shows the KEY HANDOFF to native. For per-file (envelope)
 *     encryption, the per-file DEK is unwrapped here in JS using the
 *     audited encryptionService.unwrapDEK() and only that single-file DEK
 *     is passed to native. The native component therefore never receives
 *     or stores the user's master key — at most it sees one file's DEK for
 *     the lifetime of one render. (The `decryptionKeyBase64` prop name is
 *     generic; in the envelope path its value is the unwrapped DEK, not
 *     the master key.)
 *
 *   - It FAILS CLOSED. If no key is available (locked / logged out) or the
 *     IV/tag are missing, the component renders nothing rather than
 *     attempting to display anything.
 *
 *   - It re-resolves the key on key-change events, so when the app locks
 *     (master key wiped from RAM via lockMemory) the next render has no
 *     key and shows nothing until unlock.
 *
 * The cryptographic operations (unwrapDEK, key storage, the GCM scheme)
 * live in EncryptionService.ts. The native decryptor mirrors that same
 * AES-128-GCM contract; its source is published separately.
 */

import { requireNativeComponent, StyleSheet, ViewStyle } from 'react-native';
import { memo, useEffect, useState, useCallback } from 'react';
import { encryptionService } from '../middleware/EncryptionMiddleware';

interface NativeEncryptedImageProps {
  encryptedFilePath: string;
  decryptionKeyBase64: string;   // per-file DEK (envelope) or master key (legacy)
  ivBase64: string;
  tagBase64: string;
  resizeMode?: 'cover' | 'contain';
  style?: ViewStyle;
  onLoad?: (event: any) => void;
}

const NativeEncryptedImageView =
  requireNativeComponent<NativeEncryptedImageProps>('WispdayEncryptedImageView');

// The native side expects base64 inputs; the IV/tag are stored as hex.
function hexToBase64(hex: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return btoa(String.fromCharCode(...bytes));
}

export const EncryptedImage = memo(({
  img,
  style,
  resizeMode = 'cover',
  onLoad,
}: {
  img: any;
  style?: any;
  resizeMode?: 'cover' | 'contain';
  onLoad?: () => void;
}) => {
  const rawUri = img?.thumbnail || img?.uri || null;

  const [decryptionKeyBase64, setDecryptionKeyBase64] = useState<string | null>(null);

  // Resolve the key to hand to native:
  //   - Envelope path: unwrap the per-file DEK with the master key (in JS,
  //     via the audited unwrapDEK) and pass ONLY that DEK to native.
  //   - Legacy path (no wrapped DEK on the item): pass the active key.
  // If no key is available, pass null → the component renders nothing.
  const resolveKey = useCallback(() => {
    const masterOrGuestKey = encryptionService.getRawKeyBase64();
    if (!masterOrGuestKey) {
      setDecryptionKeyBase64(null);
      return;
    }

    if (img?.encryptedDek && img?.dekIv && img?.dekTag) {
      const dekBuffer = encryptionService.unwrapDEK(img.encryptedDek, img.dekIv, img.dekTag);
      setDecryptionKeyBase64(dekBuffer ? dekBuffer.toString('base64') : null);
    } else {
      setDecryptionKeyBase64(masterOrGuestKey);
    }
  }, [img?.encryptedDek, img?.dekIv, img?.dekTag]);

  useEffect(() => {
    // Resolve on mount, and re-resolve whenever key state changes (e.g. the
    // app locks and wipes the master key, or unlocks and restores it).
    resolveKey();
    const unsubscribe = encryptionService.onKeyChange(resolveKey);
    return () => unsubscribe();
  }, [resolveKey]);

  // Fail closed: without a file, a resolved key, and the IV+tag, render nothing.
  if (!rawUri || !decryptionKeyBase64 || !img?.encryptionIv || !img?.encryptionTag) {
    return null;
  }

  const filePath  = rawUri.replace('file://', '');
  const ivBase64  = hexToBase64(img.encryptionIv);
  const tagBase64 = hexToBase64(img.encryptionTag);

  return (
    <NativeEncryptedImageView
      style={style ?? [StyleSheet.absoluteFill, { borderRadius: 16 }]}
      encryptedFilePath={filePath}
      decryptionKeyBase64={decryptionKeyBase64}
      ivBase64={ivBase64}
      tagBase64={tagBase64}
      resizeMode={resizeMode}
      onLoad={onLoad}
    />
  );
});