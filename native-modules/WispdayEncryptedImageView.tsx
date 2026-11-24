import { requireNativeComponent, StyleSheet, ViewStyle } from 'react-native';
import { memo, useEffect, useState, useCallback } from 'react';
import { encryptionService } from '../middleware/EncryptionMiddleware';
import { isWdc2 } from '../secure-media/mediaFormat';
import { EncryptedVideoFrame } from '../secure-media/EncryptedVideoFrame';
import { EncryptedPdfThumbnail } from '../secure-media/EncryptedPdf';
import { mediaCacheManager } from '../utils/MediaCacheManager';

interface NativeEncryptedImageProps {
  encryptedFilePath: string;
  decryptionKeyBase64: string; 
  ivBase64: string;
  tagBase64: string;
  resizeMode?: 'cover' | 'contain';
  style?: ViewStyle;
  onLoad?: (event: any) => void; 
}
 
const NativeEncryptedImageView = requireNativeComponent<NativeEncryptedImageProps>('WispdayEncryptedImageView');

function hexToBase64(hex: string): string {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return btoa(String.fromCharCode(...bytes));
}

export const EncryptedImage = memo(({ img, style, resizeMode = 'cover', onLoad }: { img: any, style?: any, resizeMode?: 'cover' | 'contain', onLoad?: () => void; }) => {
  const rawUri = img?.thumbnail || img?.uri || null;
  
  const [decryptionKeyBase64, setDecryptionKeyBase64] = useState<string | null>(null);

  // Not on the phone yet (still downloading): this one is on screen, so it goes first.
  useEffect(() => {
    if (!rawUri && img?.id) mediaCacheManager.prioritize(img.id);
  }, [rawUri, img?.id]);

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
    // 1. Resolve immediately on mount
    resolveKey();

    // 2. Listen to the central middleware for key changes
    const unsubscribe = encryptionService.onKeyChange(() => {
      resolveKey();
    });

    return () => unsubscribe();
  }, [resolveKey]);

  // WDC2 PDFs: first page, decrypted in RAM only.
  if (isWdc2(img) && img?.type === 'document') {
    return (
      <EncryptedPdfThumbnail
        media={img}
        style={style ?? [StyleSheet.absoluteFill, { borderRadius: 16 }]}
        resizeMode={resizeMode === 'contain' ? 'contain' : 'cover'}
        onLoad={onLoad ? () => onLoad() : undefined}
      />
    );
  }

  // WDC2 (chunked) videos: show the decrypted first frame, kept in RAM only.
  if (isWdc2(img)) {
    return (
      <EncryptedVideoFrame
        media={img}
        style={style ?? [StyleSheet.absoluteFill, { borderRadius: 16 }]}
        resizeMode={resizeMode}
        onLoad={onLoad ? () => onLoad() : undefined}
      />
    );
  }

  if (!rawUri || !decryptionKeyBase64 || !img?.encryptionIv || !img?.encryptionTag) {
    return null;
  }   

  const filePath = rawUri.replace('file://', '');
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
 
