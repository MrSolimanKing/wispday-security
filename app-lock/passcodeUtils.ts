import CryptoJS from 'crypto-js';
import QuickCrypto from 'react-native-quick-crypto';
import { Buffer } from 'buffer';
 
const RECOVERY_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 characters: byte % 32 is unbiased

/** Recovery code, e.g. "K7Q2M-9XHPA-3RTNE". Uses the secure random generator (was Math.random). */
export const generateRecoveryHash = (): string => {
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(QuickCrypto.randomBytes(15));
  } catch {
    // Never expected; keeps the old behaviour rather than failing the setup.
    bytes = Uint8Array.from({ length: 15 }, () => Math.floor(Math.random() * 256));
  }
  let hash = '';
  for (let i = 0; i < 15; i++) {
    if (i > 0 && i % 5 === 0) hash += '-';
    hash += RECOVERY_CHARS.charAt(bytes[i] % RECOVERY_CHARS.length);
  }
  return hash;
};

/** Old format (SHA-256 + fixed salt). Kept only to recognise passcodes saved by earlier versions. */
export const hashPasscode = (passcode: string): string => {
  return CryptoJS.SHA256(passcode + 'diary_salt_2024').toString();
};

// ── Passcode hashing (current format) ─────────────────────────────────────────
// "pbkdf2$<iterations>$<salt base64>$<hash base64>": PBKDF2-SHA256 with a random salt per
// passcode, so a copied hash can't be checked against a precomputed table and each guess is slow.
// Earlier versions saved a plain SHA-256: those still unlock, and are upgraded on the next unlock.
const PBKDF2_PREFIX = 'pbkdf2$';
const PBKDF2_ITERATIONS = 100_000;

const pbkdf2 = (passcode: string, salt: Buffer, iterations: number): Buffer =>
  Buffer.from(QuickCrypto.pbkdf2Sync(passcode, salt, iterations, 32, 'sha256') as any);

/** Hash a new passcode in the current format. */
export const hashPasscodeSecure = (passcode: string): string => {
  const salt = Buffer.from(QuickCrypto.randomBytes(16) as any);
  const hash = pbkdf2(passcode, salt, PBKDF2_ITERATIONS);
  return `${PBKDF2_PREFIX}${PBKDF2_ITERATIONS}$${salt.toString('base64')}$${hash.toString('base64')}`;
};

/** Same length check + compare without stopping at the first difference. */
const constantTimeEqual = (a: Buffer, b: Buffer): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

/**
 * Checks a passcode against what's stored, in either format.
 * `needsUpgrade`: it matched an old-format hash – save it again with hashPasscodeSecure.
 */
export const checkPasscode = (passcode: string, stored: string | undefined): { ok: boolean; needsUpgrade: boolean } => {
  if (!stored) return { ok: false, needsUpgrade: false };
  if (stored.startsWith(PBKDF2_PREFIX)) {
    try {
      const [, iter, saltB64, hashB64] = stored.split('$');
      const iterations = Number(iter);
      if (!iterations || !saltB64 || !hashB64) return { ok: false, needsUpgrade: false };
      const expected = Buffer.from(hashB64, 'base64');
      const actual = pbkdf2(passcode, Buffer.from(saltB64, 'base64'), iterations);
      return { ok: constantTimeEqual(actual, expected), needsUpgrade: false };
    } catch {
      return { ok: false, needsUpgrade: false };
    }
  }
  // Old format.
  const ok = constantTimeEqual(Buffer.from(hashPasscode(passcode)), Buffer.from(stored));
  return { ok, needsUpgrade: ok };
};

export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

export const formatRecoveryHash = (hash: string): string => {
  const cleaned = hash.replace(/-/g, '').toUpperCase();
  return cleaned.match(/.{1,5}/g)?.join('-') || cleaned;
};

export const compareHash = (input: string, stored: string): boolean => {
  const cleanInput = input.replace(/-/g, '').toUpperCase();
  const cleanStored = stored.replace(/-/g, '').toUpperCase();
  return cleanInput === cleanStored;
};