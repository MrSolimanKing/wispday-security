// Password protection for a backup. Standard, boring crypto on purpose:
//   key  = PBKDF2-SHA256(password, random 16-byte salt, 310 000 rounds) → 32 bytes
//   blob = "WDB1" | 12-byte random IV | AES-256-GCM ciphertext | 16-byte tag
// The key never leaves the phone; the password is never stored. While a job runs, the derived key
// is kept in the encrypted job database (device key) so the job can resume after a restart, and it
// is deleted when the job ends.
import { Buffer } from 'buffer';
import type { BackupEncryption } from './format';

export interface CryptoPrimitives {
  randomBytes(n: number): Uint8Array;
  pbkdf2Sync(password: string, salt: Uint8Array, iterations: number, keylen: number, digest: 'sha256'): Uint8Array;
  createCipheriv(alg: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array): { update(b: Uint8Array): Uint8Array; final(): Uint8Array; getAuthTag(): Uint8Array };
  createDecipheriv(alg: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array): { update(b: Uint8Array): Uint8Array; final(): Uint8Array; setAuthTag(t: Uint8Array): void };
  createHash?(alg: 'sha256'): { update(b: Uint8Array): any; digest(): Uint8Array };
}

declare const __DEV__: boolean | undefined;

export const PBKDF2_ITERATIONS = 310_000;
export const MIN_PASSWORD_LENGTH = 6;
const MAGIC = Buffer.from('WDB1');
const IV_LEN = 12;
const TAG_LEN = 16;
const CHECK_TEXT = 'wispday-backup-check-v1';

/** A standalone copy (byteOffset 0, own ArrayBuffer) – safe to hand to native crypto. */
const copy = (u: Uint8Array): Buffer => {
  const out = Buffer.alloc(u.length);
  out.set(u);
  return out;
};

export class WrongPasswordError extends Error {
  code = 'WRONG_PASSWORD';
  constructor() { super('WRONG_PASSWORD'); }
}

export class BackupCipher {
  private constructor(private c: CryptoPrimitives, private key: Buffer) {}

  /** New backup: random salt, derive, and produce the manifest's `encryption` block. */
  static create(c: CryptoPrimitives, password: string, iterations = PBKDF2_ITERATIONS): { cipher: BackupCipher; params: BackupEncryption } {
    const salt = copy(c.randomBytes(16));
    const cipher = new BackupCipher(c, copy(new Uint8Array(c.pbkdf2Sync(password.normalize('NFC'), salt, iterations, 32, 'sha256') as any)));
    const check = cipher.seal(Buffer.from(CHECK_TEXT)).toString('base64');
    return { cipher, params: { method: 'aes-256-gcm', kdf: 'pbkdf2-sha256', iterations, salt: salt.toString('base64'), check } };
  }

  /** Existing backup: derive from the manifest and verify the password. Throws WrongPasswordError. */
  static unlock(c: CryptoPrimitives, password: string, params: BackupEncryption): BackupCipher {
    if (params.method !== 'aes-256-gcm' || params.kdf !== 'pbkdf2-sha256') throw new Error('UNSUPPORTED_ENCRYPTION');
    const key = copy(new Uint8Array(c.pbkdf2Sync(password.normalize('NFC'), copy(Buffer.from(params.salt, 'base64')), params.iterations, 32, 'sha256') as any));
    const cipher = new BackupCipher(c, key);
    let ok = false;
    let openError: string | null = null;
    try { ok = cipher.open(Buffer.from(params.check, 'base64')).toString() === CHECK_TEXT; } catch (e: any) { ok = false; openError = String(e?.message ?? e); }
    if (!ok) {
      // Diagnostics without secrets: lets us tell "different password typed" from "crypto misbehaving on this phone".
      let roundTrip = 'n/a';
      try { roundTrip = cipher.open(cipher.seal(Buffer.from('rt'))).toString() === 'rt' ? 'ok' : 'mismatch'; } catch (e: any) { roundTrip = `throws: ${e?.message ?? e}`; }
      let keyFp = 'n/a';
      try { if (c.createHash) keyFp = Buffer.from(c.createHash('sha256').update(key).digest()).toString('hex').slice(0, 12); } catch {}
      if (typeof __DEV__ !== 'undefined' && __DEV__) console.warn('[Backup] unlock check failed', JSON.stringify({
        passwordLength: password.length,
        passwordIsAsciiOnly: /^[\x20-\x7e]*$/.test(password),
        keyFp, roundTrip, openError, iterations: params.iterations, checkBytes: Buffer.from(params.check, 'base64').length,
      }));
      throw new WrongPasswordError();
    }
    return cipher;
  }

  /** Resume a job from the key saved in the (encrypted) job database. */
  static fromSavedKey(c: CryptoPrimitives, keyBase64: string): BackupCipher {
    return new BackupCipher(c, copy(Buffer.from(keyBase64, 'base64')));
  }

  exportKey(): string {
    return this.key.toString('base64');
  }

  seal(plain: Uint8Array): Buffer {
    const iv = copy(this.c.randomBytes(IV_LEN));
    const enc = this.c.createCipheriv('aes-256-gcm', this.key, iv);
    const body = Buffer.concat([Buffer.from(enc.update(copy(plain))), Buffer.from(enc.final())]);
    return Buffer.concat([MAGIC, iv, body, Buffer.from(enc.getAuthTag())]);
  }

  open(blob: Uint8Array): Buffer {
    const b = Buffer.from(blob);
    // Byte-by-byte: in React Native's Buffer polyfill subarray() returns a plain Uint8Array (no .equals()).
    if (b.length < MAGIC.length + IV_LEN + TAG_LEN || !MAGIC.every((v, i) => b[i] === v)) throw new Error('NOT_A_SEALED_FILE');
    // Fresh Buffer copies (RN's subarray() gives plain Uint8Array views; native crypto wants standalone buffers).
    const iv = copy(b.subarray(4, 4 + IV_LEN));
    const tag = copy(b.subarray(b.length - TAG_LEN));
    const body = copy(b.subarray(4 + IV_LEN, b.length - TAG_LEN));
    const dec = this.c.createDecipheriv('aes-256-gcm', this.key, iv);
    dec.setAuthTag(tag);
    return Buffer.concat([Buffer.from(dec.update(body)), Buffer.from(dec.final())]);
  }

  sealText(text: string): string {
    return this.seal(Buffer.from(text, 'utf8')).toString('base64');
  }

  openText(base64: string): string {
    return this.open(Buffer.from(base64, 'base64')).toString('utf8');
  }
}
