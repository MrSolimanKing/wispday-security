/**
 * locationCodec.ts
 *
 * The ONLY place that reads/writes the `items.location` column.
 *
 *  • Signed-in users: location is stored as ciphertext ("iv:tag:data"), same
 *    encryptionService.encrypt() used for content.
 *  • Guests: encrypt() returns null, so — exactly like content today — the
 *    location is kept as plain JSON locally until the user creates an account;
 *    then migrateLocalDataToEncrypted() encrypts it with the master key.
 *
 * Plain location JSON always starts with "{"; ciphertext never does.
 */
import { encryptionService } from '../../middleware/EncryptionMiddleware';

export interface EntryLocation {
  v: 1;
  lat?: number;
  lng?: number;
  name?: string;        // what the chip shows, e.g. "The Cabin" (user-editable)
  street?: string;      // "Gulf Road" (exact precision only, never the house number)
  district?: string;    // neighbourhood / area, e.g. "Salmiya"
  city?: string;
  region?: string;
  country?: string;
  countryCode?: string; // ISO 3166-1 alpha-2, e.g. "KW"
  source: 'gps' | 'photo' | 'search' | 'import';
  precision: 'exact' | 'city';
}

const ENC_RE = /^[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]*={0,2}$/;
const ERRORS = new Set(['🔒 Locked', '⚠️ Invalid Data', '⚠️ Corrupted', '🚫 Unreadable']);

export const isEncryptedLocation = (s?: string | null): boolean => !!s && ENC_RE.test(s);

/** For saving. Returns the value to put in `items.location` (or null = no location). */
export function encodeLocation(loc: EntryLocation | null | undefined): string | null {
  if (!loc) return null;
  const json = JSON.stringify({ ...loc, v: 1 });
  return encryptionService.encrypt(json) ?? json;
}

/** For reading. Accepts ciphertext or plain JSON (guest). Never throws. */
export function decodeLocation(raw?: string | null): EntryLocation | null {
  if (!raw) return null;
  let json = raw;
  if (isEncryptedLocation(raw)) {
    const d = encryptionService.decrypt(raw);
    if (!d || ERRORS.has(d)) return null;
    json = d;
  }
  try {
    const o = JSON.parse(json);
    return o && typeof o === 'object' && !Array.isArray(o) ? (o as EntryLocation) : null;
  } catch {
    return null;
  }
}

/**
 * For the guest → account migration.
 * Returns new ciphertext, or undefined = leave the column exactly as it is
 * (empty, unreadable, or encryption unavailable). Never returns plain text.
 */
export function reencryptLocation(raw?: string | null): string | undefined {
  const loc = decodeLocation(raw);
  if (!loc) return undefined;
  return encryptionService.encrypt(JSON.stringify(loc)) ?? undefined;
}

const uniqueParts = (parts: (string | undefined)[]) => {
  const out: string[] = [];
  for (const p of parts) {
    const v = p?.trim();
    if (v && !out.some(o => o.toLowerCase() === v.toLowerCase())) out.push(v);
  }
  return out;
};

/**
 * What the UI shows, most precise first, at most two parts:
 *   custom name  → "The Cabin"
 *   exact        → "Gulf Road, Salmiya"  /  "Salmiya, Kuwait City"
 *   city only    → "Kuwait City"
 *   fallback     → region → country
 */
export function locationLabel(loc?: EntryLocation | null): string {
  if (!loc) return '';
  if (loc.name?.trim()) return loc.name.trim();
  const parts = loc.precision === 'city'
    ? uniqueParts([loc.city || loc.district, loc.city ? undefined : loc.region])
    : uniqueParts([loc.street, loc.district, loc.city, loc.region]);
  if (parts.length) return parts.slice(0, 2).join(', ');
  return (loc.region || loc.country || '').trim();
}

/** "Kuwait City, Kuwait" — the second line under a custom name. */
export function locationSubtitle(loc?: EntryLocation | null): string {
  if (!loc) return '';
  const shown = new Set(locationLabel(loc).toLowerCase().split(', '));
  return uniqueParts([loc.district, loc.city || loc.region, loc.country])
    .filter(p => !shown.has(p.toLowerCase()))
    .join(', ');
}
