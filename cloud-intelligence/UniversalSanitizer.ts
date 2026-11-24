/**
 * UniversalSanitizer.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Language-agnostic PII sanitizer for WispDay.
 * Strategy: strip ALL structured identifiers (emails, numbers, codes)
 * regardless of surrounding language. Named entities (people/places)
 * are handled separately by WispDay's Insight Engine and passed in as
 * pre-tokenized entityMap — we never try to detect names ourselves.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import NativeTextEntityParser from "../native-modules/NativeTextEntityParser";

export interface Redaction {
  type: string;
  label: string;
  original: string;
  token: string;
}

export interface SanitizeOptions {
  /**
   * Named entities already extracted by WispDay's Insight Engine.
   * e.g. { 'Mike': 'P_1', 'London': 'L_1' }
   * These are replaced first, before any pattern matching.
   */
  entityMap?: Record<string, string>;
  /** Pattern IDs to skip, e.g. ['date'] */
  skip?: string[];
  /**
   * Aggressive mode: also redact any standalone digit sequence >= 6 digits
   * that wasn't caught by a specific pattern.
   * Recommended: true for maximum privacy.
   */
  aggressive?: boolean;
  stripMarkdown?: boolean;
}

export interface SanitizeResult {
  sanitized: string;
  redactions: Redaction[];
}

interface PIIPattern {
  id: string;
  label: string;
  regex: RegExp;
  token: string;
  validate?: (match: string) => boolean;
}

// ─── Pattern Registry ─────────────────────────────────────────────────────────
//
// All patterns are language-agnostic — they match structure, not words.
// Order matters: more specific patterns run before generic numeric ones.
//
const PATTERNS: PIIPattern[] = [

  // ── Network identifiers ──────────────────────────────────────────────────

  {
    id: 'email',
    label: 'Email address',
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    token: '[EMAIL]',
  },
  {
    id: 'url',
    label: 'URL',
    regex: /(?:https?|ftp):\/\/[^\s<>"']+|www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s<>"']*/g,
    token: '[URL]',
  },
  {
    id: 'ipv4',
    label: 'IP address',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    token: '[IP]',
  },
  {
    id: 'ipv6',
    label: 'IPv6 address',
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    token: '[IP]',
  },

  // ── Financial ────────────────────────────────────────────────────────────

  {
    id: 'iban',
    label: 'IBAN',
    // Run before card/phone — IBAN is more specific
    regex: /\b[A-Z]{2}\d{2}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}\b/g,
    validate: (m) => m.replace(/\s/g, '').length >= 15,
    token: '[IBAN]',
  },
  {
    id: 'card',
    label: 'Payment card number',
    regex: /\b(?:\d[\s\-]?){13,19}\b/g,
    validate: (m) => {
      const d = m.replace(/[\s\-]/g, '');
      return d.length >= 13 && d.length <= 19 && /^[3-6]/.test(d);
    },
    token: '[CARD]',
  },
  {
    id: 'money',
    label: 'Monetary amount',
    // Matches any currency symbol + digits, or digits + currency code
    // Works for $, €, £, ¥, ₺, ₹, ₩, ฿ and text codes USD/EUR/TRY etc.
    regex: /(?:[$€£¥₺₹₩฿₴₦₨])\s?[\d,.]+|[\d,.]+\s?(?:USD|EUR|GBP|TRY|JPY|CNY|RUB|AED|SAR|INR|KRW|BTC|ETH)\b/gi,
    token: '[AMOUNT]',
  },

  // ── Telecom ──────────────────────────────────────────────────────────────

  {
    id: 'phone',
    label: 'Phone number',
    // Covers: +90 532 123 45 67 / (212) 555-1234 / 555.123.4567
    regex: /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{2,4}[\s\-.]?\d{2,4}(?:[\s\-.]?\d{1,4})?/g,
    validate: (m) => {
      const d = m.replace(/\D/g, '');
      return d.length >= 7 && d.length <= 15;
    },
    token: '[PHONE]',
  }, 

  // ── Government / national IDs ────────────────────────────────────────────

  {
    id: 'tc_kimlik',
    label: 'TC Kimlik',
    regex: /\b[1-9]\d{10}\b/g,
    validate: (m) => {
      // Official checksum algorithm — eliminates false positives
      const d = m.split('').map(Number);
      const sumOdd  = d[0] + d[2] + d[4] + d[6] + d[8];
      const sumEven = d[1] + d[3] + d[5] + d[7];
      return d[9] === (sumOdd * 7 - sumEven) % 10
          && d[10] === (sumOdd + sumEven + d[9]) % 10;
    },
    token: '[ID]',
  },
  {
    id: 'ssn',
    label: 'SSN (USA)',
    regex: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    token: '[ID]',
  },
  {
    id: 'nino',
    label: 'National Insurance (UK)',
    regex: /\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[ABCD]\b/gi,
    token: '[ID]',
  },
  {
    id: 'passport',
    label: 'Passport number',
    // Generic: 1-2 letters + 6-9 digits (covers most countries)
    regex: /\b[A-Z]{1,2}\d{6,9}\b/g,
    token: '[PASSPORT]',
  },

  // ── Location ─────────────────────────────────────────────────────────────

  {
    id: 'coords',
    label: 'GPS coordinates',
    regex: /[-+]?\d{1,3}\.\d{4,},\s*[-+]?\d{1,3}\.\d{4,}/g,
    token: '[COORDS]',
  },

  // ── Dates ────────────────────────────────────────────────────────────────
  // Catches DD/MM/YYYY, YYYY-MM-DD, DD.MM.YYYY — script-neutral

  {
    id: 'date',
    label: 'Date',
    regex: /\b(?:0?[1-9]|[12]\d|3[01])[\s\/\-.](?:0?[1-9]|1[012])[\s\/\-.](?:19|20)\d{2}\b|\b(?:19|20)\d{2}[\s\/\-.](?:0?[1-9]|1[012])[\s\/\-.](?:0?[1-9]|[12]\d|3[01])\b/g,
    token: '[DATE]',
  },
];

// ─── Unicode-safe word boundary ───────────────────────────────────────────────
//
// \b only works for ASCII. Unicode property escapes handle every script:
// Arabic, Cyrillic, CJK, Thai, etc. — with ASCII fallback for old engines.
//
export function buildUnicodeWordRegex(term: string, flags = 'giu'): RegExp {
  const esc = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  try {
    return new RegExp(
      `(?<![\\p{L}\\p{N}\\p{M}])${esc}(?![\\p{L}\\p{N}\\p{M}])`,
      flags,
    );
  } catch (_) {
    return new RegExp(`(?<!\\w)${esc}(?!\\w)`, 'gi');
  }
}

// ─── Core sanitize ────────────────────────────────────────────────────────────

  export function sanitize(text: string, options: SanitizeOptions = {}): SanitizeResult {
    if (!text) return { sanitized: text, redactions: [] };

    const { 
      entityMap = {}, 
      skip = [], 
      aggressive = false, 
      stripMarkdown = false // <-- Default to false for safety
    } = options;
    
    const redactions: Redaction[] = [];
    let out = text;

    // ── 0. Strip Markdown (if requested) ─────────────────────────────────────
    // Must run before absolutely everything else so PII patterns match cleanly
    if (stripMarkdown) {
      out = NativeTextEntityParser.stripMarkdown(out);
    } 

    // ── 1. Named entities (from WispDay Insight Engine) ───────────────────────
    // Must run first — before any numeric pattern could corrupt a name.
    // Sorted longest-first to prevent partial replacements (e.g. "Alex" before "Al").
    const entityEntries = Object.entries(entityMap)
      .filter(([name]) => name.trim().length > 0)
      .sort(([a], [b]) => b.length - a.length);

  for (const [name, tokenId] of entityEntries) {
    const regex = buildUnicodeWordRegex(name);
    out = out.replace(regex, (match) => {
      const token = `[${tokenId}]`;
      redactions.push({ type: 'entity', label: 'Named entity', original: match, token });
      return token;
    });
  }

  // ── 2. Structured PII patterns ───────────────────────────────────────────
  for (const pattern of PATTERNS) {
    if (skip.includes(pattern.id)) continue;

    // Rebuild each time to reset lastIndex (stateful g-flag regex safety)
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

    out = out.replace(regex, (match) => {
      if (pattern.validate && !pattern.validate(match)) return match;
      redactions.push({
        type: pattern.id,
        label: pattern.label,
        original: match,
        token: pattern.token,
      });
      return pattern.token;
    });
  }

  // ── 3. Aggressive numeric sweep (optional) ───────────────────────────────
  // Catches any remaining long digit sequence not matched above.
  // Skips content already inside a [...] token.
  if (aggressive) {
    out = out.replace(/(?<!\[)\b\d{6,}\b(?!])/g, (match) => {
      redactions.push({
        type: 'number',
        label: 'Long number',
        original: match,
        token: '[NUMBER]',
      });
      return '[NUMBER]';
    });
  }

  return { sanitized: out, redactions };
}

// ─── Batch helper ─────────────────────────────────────────────────────────────

export interface BatchEntry {
  id: string | number;
  text: string;
  entityMap?: Record<string, string>;
}

export interface BatchResult {
  id: string | number;
  sanitized: string;
  redactions: Redaction[];
}

export function sanitizeBatch(
  entries: BatchEntry[],
  sharedOptions: SanitizeOptions = {},
): BatchResult[] {
  return entries.map((entry) => ({
    id: entry.id,
    ...sanitize(entry.text, {
      ...sharedOptions,
      entityMap: { ...(sharedOptions.entityMap ?? {}), ...(entry.entityMap ?? {}) },
    }),
  }));
}

// ─── Runtime pattern extension ────────────────────────────────────────────────

export function registerPattern(pattern: PIIPattern): void {
  if (PATTERNS.find((p) => p.id === pattern.id)) {
    throw new Error(`Pattern "${pattern.id}" is already registered.`);
  }
  PATTERNS.push(pattern);
}



/**
 
EXAMPLE: 

  Called Dr. Ahmed at +90 532 123 45 67 about my appointment. Sent the invoice of $1,250 to billing@hospital.com and the IBAN TR33 0006 1005 1978 6457 8413 26. My SSN is 234-56-7890 and I live at 40.7128, -74.0060.
  Called Dr. Ahmed at [PHONE] about my appointment. Sent the invoice of [AMOUNT] to [EMAIL] and the IBAN [IBAN]. My SSN is [PHONE] and I live at [COORDS].

 */