// The WispDay backup file (.zip). Shared by the exporter (src/backup) and the importer
// (src/import/sources/wispday). Change BACKUP_FORMAT_VERSION only together with the reader.
//
//   WispDay-Backup-2026-10-31.zip
//   ├── manifest.json            never encrypted: format, dates, counts, password parameters
//   ├── collections.json(.wdb)   your collections (name, icon, colour)
//   ├── entries/000.json(.wdb)   500 entries per file
//   ├── photos/<id>.jpg(.wdb)
//   ├── voice/<id>.m4a(.wdb)
//   ├── videos/<id>.mp4|.mov      plain backup: the playable video
//   ├── videos/<id>.wdc2          password backup: the app's own encrypted file (see below)
//   ├── documents/<id>.pdf
//   └── documents/<id>.wdc2
//
// With a password every file except manifest.json ends in ".wdb" and is sealed (see password.ts):
//   - media .wdb files hold the sealed bytes,
//   - JSON .wdb files hold the sealed bytes as base64 text (so they can be read as text).
// Videos and PDFs in a password backup are NOT re-sealed: they are copied as the
// app's own chunked encrypted file (.wdc2, AES-GCM), and the file's key is stored
// in its entry inside the sealed entries JSON. Only the password opens it, and a
// 1 GB video never has to be decrypted or held in memory.
// Without a password the zip is plain and readable by anything.
//
// formatVersion 2 = the backup contains videos or PDFs (older apps say "update").

export const BACKUP_FORMAT = 'wispday-backup';
/** Highest version this app reads. Backups with only photos / voice are still written as 1. */
export const BACKUP_FORMAT_VERSION = 2;
export const BACKUP_FORMAT_VERSION_BASIC = 1;
export const WDC2_EXT = '.wdc2';
export const MANIFEST_PATH = 'manifest.json';
export const SEALED_SUFFIX = '.wdb';
export const ENTRIES_PER_CHUNK = 500;

export type BackupMediaKind = 'image' | 'voice' | 'video' | 'document';

export const MEDIA_FOLDER: Record<BackupMediaKind, string> = { image: 'photos', voice: 'voice', video: 'videos', document: 'documents' };
export const MEDIA_EXT: Record<BackupMediaKind, string> = { image: '.jpg', voice: '.m4a', video: '.mp4', document: '.pdf' };

export interface BackupEncryption {
  method: 'aes-256-gcm';
  kdf: 'pbkdf2-sha256';
  iterations: number;
  salt: string; // base64
  /** A known text sealed with the key – lets the importer say "wrong password" before reading anything else. */
  check: string; // base64 of a sealed blob
}

export interface BackupManifest {
  format: typeof BACKUP_FORMAT;
  formatVersion: number;
  backupId: string; // random – identifies this file (resume / "same file" check)
  createdAt: string;
  app: { name: 'WispDay'; version?: string };
  encryption: BackupEncryption | null;
  counts: { entries: number; photos: number; voice: number; videos: number; documents?: number; missingMedia: number; collections: number };
  firstDate: string | null;
  lastDate: string | null;
  files: { collections: string; entries: string[] };
}

export interface BackupCollection {
  id: string;
  name: string;
  description?: string;
  icon?: string;
  color?: string;
  order?: number;
}

export interface BackupMedia {
  id: string; // the media id in the app that made the backup
  kind: BackupMediaKind;
  /** Path inside the zip, or null when the file couldn't be included (see `missingReason`). */
  file: string | null;
  missingReason?: string;
  width?: number;
  height?: number;
  duration?: number;
  createdAt?: string;
  /** PDFs. */
  pageCount?: number;
  /** 'wdc2': `file` is the app's encrypted file; `key` (password backups only) opens it. */
  encFormat?: 'wdc2';
  /** Raw key (base64) of a .wdc2 file. Only ever inside a SEALED entries file. */
  key?: string;
}

export interface BackupEntry {
  id: string; // the entry id in the app that made the backup
  timestamp: string; // ISO
  content: string; // markdown
  starred: boolean;
  mood: number; // 0 = none, 1–6
  moodIntensity?: number;
  moodEnergy?: number;
  notes?: string;
  weather?: Record<string, any> | null;
  /** The entry's place (EntryLocation). Inside a password backup it is sealed with the rest of the file. */
  location?: Record<string, any> | null;
  fontFamily?: string;
  fontColor?: string;
  collections: string[]; // BackupCollection ids
  media: BackupMedia[];
}

export const mediaPath = (kind: BackupMediaKind, id: string, sealed: boolean) =>
  `${MEDIA_FOLDER[kind]}/${id}${MEDIA_EXT[kind]}${sealed ? SEALED_SUFFIX : ''}`;
/** Videos / PDFs: plain file with its real extension, or the app's encrypted .wdc2 file. */
export const fileMediaPath = (kind: BackupMediaKind, id: string, ext: string) => `${MEDIA_FOLDER[kind]}/${id}${ext}`;
export const entriesChunkPath = (i: number, sealed: boolean) => `entries/${String(i).padStart(3, '0')}.json${sealed ? SEALED_SUFFIX : ''}`;
export const collectionsPath = (sealed: boolean) => `collections.json${sealed ? SEALED_SUFFIX : ''}`;

export const isBackupManifest = (x: any): x is BackupManifest =>
  !!x && x.format === BACKUP_FORMAT && typeof x.formatVersion === 'number' && Array.isArray(x.files?.entries);
