/**
 * WispDay — MirrorDatabase (excerpt: schema only)
 * =====================================================================
 * The "search mirror": a local database that holds DECRYPTED copies of
 * entries so search, the calendar, the album and the map are instant
 * without decrypting every entry on each screen.
 *
 * What a reviewer can verify here and in the files it relies on:
 *
 *   1. WHAT IT HOLDS — the columns below: entry text, notes, voice
 *      transcript, reflections, tags/categories, entities, weather,
 *      location and media DETAILS (not the media files, which stay
 *      encrypted .enc files), plus a search index column.
 *
 *   2. HOW IT IS PROTECTED — it is opened only through
 *      database/SharedMirrorConnection.ts, on SQLCipher, with its OWN
 *      random 256-bit key (EncryptionMiddleware.getOrGenerateMirrorKey):
 *        • Standard mode: key in the iOS Keychain, WHEN_UNLOCKED_THIS_DEVICE_ONLY.
 *        • Maximum Security: key inside the Face ID–protected key bundle.
 *
 *   3. LIFETIME — on lock the connection is closed and the mirror key is
 *      dropped from memory (hooks/useAppLockLifecycle.ts); on sign-out the
 *      files are deleted (database/wipeLocalData.ts).
 *
 *   4. IT NEVER SYNCS — it is a local, rebuildable copy of the encrypted
 *      main database. Nothing in it is sent to the server.
 *
 * Omitted: filling/updating rows, search and ranking (product logic, not
 * security). A native implementation fills the mirror faster using the
 * same rules; it is not published.
 */

export class MirrorDatabase {
  private db: { execute(sql: string): Promise<unknown> } | null = null; // [app boundary] SQLCipher handle from SharedMirrorConnection

  private async createSchema(): Promise<void> {
    if (!this.db) throw new Error('DB not open');

    // Main table — uses snake_case columns to match PowerSync
    await this.db.execute(`
      CREATE TABLE IF NOT EXISTS mirror_items (
        id                    TEXT PRIMARY KEY,
        content               TEXT NOT NULL DEFAULT '',
        voice_content         TEXT DEFAULT '',
        timestamp             TEXT NOT NULL,
        starred               INTEGER DEFAULT 0,
        selectedMood          INTEGER,
        moodIntensity         INTEGER,
        moodEnergy            INTEGER,
        notes                 TEXT DEFAULT '',
        itemSummery           TEXT DEFAULT '',
        font_family           TEXT DEFAULT '',
        font_color            TEXT DEFAULT '',
        item_coach_content    TEXT DEFAULT '',
        item_content_insight  TEXT DEFAULT '',
        categories_json       TEXT DEFAULT '[]',
        entities_json         TEXT DEFAULT '[]',
        replies_json          TEXT DEFAULT '[]',
        weather_json          TEXT DEFAULT '{}',
        attribute_json        TEXT DEFAULT '{}',
        media_json            TEXT DEFAULT '[]',
        search_text           TEXT DEFAULT '',
        source_hash           TEXT,
        synced_at             INTEGER NOT NULL,
        created_at            INTEGER DEFAULT (strftime('%s', 'now')),
        updated_at            INTEGER DEFAULT (strftime('%s', 'now'))
      );
    `);

    // Safe migrations (ignore "column already exists" errors)
    const migrations = [
      `ALTER TABLE mirror_items ADD COLUMN font_family TEXT DEFAULT ''`,
      `ALTER TABLE mirror_items ADD COLUMN font_color  TEXT DEFAULT ''`,
      // Location (decrypted copy — this DB never syncs)
      `ALTER TABLE mirror_items ADD COLUMN location_json TEXT DEFAULT ''`,
      `ALTER TABLE mirror_items ADD COLUMN lat           REAL`,
      `ALTER TABLE mirror_items ADD COLUMN lng           REAL`,
      `ALTER TABLE mirror_items ADD COLUMN place_name    TEXT DEFAULT ''`,
      `ALTER TABLE mirror_items ADD COLUMN country_code  TEXT DEFAULT ''`,
    ];
    for (const sql of migrations) {
      try { await this.db.execute(sql); } catch (_) {}
    }

    await this.db.execute(`
      CREATE TABLE IF NOT EXISTS mirror_sync_meta (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at INTEGER DEFAULT (strftime('%s', 'now'))
      );
    `);
  }

}
