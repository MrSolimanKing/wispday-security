# WispDay — Security Layer


[![Download on the App Store](https://developer.apple.com/assets/elements/badges/download-on-the-app-store.svg)](https://apps.apple.com/us/app/wispday-private-daily-diary/id6765516524)


This repository contains the client-side security layer of **WispDay**, an
end-to-end encrypted journal app. It is published so the app's encryption
claims can be independently inspected.

It is **not** the full app. Only the files that derive keys, encrypt and
decrypt data, gate access, and tear down key material are included. The UI,
sync engine, subscription logic, media pipeline, and other product code are
intentionally excluded — they are not needed to verify how data is protected.

> **Scope of the published files:** these are the real security modules.
> Where they call into excluded app code, the call is reduced to its signature
> and marked `// [app boundary]`. Several files (`AuthProvider.tsx`,
> `ItemsContext.tsx`, `Router.tsx`, `AppDatabase.ts`,
> `MirrorDatabase.excerpt.ts`) are focused **excerpts** of larger app files,
> trimmed to the security-relevant flow. `EncryptionMiddleware.ts` — the
> cryptographic core — is published in full.
>
> **Matches:** WispDay 1.0.1 (iOS), November 2026. See
> [Security updates](#security-updates-november-2026) for what changed since
> the first publication in June 2026.
>
> **Not published:** the native (Swift) media code — the image decryptor, the
> chunked video format and player, and the PDF/book renderer. It uses the same
> AES-GCM keys and per-file DEKs described here; its implementation is kept
> private for now. See [Native code](#native-code-not-published).

---

## What the app claims

1. Diary content — entry text, notes, categories, and media — is encrypted on
   the device before it is stored or synced. The server stores only ciphertext.
2. The key that protects that content is derived from a recovery phrase the
   user holds. The server never receives the key or the phrase.
3. When the app is locked or the user logs out, the key is removed from memory,
   and on logout the encrypted local data is cleared as well.

This repository lets you check claims **1** and **3** directly in code. Claim
**2**'s client half (derivation, storage, the fact that only ciphertext and a
verifier leave the device) is here; its server half is described under
[The server boundary](#the-server-boundary) and cannot be proven from client
code alone.

---

## Cryptography at a glance

| Purpose | Scheme |
| --- | --- |
| Entry text, notes, categories | AES-128-GCM (authenticated) |
| Media files | AES-128-GCM, per-file random data-encryption key (DEK) |
| DEK wrapping | Each file's DEK is wrapped with the master key (AES-128-GCM) |
| Master key | The 128-bit entropy of a BIP-39 12-word mnemonic |
| Identity key pair | X25519, deterministically derived from the mnemonic via SHA-256 domain separation |
| Local databases at rest | SQLCipher (`op-sqlite` with `sqlcipher: true`) |
| Search mirror (decrypted copy for search) | SQLCipher under its own random 256-bit key |
| Encrypted KV store | MMKV with an encryption key |
| Password-protected backups (.zip) | PBKDF2-SHA256 (310,000 rounds, random 16-byte salt) → AES-256-GCM |
| App passcode (the App Lock PIN) | PBKDF2-SHA256 (100,000 rounds, random 16-byte salt), constant-time compare |
| Passcode recovery code | 15 characters from the system CSPRNG |

All authenticated encryption uses a 96-bit IV and a 128-bit GCM auth tag, so
tampered ciphertext is rejected before any plaintext is produced. See
`EncryptionMiddleware.ts` for the constants and the implementation.

---

## Key model

Three distinct keys, with different lifetimes and jobs:

- **Master key** — per user, derived from the BIP-39 mnemonic. Encrypts diary
  content. Held in RAM only while unlocked; zero-filled from memory on
  background/lock and removed from storage on logout.
- **Device key** — per install, random. Encrypts the local SQLCipher databases
  and the MMKV store at rest. Available at boot, before any user unlock, so the
  app can start; it is not tied to a user account.
- **Per-file DEK** — a fresh random key for each media file. The file is
  encrypted with its DEK; the DEK is then wrapped under the master key. Only the
  wrapped DEK is stored, so the server cannot unwrap it.
- **Mirror key** — per install, a random 256-bit key for the local search
  mirror (see [The search mirror](#the-search-mirror)). Not derived from the
  master or device key.

**The recovery phrase in Maximum Security.** The 12 words *are* the master key.
In Standard mode a copy of the words is kept in the Keychain so Settings can
show them. In Maximum Security that readable copy is removed once the master
key has been loaded from the Face ID bundle and the words rebuilt from it match
the stored copy exactly (`removePlainMnemonicIfVaulted`). Settings then rebuilds
the words from the unlocked key. Turning Maximum Security off writes the copy
back.

**Storage modes.** Keys live in the OS keystore (iOS Keychain / Android
Keystore). There are two user-facing modes, selected by a single setting:

- **Standard (default).** Keys are readable while the device is unlocked. On
  background, keys are wiped from RAM after a short grace period, and the app
  silently re-unlocks on return if still valid.
- **Max Security.** The device + master + secondary keys are bundled behind a
  Face ID / Touch ID requirement, and the wipe + lock happen **immediately** on
  background, with no grace period. A single-prompt coordinator ensures
  concurrent callers share one biometric prompt rather than triggering several.

Internally a `vault_key_binding` flag exists and currently tracks the Max
Security state (a legacy of an earlier separate tier); it is retained in the
code but is not a separately user-selectable mode.

---

## Files

| File | Role |
| --- | --- |
| `middleware/EncryptionMiddleware.ts` | The cryptographic core: key derivation, AES-128-GCM encrypt/decrypt, per-file DEK wrap/unwrap, key storage and lifecycle (Standard / Maximum Security), mirror key, memory wipe. **Published in full.** |
| `hooks/useAppLockLifecycle.ts` | Background/foreground key hygiene — wipes keys from RAM, closes the search mirror on lock, and blocks Face ID prompts the lock screen didn't ask for. |
| `screens/security/SecurityLockScreen.tsx` | The unlock gate. Enforces the lock; fail-safe handling of biometric lockout and key invalidation. |
| `database/AppDatabase.ts` | Opens the local databases on SQLCipher with the device key; fail-safe init; reset/rotation routines. (Excerpt.) |
| `database/SharedMirrorConnection.ts` | The only way the search mirror is opened (SQLCipher, mirror key) and closed. |
| `database/MirrorDatabase.excerpt.ts` | What the search mirror stores — its schema. (Excerpt.) |
| `database/wipeLocalData.ts` | Deletes the local database files, including the mirror, on sign-out. |
| `storage/AppStorage.ts` | Encrypted MMKV key-value store, keyed by the device key. Holds only non-content app/session state. |
| `providers/ItemsContext.tsx` | Where diary entries are encrypted on write and decrypted on read, and where media is encrypted before upload. (Excerpt.) |
| `providers/AuthProvider.tsx` | Login / logout / unlock — where the session lifecycle triggers key operations and local data is cleared. (Excerpt.) |
| `routing/Router.tsx` | Cold-start lock decision and fail-safe database init. (Excerpt.) |
| `native-modules/WispdayEncryptedImageView.tsx` | JS bridge to the native image decryptor. Resolves/unwraps the per-file DEK and hands it to native; does no decryption itself. |
| `app-lock/passcodeUtils.ts` | App Lock passcode hashing (PBKDF2, upgrade from the old format) and the recovery code (CSPRNG). |
| `backup/password.ts` | Password protection for backups: PBKDF2-SHA256 → AES-256-GCM, per-file. |
| `migration/MigrateLocalDataToEncrypted.ts` | Guest → account: re-encrypts guest entries with the user's master key and re-wraps every media DEK (in entries and in the upload queue), in one database transaction. |
| `location/locationCodec.ts` | The only reader/writer of an entry's location: ciphertext for accounts, plain JSON for guests until sign-up; never writes an error marker back. |
| `utils/FreshInstallGuard.ts` | Detects a reinstall (iOS keeps Keychain items after an app is deleted) by comparing a token in the app sandbox with one in the Keychain, and wipes every stale key slot before anything opens. |
| `cloud-intelligence/CloudIntelligenceBoundary.excerpt.ts` | The optional Cloud Intelligence feature: the on/off switch, decrypt → sanitize → send, and exactly what a request contains. (Excerpt.) |
| `cloud-intelligence/UniversalSanitizer.ts` | Removes structured personal data (emails, phone numbers, cards, IBANs, IDs, coordinates, dates, long numbers…) from text before it is sent. |
| `cloud-intelligence/AIEntityProcessor.ts` | Prepares entries for the people/places insight feature: sanitizes the text and sends only it, the mood word, the date and the item id. Prompts live on the server. |
| `secure-media/mediaFormat.ts` | Tells the two media formats apart: single-blob AES-GCM (photos, voice) and the chunked container (videos, PDFs). |
| `secure-media/videoEncryption.ts` | Video encryption, JS side: fresh 16-byte DEK, wrapped by the master/guest key, zeroed after handing it to native; the video never passes through JS memory. |
| `secure-media/documentEncryption.ts` | PDF encryption, JS side: same DEK envelope as videos; refuses to encrypt if no key is available to wrap the DEK. |
| `secure-media/useMediaDecryptionKey.ts` | Unwraps a video/PDF DEK for the native player and re-checks on every key change, so locking the app tears playback down. |
| `SECURITY.md` | How to report a vulnerability privately. |
| `backup/format.ts` | The backup .zip layout — which parts are sealed with the password and which (a small manifest) are not. |
| `package.json` | Reference subset of the app's dependencies (the security-relevant ones, exact versions). Not a buildable project. |

---

## Trace one diary entry: plaintext to ciphertext

Following a single entry through the published code:

1. **Write.** The user saves an entry. In `ItemsContext.tsx → addItem`, the
   sensitive fields (content, notes, categories) are passed through
   `encryptionService.encrypt()` **before** the row is written; the exact
   expressions are in the excerpt. Non-content metadata (timestamp, mood,
   starred) is stored in clear so the app can sort and filter without a key.

2. **At rest.** The row lands in a SQLCipher-encrypted database opened in
   `AppDatabase.ts` with the device key as `encryptionKey`. So the
   field values are encrypted under the master key, sitting inside a database
   file that is itself encrypted under the device key.

3. **Media.** Videos and PDFs go through `secure-media/videoEncryption.ts` /
   `documentEncryption.ts` (chunked container, same DEK envelope). If the entry has a photo or voice note, `encryptItemMedia` calls
   `encryptionService.encryptFile()`: a fresh per-file DEK encrypts the file,
   the DEK is wrapped under the master key, and only the encrypted `.enc` file
   plus the wrapped-DEK fields are queued for upload. The plaintext file is
   never uploaded.

4. **To the server.** Sync sends the encrypted row and the encrypted media. The
   server receives ciphertext and a wrapped DEK it cannot unwrap.

5. **Read back.** On display, `ItemsContext.tsx → safeDecrypt` runs the
   stored value through `encryptionService.decrypt()`. If the key is not loaded
   it returns a locked marker rather than exposing anything. Images are decrypted
   in a native module (`WispdayEncryptedImageView.tsx` hands it the unwrapped
   per-file DEK), so plaintext pixels never round-trip through JS or hit disk.

6. **Lock / logout.** On background, `useAppLockLifecycle.ts` calls
   `encryptionService.lockMemory()` to zero-fill the master key in RAM. On
   logout, `AuthProvider.tsx` clears the encrypted databases and then calls
   `resetDevice()` to remove the key material. Either way, the key does not
   outlive the session.

---

## Threat model

**What this design protects against**

- **Server compromise / a curious or hostile server.** The server holds only
  ciphertext, wrapped DEKs, public keys, and a verifier. It cannot read entries.
- **Cloud / sync interception.** Data is encrypted before it leaves the device.
- **Casual device access while locked.** Diary content is unreadable while the
  master key is wiped from RAM, and the local database files are SQLCipher-
  encrypted and gated by the OS behind device unlock.
- **Lost device, at rest.** Both databases and the KV store are encrypted at
  rest; the master key requires the user's phrase (or biometric-bundled access).

**Documented design choices a reviewer should weigh**

These are deliberate decisions, stated openly rather than hidden:

- **Locking is a key wipe, not a full teardown — by design.** On background,
  the master key is wiped from RAM. The mirror database is closed and its
  independent key wiped (immediately in Max Security mode, after a short grace
  period otherwise), and reopened when the user returns. The primary database
  handle may remain open, but its contents stay encrypted under the user's
  master key — which has been wiped — so the open handle exposes no readable
  diary content. See `useAppLockLifecycle.ts` and `AppDatabase.ts`.

- **The "standard" (non-biometric) tier uses a short grace timer.** On iOS the
  OS suspends a backgrounded process quickly, so a scheduled grace-wipe timer
  may not fire until the app next becomes active. The *biometric* tier wipes
  synchronously and immediately on background; the standard tier's wipe can be
  deferred to the next foreground in practice. See `useAppLockLifecycle.ts`.

- **The search mirror holds decrypted copies.** See
  [The search mirror](#the-search-mirror) below — it is protected at the same
  level as the master key in each mode.

- **Background-timer dependency.** The lock lifecycle uses
  `react-native-background-timer`, which is not actively maintained. It is on a
  security-relevant path.

---

## Guest mode (no account)

WispDay can be used without an account. In that case nothing leaves the device,
and there is no master key yet — the master key comes from the recovery phrase
created with an account.

- **Media** (photos, videos, voice memos, PDFs) is encrypted exactly as for
  accounts, with a per-file DEK; the DEK is wrapped with a **guest key**
  derived from the device key (SHA-256 with domain separation,
  `getGuestFallbackKey`).
- **Entry text and locations** are stored inside the SQLCipher-encrypted local
  database (device key), but are not encrypted a second time with a personal
  key until an account exists. See `location/locationCodec.ts` and the
  `addItem` excerpt in `providers/ItemsContext.tsx`.
- **On sign-up / sign-in**, `migration/MigrateLocalDataToEncrypted.ts`
  re-encrypts entry text, notes, categories, replies and locations with the
  master key and re-wraps every media DEK from the guest key to the master key
  — including files still waiting in the upload queue. The media files
  themselves are not rewritten. The database part runs in a single
  transaction, so an interruption leaves the data as it was.

Guest data is therefore protected by the device key and the phone's own
protection; personal-key (end-to-end) protection starts with an account.

---

## Cloud Intelligence (optional)

Cloud Intelligence finds moods, categories (people, places, emotions…), goals
and insights in entries. It is the one feature where entry text leaves the
device, so it is published in `cloud-intelligence/`:

- **A setting, on by default.** It can be turned off in onboarding and in
  Settings → Security. With it off, no AI tasks are created and no entry text
  is sent for analysis.
- **Decrypted on the device, then sanitized.** If the key isn't available the
  task waits; ciphertext is never sent. `UniversalSanitizer.ts` then removes
  structured personal data: emails, URLs, IP addresses, IBANs, card numbers,
  money amounts, phone numbers, national ID and passport numbers, coordinates,
  dates and (aggressive mode) any number of 6+ digits.
- **Names are not removed.** The people and places features need them.
- **What is sent:** the sanitized text, the type of analysis, an item id and
  the device id, to the WispDay server, which relays it to an AI provider for
  processing. Never the encryption key, the recovery phrase or the account
  email.

So with Cloud Intelligence on, the end-to-end guarantee covers storage and
sync, while sanitized entry text is processed to power these features.

---

## The search mirror

To make search and browsing instant, WispDay keeps a second local database with
**decrypted copies** of entries: text, notes, voice transcripts, reflections,
tags, places and weather, plus a search index. Photos and videos are not in it;
they stay encrypted files. The schema is in `database/MirrorDatabase.excerpt.ts`.

- **Encrypted at rest** with SQLCipher under its own random 256-bit mirror key,
  opened only through `database/SharedMirrorConnection.ts`.
- **Standard mode:** the mirror key is in the Keychain
  (`WHEN_UNLOCKED_THIS_DEVICE_ONLY`). **Maximum Security:** it is inside the
  Face ID–protected bundle with the other keys.
- **On lock** the mirror is closed and its key dropped from memory —
  immediately in Maximum Security, after a short grace period in Standard mode.
  **On sign-out** its files are deleted (`database/wipeLocalData.ts`).
- **It never syncs** and can always be rebuilt from the encrypted main database.
- **Habits and goals** have their own mirror tables, handled the same way:
  closed with the mirror on lock and cleared on sign-out.

The mirror is protected at the same level as the master key in each mode: in
Standard mode both are available while the phone is unlocked; in Maximum
Security both need Face ID and are wiped when the app is left. It therefore
adds no exposure beyond what the chosen mode already allows — which is what
Maximum Security exists for.

---

## Security updates (November 2026)

Full details, including a security advisory for Maximum Security, are in
[CHANGELOG.md](CHANGELOG.md).

Changes since this repository was first published:

- **Maximum Security keeps the recovery phrase behind Face ID too.** The
  readable copy of the 12 words is removed from the Keychain once it is
  provably redundant (see [Key model](#key-model)).
- **No Face ID prompts behind the lock screen.** On background the app now
  calls `lockForBackground()`: the same key wipe as before, and in Maximum
  Security no new biometric prompt may start until the lock screen asks for
  one. Previously a database read still finishing in the background could
  request the keys by itself when the app returned.
- **Background work waits for unlock.** Notification scheduling and
  "On this day" no longer try to open the journal while the keys are wiped;
  they wait for the user to unlock.
- **App passcode hashing upgraded** from salted SHA-256 to PBKDF2-SHA256 with a
  random salt and a constant-time compare. Old hashes still unlock and are
  upgraded on the next unlock. The passcode recovery code now uses the system
  CSPRNG (it previously used `Math.random`).
- **Recovery key copy** now goes to the clipboard as a local-only item that
  expires after 60 seconds.
- **Password-protected backups** (PBKDF2-SHA256 → AES-256-GCM) — new, see
  `backup/`.
- **Search mirror, guest mode and Cloud Intelligence documented** in full
  above, with their code. Reinstall key cleanup (`utils/FreshInstallGuard.ts`)
  published.
- **`SECURITY.md`** added for private vulnerability reports.

---

## Native code (not published)

Media is decrypted natively so plaintext never round-trips through JavaScript:
photos, videos (a chunked AES-GCM container that is decrypted chunk by chunk
while playing, with decrypted chunks held only in RAM), PDFs and scans, and the
journal-to-book renderer. These use the same master key and per-file DEKs
described above. Their implementation is not published at this time; the
JavaScript side that unwraps a DEK and hands it to native code is
(`native-modules/WispdayEncryptedImageView.tsx`).

---

## The server boundary

End-to-end encryption is a claim about both ends. The client code here shows
what *leaves* the device; it cannot, by itself, prove what the server does. For
completeness, the server's role in this design is:

- It **stores** encrypted entry rows, encrypted media, and wrapped DEKs.
- It **holds** each user's public key and an `encryption_verifier` — a known
  phrase encrypted under the user's key, used to confirm an entered recovery
  phrase is correct (see `AuthProvider.tsx → unlockEncryption`).
- It **never receives** the master key, the device key, or the BIP-39 mnemonic.
  More generally, no key held in device secure storage (iOS Keychain / Android
  Keystore) is ever transmitted to the server. There is no server-side key
  escrow in any code path in this repository.

A reviewer can verify from the client that the key and phrase are never
transmitted, and that only ciphertext and the verifier are sent. Verifying the
server never logs or derives more than that requires the server side, which is
out of scope here.

---

## Contributing & security reports

**Improvements, fixes, and questions** — open an issue or a pull request.
Contributions that make WispDay safer or clearer are genuinely welcome, and
discussing the code in the open is encouraged.

**Found an actual security vulnerability?** Those, please report privately to
**[contact@wispday.com](mailto:contact@wispday.com)** instead of opening a
public issue, so it can be fixed before it's disclosed. Enough detail to
reproduce it helps. Reports are read and taken seriously.

WispDay does not currently run a paid bug-bounty program. We can't offer
compensation for reports right now, and we're grateful for good-faith
disclosures regardless. If that changes, we'll say so here.

---

## License & usage

© 2026 WispDay. Licensed under the [GNU AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html).

You're welcome to read, verify, and learn from this code, and to contribute
improvements back. If you reuse it, the same openness applies — any derivative
must also be open-sourced under the AGPL. This is the published security layer
of WispDay; the rest of the app is separate.

Found a security issue? See [Contributing & security reports](#contributing--security-reports) above. 