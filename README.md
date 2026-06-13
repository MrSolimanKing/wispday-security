# WispDay — Security Layer

This repository contains the client-side security layer of **WispDay**, an
end-to-end encrypted journal app. It is published so the app's encryption
claims can be independently inspected.

It is **not** the full app. Only the files that derive keys, encrypt and
decrypt data, gate access, and tear down key material are included. The UI,
sync engine, subscription logic, media pipeline, and other product code are
intentionally excluded — they are not needed to verify how data is protected.

> **Scope of the published files:** these are the real security modules,
> lightly cleaned. Where they call into excluded app code, the call is reduced
> to its signature and marked `// [app boundary]`. Several files
> (`AuthProvider.tsx`, `ItemEncryptionFlow.ts`, `Router.tsx`,
> `AppDatabase.ts`) are focused **excerpts** of larger app files,
> trimmed to the security-relevant flow. `EncryptionMiddleware.ts` — the
> cryptographic core — is published in full.

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
| Encrypted KV store | MMKV with an encryption key |

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
| `EncryptionMiddleware.ts` | The cryptographic core: key derivation, AES-128-GCM encrypt/decrypt, per-file DEK wrap/unwrap, key storage and lifecycle, memory wipe. **Published in full.** |
| `AppDatabase.ts` | Opens the local databases on SQLCipher with the device key; fail-safe init error handling; reset/rotation routines. (Excerpt.) |
| `AppStorage.ts` | Encrypted MMKV key-value store, keyed by the device key. Holds only non-content app/session state. |
| `ItemEncryptionFlow.ts` | Where diary entries are encrypted on write and decrypted on read, and where media is encrypted before upload. (Excerpt.) |
| `WispdayEncryptedImageView.tsx` | JS bridge to the native image decryptor. Resolves/unwraps the per-file DEK and hands it to native; does no decryption itself. |
| `useAppLockLifecycle.ts` | Background/foreground key hygiene — wipes the master key from RAM when the app is backgrounded. |
| `SecurityLockScreen.tsx` | The unlock gate. Enforces the lock; fail-safe handling of biometric lockout and key-invalidation. |
| `Router.tsx` | Cold-start lock decision and fail-safe database init. (Excerpt.) |
| `AuthProvider.tsx` | Login / logout / unlock — the points where the session lifecycle triggers key operations. (Excerpt.) |
| `_appBoundaryStubs.ts` | Minimal stand-ins so the excerpts type-check in isolation. Substitutes the real app modules they call: the `AppDatabase.ts` helpers (`powerSync`, `closeEncryptedDatabases`, `reopenEncryptedDatabases`, `quiesceForLock`, `connectAndWatch`), the encrypted KV store (`AppStorage.ts`), the auth hook (`useAuth` from `AuthProvider.tsx`), and utilities (`recordEvent`, `generateUUID`). Has no equivalent in the app — in the running app these resolve to those real modules. |
| `package.json` | Reference subset of the app's dependencies (the security-relevant ones, exact versions). Not a buildable project. |

---

## Trace one diary entry: plaintext to ciphertext

Following a single entry through the published code:

1. **Write.** The user saves an entry. In `ItemEncryptionFlow.ts → addItem`, the
   sensitive fields (content, notes, categories) are passed through
   `encryptionService.encrypt()` **before** the row is written. If no key is
   available, the write is refused rather than storing plaintext. Non-content
   metadata (timestamp, mood, starred) is stored in clear so the app can sort
   and filter without a key.

2. **At rest.** The row lands in a SQLCipher-encrypted database opened in
   `AppDatabase.ts` with the device key as `encryptionKey`. So the
   field values are encrypted under the master key, sitting inside a database
   file that is itself encrypted under the device key.

3. **Media.** If the entry has a photo or voice note, `encryptItemMedia` calls
   `encryptionService.encryptFile()`: a fresh per-file DEK encrypts the file,
   the DEK is wrapped under the master key, and only the encrypted `.enc` file
   plus the wrapped-DEK fields are queued for upload. The plaintext file is
   never uploaded.

4. **To the server.** Sync sends the encrypted row and the encrypted media. The
   server receives ciphertext and a wrapped DEK it cannot unwrap.

5. **Read back.** On display, `ItemEncryptionFlow.ts → safeDecrypt` runs the
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

- **A secondary local database** exists alongside the primary, opened with its
  own independent key (not derived from the device key). Its purpose is internal
  to the app; what matters for security is that it is SQLCipher-encrypted under a
  separate key.

- **Background-timer dependency.** The lock lifecycle uses
  `react-native-background-timer`, which is not actively maintained. It is on a
  security-relevant path.

**Out of scope / not claimed**

- This is not a defense against a fully compromised OS or an attacker with the user's unlocked device and recovery phrase (12 word).
- AI / processing features (if any entry text is sent for processing) are a
  separate, disclosed feature and are **not** part of the at-rest encryption
  pipeline shown here.
- The server implementation is not in this repository (see below).
- The native image-decryption module (Objective-C / Swift) is not yet published;
  only its JS bridge is here. That native component is where decrypted pixels
  briefly exist, and is the natural next thing to publish for full verification.

---

## The server boundary

End-to-end encryption is a claim about both ends. The client code here shows
what *leaves* the device; it cannot, by itself, prove what the server does. For
completeness, the server's role in this design is:

- It **stores** encrypted entry rows, encrypted media, and wrapped DEKs.
- It **holds** each user's public key and an `encryption_verifier` — a known
  phrase encrypted under the user's key, used to confirm an entered recovery
  phrase is correct (see `AuthProvider.ts → unlockEncryption`).
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