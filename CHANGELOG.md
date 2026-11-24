# Changelog

Security-relevant changes to the published WispDay security layer.
Each entry names the WispDay iOS version that contains it.

## v1.0.1 — November 2026

### Security advisory: Maximum Security kept a readable copy of the recovery phrase

**What:** In Maximum Security mode, the encryption key was correctly protected
by Face ID, but a readable copy of the 12-word recovery phrase was also kept in
the iOS Keychain without Face ID protection, so Settings could display it.
Because the phrase *is* the key, someone able to read the Keychain of an
**unlocked** phone (for example with forensic tools) could have rebuilt the key
without Face ID.

**Who:** Users with Maximum Security turned on. Standard mode works as
documented — there, the key is available while the phone is unlocked by design.

**Fix:** In Maximum Security, the readable copy is now removed once the key has
been loaded with Face ID and verified to match exactly
(`removePlainMnemonicIfVaulted` in `middleware/EncryptionMiddleware.ts`).
Settings rebuilds the phrase from the unlocked key. Turning Maximum Security
off restores the copy. Nothing is re-encrypted and nobody is locked out.

**Action needed:** None — update to 1.0.1 and unlock once.

We have no reports of this being used. It was found during our own review of
the Maximum Security design.

### Other security improvements

- **No Face ID prompts behind the lock screen.** In Maximum Security, a
  background database read could request the keys by itself when the app
  returned; now only the lock screen can (`lockForBackground`).
- **Background work waits for unlock.** Notifications and "On this day" no
  longer try to open the journal while the keys are wiped.
- **App passcode:** PBKDF2-SHA256 with a random salt replaces salted SHA-256
  (old passcodes still work and are upgraded on the next unlock); the passcode
  recovery code now uses the system CSPRNG instead of `Math.random`.
- **Recovery key copy:** local-only clipboard item that expires after 60 seconds.

### Newly published

Search mirror, guest mode and its migration, Cloud Intelligence boundary and
sanitizer, reinstall key cleanup, backup password encryption, the JavaScript
side of video and PDF encryption, and `SECURITY.md`. See the README.
