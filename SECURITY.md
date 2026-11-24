# Security Policy

WispDay is an end-to-end encrypted journal. This repository publishes its
client-side security layer so its claims can be checked. If you find a problem,
thank you — please tell us privately first.

## Reporting a vulnerability

Email **[contact@wispday.com](mailto:contact@wispday.com)** with:

- what you found and why it matters,
- the file(s) and line(s) involved, or steps to reproduce,
- the app version, if you tested the app itself.

Please **don't open a public issue** for a vulnerability until it has been
fixed, so users are protected in the meantime. We'll confirm we received your
report, keep you updated, and credit you in the release notes if you'd like.

## Scope

In scope: the code in this repository and the claims made in its README —
how entries, media and keys are encrypted, stored, locked, migrated and wiped.

Out of scope: the parts of the app that aren't published here (UI, sync engine,
native media code) unless your finding shows a published claim is wrong, and
issues that need a phone the attacker has already unlocked *and* that the user
has opened WispDay on (no app can protect content the user is shown on screen).

## Bug bounty

WispDay doesn't run a paid bug bounty at the moment. Good-faith reports are
read and taken seriously, and we're grateful for them. If that changes, it will
be announced here.

## Supported versions

The code here matches the WispDay iOS version named at the top of the README.
Fixes are made in the latest app version.
