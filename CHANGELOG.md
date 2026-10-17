# Changelog

## 2.2.0

## Unreleased

These changes include stricter parsing and a higher Node.js minimum. Release them as a new major version; package.json keeps the existing version until a release is prepared.

- Fix input mutation, repeat generation, string signing and literal replacement.
- Escape templates, require full-file matches and validate fields and signatures.
- Accept LF/CRLF and reject ambiguous adjacent tokens, duplicate tokens and lossy values.
- Preserve canonical signatures for supported existing flat object licenses.
- Add opt-in version 2 JSON envelopes with signed format version and structured data.
- Add explicit expiration, product and exact application version policy checks through validate().
- Remove runtime dependencies and unused test dependency.
- Require Node.js >=22; add tests, CI, publication file allowlist and MIT license text.
