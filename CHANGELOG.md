# Changelog

All notable changes to `@saihm/erasure-receipt` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-12

First release. Zero-dependency library for building and verifying tamper-evident
cryptographic-erasure receipts.

### Added
- `buildErasureReceipt()` — turns a seal plus the results of a `forget` into a portable receipt.
- `verifyReceipt()` — recomputes the receipt hash and reports tampering.
- `RECEIPT_SCHEMA` — the schema identifier a verifier checks before trusting field meanings.
- Hand-written TypeScript declarations; no build step, the published `.mjs` is the source.

### Refused rather than approximated
These are the cases where the library reports a weaker result instead of a convenient one:

- **A forget that did not complete.** An incomplete, failed, or empty-steps forget yields
  `keyDestroyed: false`. The receipt is still produced, because a compliance reviewer needs the
  record of the attempt, but it does not claim destruction that did not happen.
- **A surviving copy.** A non-zero `copiesRemaining` makes the receipt non-irreversible and
  invalid. Destroying one key while another copy of the record remains readable is not erasure,
  and a receipt that said otherwise would be worse than no receipt.
- **A malformed epoch.** `0`, negative, `NaN`, `Infinity`, `null` and out-of-range values fail
  closed to approximately now rather than to 1970 — an erasure timestamped at the Unix epoch
  reads as a very old, already-satisfied request.
- **A mutated body.** The stored hash is recomputed on verify, so an edited receipt fails rather
  than verifying against its own altered contents.

[0.1.0]: https://github.com/SAIHM-Admin/saihm-erasure-receipt/releases/tag/v0.1.0
