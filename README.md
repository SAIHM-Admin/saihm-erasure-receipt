# @saihm/erasure-receipt

**Prove a record was erased — not hidden.** Build and verify tamper-evident **cryptographic-erasure
receipts** (GDPR Art. 17) for [SAIHM](https://saihm.coti.global). Zero runtime dependencies.

SAIHM erases a record by destroying the *wrapped key* that decrypts it: the stored ciphertext
becomes unrecoverable noise, so the record is *gone, not merely de-indexed*. This library turns the
protocol's own seal + `forget` results into a small, portable receipt a compliance reviewer can
read, **re-verify**, and archive.

```bash
npm install @saihm/erasure-receipt
```

## Usage

```js
import { buildErasureReceipt, verifyReceipt } from '@saihm/erasure-receipt';

// After you seal a record and honour an erasure request via @saihm/client-pro:
const receipt = buildErasureReceipt({
  cellId,           // the erased record's public id
  commitmentHash,   // the record's public commitment (e.g. remember().commitmentHash)
  forget,           // the forget() result: { complete, steps: [{ success }], epoch }
                    //   epoch is the SAIHM protocol epoch, in HOURS (as the endpoint reports it)
  copiesRemaining,  // records with this id still readable after erasure (you verify == 0)
  endpoint,         // 'local blind sandbox' or your hosted endpoint host
});

const { valid, reasons } = verifyReceipt(receipt);
// valid === true only when the hash matches the body AND the erasure is irreversible
// (wrapped key destroyed AND zero copies remain). Otherwise `reasons` explains why.
```

## What's in a receipt

The receipt carries only **public** material — no plaintext, no secret:

```json
{
  "schema": "saihm.erasure-receipt/v1",
  "action": "cryptographic-erasure",
  "basis": "GDPR Art. 17 (right to erasure)",
  "record": { "cellId": "9c29fce8…", "commitmentHash": "c3999ac2…" },
  "result": { "keyDestroyed": true, "copiesRemaining": 0, "irreversible": true },
  "erasedAt": "2026-06-24T05:28:08.000Z",
  "endpoint": "local blind sandbox",
  "note": "The endpoint holds ciphertext only; destroying the wrapped key leaves the stored bytes as unrecoverable noise…",
  "receiptHash": "31228b4b…"
}
```

- **`receiptHash`** is a SHA-256 over a **canonical (key-sorted)** serialization of the body, so the
  receipt is **tamper-evident** — any change to the body changes the hash. `verifyReceipt`
  re-serializes canonically and re-hashes; never re-hash pretty-printed JSON.
- The core claim is also **reproducible**: re-read the store with this `cellId` and confirm nothing
  survives.
- `verifyReceipt` returns `{ valid: false, reasons: [...] }` if the hash doesn't match the body, if
  any copy survives, or if the wrapped key was not destroyed.

## Why this matters

For real personal data, "removed from search" is not erasure — the bytes are still there. This
library records erasure with the properties a compliance reviewer asks about: **key-destruction, not
de-indexing**; **targeted** (only the requested record); **provable** (a portable, tamper-evident,
reproducible receipt an auditor can re-verify); **non-custodial** (records are sealed client-side;
the endpoint only ever holds ciphertext).

## See also

- [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro) — the sealing client that
  produces the `remember` / `forget` results this receipt is built from.
- Runnable demo + all SAIHM demos: <https://citw2.github.io/saihm-demos/>.
- Join the protocol: <https://saihm.coti.global/join>.

## License

Apache-2.0 © SAIHM
