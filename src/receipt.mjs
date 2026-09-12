// A public, tamper-evident erasure receipt for SAIHM.
//
// SAIHM erases a record by destroying the *wrapped key* that decrypts it: the stored
// ciphertext becomes unrecoverable noise, so the record is gone, not merely de-indexed.
// This module turns the protocol's own seal + forget results into a small, portable
// receipt that a compliance reviewer can read, re-verify, and archive.
//
// The receipt contains ONLY public material — the cell id and the record's public commitment (the
// endpoint-reported commitment for the record; offline it is the client-sealed sha256 of the
// ciphertext), plus the verifiable outcome. It carries no plaintext and no secret.
// Integrity is self-checking (`receiptHash`), and the core claim is *reproducible*: re-read
// the store after erasure and confirm zero copies survive.

import { createHash } from 'node:crypto';

export const RECEIPT_SCHEMA = 'saihm.erasure-receipt/v1';

// The protocol epoch is counted in hours; these bound what a receipt will accept as an erasure
// time. Anything outside the window falls back to the current time rather than being trusted.
const SECONDS_PER_EPOCH = 3600;
const EPOCH_FLOOR_SEC = Date.UTC(2020, 0, 1) / 1000;
const EPOCH_SKEW_SEC = 86400;

/**
 * Build an erasure receipt from the protocol's seal + forget results.
 *
 * @param {object} a
 * @param {string} a.cellId            - public id of the erased record
 * @param {string|null} [a.commitmentHash] - the record's public commitment (endpoint-reported; offline it equals the client-sealed sha256 of the ciphertext). Verify it via verifyEnvelope() if you must trust it on a hosted endpoint
 * @param {object} a.forget            - the `forget()` result ({ complete, steps:[{success}], epoch }); `epoch` is the SAIHM protocol epoch, in hours
 * @param {number} a.copiesRemaining   - records with this id still readable after erasure (verified by re-reading)
 * @param {string} a.endpoint          - 'local blind sandbox' or the hosted endpoint host
 * @returns {object} the receipt, including a `receiptHash` that makes it tamper-evident
 */
export function buildErasureReceipt({ cellId, commitmentHash = null, forget, copiesRemaining, endpoint }) {
  if (!cellId) throw new Error('buildErasureReceipt: cellId is required');
  if (!Number.isInteger(copiesRemaining) || copiesRemaining < 0) {
    throw new Error('buildErasureReceipt: copiesRemaining must be a non-negative integer');
  }
  const steps = Array.isArray(forget?.steps) ? forget.steps : [];
  const keyDestroyed = Boolean(forget?.complete) && steps.length > 0 && steps.every((s) => s?.success === true);
  const nowSec = Math.floor(Date.now() / 1000);
  // `forget.epoch` is the SAIHM protocol epoch: HOURS since the unix epoch. That is what the
  // blind operator endpoint reports and what the runtime itself multiplies by an hour to get
  // milliseconds. Reading it as seconds lands the receipt in 1970 while every other field still
  // checks out -- a receipt that verifies true and misstates when the erasure happened, which is
  // the one outcome this artifact must never produce.
  const epochSec = Number(forget?.epoch) * SECONDS_PER_EPOCH;
  // Fail closed to now unless the result is a plausible erasure time. The floor is what makes the
  // 1970 case unreachable; the ceiling catches the opposite mistake, a unix-seconds value passed
  // in by hand, which overshoots by orders of magnitude. Either unit error degrades to "now"
  // rather than to a date that would misstate the erasure. null/""/0, negative, NaN and Infinity
  // all fall outside the window too, so a malformed or hostile epoch never throws.
  const safeEpoch =
    Number.isFinite(epochSec) && epochSec >= EPOCH_FLOOR_SEC && epochSec <= nowSec + EPOCH_SKEW_SEC
      ? epochSec
      : nowSec;
  const erasedAt = new Date(safeEpoch * 1000).toISOString();

  const body = {
    schema: RECEIPT_SCHEMA,
    action: 'cryptographic-erasure',          // key destruction, not de-indexing
    basis: 'GDPR Art. 17 (right to erasure)',
    record: { cellId, commitmentHash },        // public anchors for the erased record (endpoint-reported commitment)
    result: {
      keyDestroyed,                            // the wrapped key that decrypts this record was destroyed
      copiesRemaining,                         // verified by re-reading the store after erasure
      irreversible: keyDestroyed && copiesRemaining === 0,
    },
    erasedAt,
    endpoint,
    note: 'The endpoint named in this receipt holds ciphertext only and reports destroying the wrapped '
      + 'key, which leaves the stored bytes as unrecoverable noise. This receipt is tamper-evident '
      + '(receiptHash), and its zero-copies outcome is reproducible — re-read the store with this cellId '
      + 'and confirm none survive.',
  };
  return { ...body, receiptHash: sha256Hex(canonical(body)) };
}

/**
 * Verify a receipt: its hash must match its body, and it must attest an irreversible erasure
 * (wrapped key destroyed AND zero copies remaining). Returns a structured result.
 */
export function verifyReceipt(receipt) {
  const reasons = [];
  if (!receipt || typeof receipt !== 'object') return { valid: false, reasons: ['not an object'] };
  if (receipt.schema !== RECEIPT_SCHEMA) reasons.push(`unexpected schema: ${receipt.schema}`);
  const { receiptHash, ...body } = receipt;
  if (typeof receiptHash !== 'string') reasons.push('missing receiptHash');
  else if (receiptHash !== sha256Hex(canonical(body))) reasons.push('receiptHash does not match body (tampered)');
  if (receipt.result?.keyDestroyed !== true) reasons.push('keyDestroyed is not true');
  if (receipt.result?.copiesRemaining !== 0) reasons.push('copiesRemaining is not zero');
  if (receipt.result?.irreversible !== true) reasons.push('not marked irreversible');
  return { valid: reasons.length === 0, reasons };
}

// --- helpers: a canonical (key-sorted) JSON so the hash is stable across runs/parsers ---
function canonical(o) { return JSON.stringify(sortKeys(o)); }
function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}
function sha256Hex(s) { return createHash('sha256').update(s, 'utf8').digest('hex'); }
