// Contract tests for @saihm/erasure-receipt. Zero-dependency: node:test + node:assert only.
// Tests the SOURCE (../src/receipt.mjs), so they pass regardless of the published package name.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildErasureReceipt, verifyReceipt, RECEIPT_SCHEMA } from '../src/receipt.mjs';

// `epoch` is the SAIHM protocol epoch: HOURS since the unix epoch, matching what the blind
// operator endpoint reports. A unix-seconds value here is the unit mistake these tests guard.
const EPOCH_HOURS = 472_000; // 2023-11-05T16:00:00Z
const okForget = (epoch = EPOCH_HOURS) => ({ complete: true, steps: [{ success: true }], epoch });

const validArgs = (over = {}) => ({
  cellId: '9c29fce8abcd',
  commitmentHash: 'c3999ac2ef01',
  forget: okForget(),
  copiesRemaining: 0,
  endpoint: 'local blind sandbox',
  ...over,
});

test('buildErasureReceipt: happy path yields an irreversible, self-consistent receipt', () => {
  const r = buildErasureReceipt(validArgs());
  assert.equal(r.schema, RECEIPT_SCHEMA);
  assert.equal(r.action, 'cryptographic-erasure');
  assert.equal(r.record.cellId, '9c29fce8abcd');
  assert.equal(r.result.keyDestroyed, true);
  assert.equal(r.result.copiesRemaining, 0);
  assert.equal(r.result.irreversible, true);
  assert.equal(typeof r.receiptHash, 'string');
  assert.equal(r.receiptHash.length, 64); // sha256 hex
});

test('verifyReceipt: a well-formed receipt validates', () => {
  const { valid, reasons } = verifyReceipt(buildErasureReceipt(validArgs()));
  assert.equal(valid, true);
  assert.deepEqual(reasons, []);
});

test('verifyReceipt: any tamper to the body is detected (hash mismatch)', () => {
  const r = buildErasureReceipt(validArgs());
  r.endpoint = 'https://evil.example';          // mutate the body after hashing
  const { valid, reasons } = verifyReceipt(r);
  assert.equal(valid, false);
  assert.ok(reasons.some((x) => x.includes('does not match body')));
});

test('verifyReceipt: mutating result.copiesRemaining is caught by the hash', () => {
  const r = buildErasureReceipt(validArgs());
  r.result.copiesRemaining = 0 + 1;             // still "looks" wrong AND breaks the hash
  const { valid, reasons } = verifyReceipt(r);
  assert.equal(valid, false);
  assert.ok(reasons.some((x) => x.includes('does not match body')));
});

test('a surviving copy makes the receipt non-irreversible and invalid', () => {
  const r = buildErasureReceipt(validArgs({ copiesRemaining: 1 }));
  assert.equal(r.result.irreversible, false);
  const { valid, reasons } = verifyReceipt(r);
  assert.equal(valid, false);
  assert.ok(reasons.includes('copiesRemaining is not zero'));
  assert.ok(reasons.includes('not marked irreversible'));
});

test('an incomplete forget means the key was not destroyed', () => {
  const r = buildErasureReceipt(validArgs({ forget: { complete: false, steps: [{ success: true }] } }));
  assert.equal(r.result.keyDestroyed, false);
  assert.equal(verifyReceipt(r).valid, false);
});

test('a failed erasure step means the key was not destroyed', () => {
  const r = buildErasureReceipt(validArgs({ forget: { complete: true, steps: [{ success: true }, { success: false }] } }));
  assert.equal(r.result.keyDestroyed, false);
});

test('an empty steps array is NOT treated as key destruction (fail-closed)', () => {
  const r = buildErasureReceipt(validArgs({ forget: { complete: true, steps: [] } }));
  assert.equal(r.result.keyDestroyed, false);
});

test('buildErasureReceipt: missing cellId throws', () => {
  assert.throws(() => buildErasureReceipt(validArgs({ cellId: '' })), /cellId is required/);
});

test('buildErasureReceipt: a negative or non-integer copiesRemaining throws', () => {
  assert.throws(() => buildErasureReceipt(validArgs({ copiesRemaining: -1 })), /non-negative integer/);
  assert.throws(() => buildErasureReceipt(validArgs({ copiesRemaining: 1.5 })), /non-negative integer/);
});

test('erasedAt reflects a valid endpoint epoch (protocol epoch, in hours)', () => {
  const r = buildErasureReceipt(validArgs({ forget: okForget(EPOCH_HOURS) }));
  assert.equal(r.erasedAt, new Date(EPOCH_HOURS * 3600 * 1000).toISOString());
});

test('a malformed epoch fails closed to ~now (never a misleading 1970 timestamp)', () => {
  for (const bad of [0, -5, NaN, Infinity, null, '', 9e15]) {
    const r = buildErasureReceipt(validArgs({ forget: { complete: true, steps: [{ success: true }], epoch: bad } }));
    const year = new Date(r.erasedAt).getUTCFullYear();
    assert.ok(year >= 2026, `epoch ${bad} -> erasedAt year ${year} should be ~now, not 1970`);
  }
});

test('verifyReceipt: wrong schema is reported', () => {
  const r = buildErasureReceipt(validArgs());
  const tampered = { ...r, schema: 'not-a-real-schema' };
  const { valid, reasons } = verifyReceipt(tampered);
  assert.equal(valid, false);
  assert.ok(reasons.some((x) => x.includes('unexpected schema')));
});

test('verifyReceipt: a non-object is rejected without throwing', () => {
  assert.deepEqual(verifyReceipt(null), { valid: false, reasons: ['not an object'] });
});

test('a protocol epoch is NOT read as unix seconds (the 1970 receipt)', () => {
  // Regression: the endpoint reports hours, this module read them as seconds, so a real erasure
  // produced a receipt dated 1970 that still verified true. A receipt that verifies and misstates
  // when the erasure happened is worse than one that fails outright, so the year is asserted here
  // rather than only the verify() result.
  const r = buildErasureReceipt(validArgs({ forget: okForget(EPOCH_HOURS) }));
  assert.equal(new Date(r.erasedAt).getUTCFullYear(), 2023);
  assert.ok(verifyReceipt(r).valid);
});

test('a unix-seconds epoch passed by hand fails closed to ~now, not to the far future', () => {
  // The opposite unit mistake overshoots by orders of magnitude; it must degrade to now rather
  // than stamp the receipt with a year that is obviously wrong but still verifies.
  const r = buildErasureReceipt(validArgs({ forget: okForget(1_700_000_000) }));
  const year = new Date(r.erasedAt).getUTCFullYear();
  assert.ok(year >= 2026 && year < 2100, `unix-seconds epoch -> erasedAt year ${year}`);
});

test('a bigint epoch from the endpoint is accepted', () => {
  // BlindForgetResult.epoch is a bigint; Number() handles it, but Number.isFinite(bigint) is
  // false, so passing the raw value must not silently fall back to now.
  const r = buildErasureReceipt(validArgs({ forget: { complete: true, steps: [{ success: true }], epoch: BigInt(EPOCH_HOURS) } }));
  assert.equal(r.erasedAt, new Date(EPOCH_HOURS * 3600 * 1000).toISOString());
});
