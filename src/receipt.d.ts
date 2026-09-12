// Type definitions for @saihm/erasure-receipt

/** The receipt schema identifier embedded in every receipt. */
export const RECEIPT_SCHEMA: "saihm.erasure-receipt/v1";

/** The `forget()` result shape this module reads (from @saihm/client-pro). */
export interface ForgetResult {
  /** Whether the erasure completed end to end. */
  complete?: boolean;
  /** Per-operation steps; the wrapped key is treated as destroyed only if every step succeeded. */
  steps?: Array<{ success?: boolean }>;
  /** SAIHM protocol epoch (HOURS since the unix epoch) of the erasure, as reported by the endpoint. */
  epoch?: number | string | null;
}

export interface BuildErasureReceiptArgs {
  /** Public id of the erased record. Required. */
  cellId: string;
  /** The record's public commitment (endpoint-reported; offline it equals the client-sealed sha256 of the ciphertext). */
  commitmentHash?: string | null;
  /** The `forget()` result. */
  forget: ForgetResult;
  /** Count of records with this id still readable after erasure — you verify this is 0. */
  copiesRemaining: number;
  /** 'local blind sandbox' or the hosted endpoint host. */
  endpoint: string;
}

export interface ErasureReceipt {
  schema: typeof RECEIPT_SCHEMA;
  action: "cryptographic-erasure";
  basis: string;
  record: { cellId: string; commitmentHash: string | null };
  result: {
    keyDestroyed: boolean;
    copiesRemaining: number;
    irreversible: boolean;
  };
  erasedAt: string;
  endpoint: string;
  note: string;
  /** SHA-256 over a canonical (key-sorted) serialization of the receipt body — tamper-evident. */
  receiptHash: string;
}

export interface VerifyResult {
  valid: boolean;
  reasons: string[];
}

/**
 * Build a tamper-evident erasure receipt from the protocol's seal + forget results.
 * Throws if `cellId` is missing or `copiesRemaining` is not a non-negative integer.
 */
export function buildErasureReceipt(args: BuildErasureReceiptArgs): ErasureReceipt;

/**
 * Verify a receipt: its hash must match its body, and it must attest an irreversible erasure
 * (wrapped key destroyed AND zero copies remaining).
 */
export function verifyReceipt(receipt: unknown): VerifyResult;
