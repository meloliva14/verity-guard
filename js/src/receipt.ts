/**
 * Verify a signed verdict receipt, and gate an action on one that actually authorizes it.
 *
 * Two different questions live here, and conflating them is the failure this file prevents:
 *
 *   verifyReceiptOffline()  -- is this signature real?
 *   requireReceipt()        -- does this receipt permit THIS action?
 *
 * The first is necessary and nowhere near sufficient. Checking a signature and calling that
 * "verified" is exactly the lie an independent verification layer must not make possible.
 *
 * Everything is ASYNC because WebCrypto is. That is a deliberate trade: `globalThis.crypto
 * .subtle` exists on Node 18.4+, Deno, Cloudflare Workers, Vercel edge and modern browsers,
 * whereas `node:crypto` and `Buffer` do not — and this package has already shipped one bug
 * from assuming `Buffer` exists. Portability wins over a synchronous signature.
 *
 * The canonicalization is specified in RECEIPTS.md. This implementation is intentionally
 * independent of the Python one and of the standalone verify_receipt.js in the repo root: if
 * they agreed because they shared code, that agreement would prove nothing.
 */

/** Every field the engine signs. Extra fields are preserved and signed over. */
export interface Receipt {
  receipt_id?: string;
  issued_at?: string;
  service?: string;
  endpoint?: string;
  model_tier?: string;
  claim_sha256?: string;
  context_sha256?: string;
  verdict?: string;
  confidence?: number;
  output_sha256?: string;
  key_id?: string;
  signature?: string;
  test?: boolean;
  [k: string]: unknown;
}

/**
 * Thrown when the runtime cannot verify at all — NOT when a signature is bad.
 *
 * "I could not check" and "I checked, and no" must never arrive in the same shape. Returning
 * a rejection here would let a runtime without WebCrypto read as a forged receipt, or worse,
 * let a caller who only checks `ok` treat an unverifiable environment as a decision.
 */
export class OfflineVerifyUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OfflineVerifyUnavailable";
  }
}

/** Thrown by requireReceipt when a receipt does not authorize the action. */
export class ReceiptRejected extends Error {
  constructor(
    public readonly reason: RejectReason,
    public readonly detail: string,
    public readonly receipt?: Receipt,
  ) {
    super(`receipt does not authorize this action [${reason}]: ${detail}`);
    this.name = "ReceiptRejected";
  }
}

export type RejectReason =
  | "invalid"
  | "not_bound"
  | "test_receipt"
  | "verdict_not_accepted"
  | "unknown_accepted_verdict"
  | "no_accepted_verdict"
  | "stale"
  | "future_dated"
  | "no_timestamp"
  | "replayed"
  | "no_receipt_id";

/**
 * Verdicts meaning "the claim held up". Deliberately tiny, and `uncertain` is NOT in it: the
 * engine returns `uncertain` precisely when it declines to guess, and reading an abstention as
 * permission would invert the one property this product sells.
 */
export const AFFIRMATIVE: readonly string[] = ["supported"];

/** Used ONLY to give a precise error when a caller allowlists an impossible verdict. */
const KNOWN_VERDICTS = new Set(["supported", "unsupported", "uncertain"]);

/** A receipt stamped slightly ahead is ordinary clock skew between two machines. */
const FUTURE_TOLERANCE_SECONDS = 120;

/**
 * Exactly the WebCrypto surface this file uses — declared structurally rather than importing
 * the DOM lib, because this package compiles against `lib: ["ES2022"]` and must stay usable in
 * runtimes that are not browsers. It also documents the whole contract a host has to satisfy.
 */
interface MinimalSubtle {
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
  importKey(
    format: "raw",
    keyData: Uint8Array,
    algorithm: string,
    extractable: boolean,
    keyUsages: string[],
  ): Promise<unknown>;
  verify(algorithm: string, key: unknown, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
}

const subtle = (): MinimalSubtle => {
  const c = (globalThis as { crypto?: { subtle?: MinimalSubtle } }).crypto;
  if (!c?.subtle) {
    throw new OfflineVerifyUnavailable(
      "offline verification needs WebCrypto (globalThis.crypto.subtle), which this runtime " +
        "does not expose. Node 18.4+, Deno, Cloudflare Workers and modern browsers all have it.",
    );
  }
  return c.subtle;
};

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new TypeError("not hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(b: ArrayBuffer | Uint8Array): string {
  const u = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = "";
  for (const x of u) s += x.toString(16).padStart(2, "0");
  return s;
}

/**
 * The exact bytes that were signed: keys sorted, no whitespace, `signature` excluded, UTF-8.
 *
 * JSON.stringify already renders integral numbers without a decimal point (1 -> "1", not
 * "1.0") and emits non-ASCII literally, which is what the Python signer does. Both are
 * deliberate divergences from RFC 8785 and are documented in RECEIPTS.md rather than left as
 * traps. Sorting is by UTF-16 code unit here vs code point in Python — identical for every
 * field name in use, and the second documented divergence.
 */
export function canonicalBytes(receipt: Receipt): Uint8Array {
  const body: Record<string, unknown> = {};
  for (const k of Object.keys(receipt).filter((k) => k !== "signature").sort()) {
    body[k] = receipt[k];
  }
  return new TextEncoder().encode(JSON.stringify(body));
}

/** key_id is derived from the key, so you can confirm you hold the right one yourself. */
export async function deriveKeyId(publicKeyHex: string): Promise<string> {
  const d = await subtle().digest("SHA-256", hexToBytes(publicKeyHex));
  return "ed25519:" + bytesToHex(d).slice(0, 16);
}

async function sha256Hex(s: string): Promise<string> {
  return bytesToHex(await subtle().digest("SHA-256", new TextEncoder().encode(s)));
}

export interface OfflineResult {
  ok: boolean;
  reason: string;
}

/**
 * Is this signature real — and, if `claim` is given, is it about that claim?
 *
 * Pass `claim` to check BINDING. Without it that question is simply not asked, and the reason
 * string says so out loud, because a valid signature over SOME claim is not authorization for
 * YOURS. Throws OfflineVerifyUnavailable if the runtime cannot verify; never returns false for
 * that case.
 */
export async function verifyReceiptOffline(
  receipt: Receipt,
  publicKeyHex: string,
  claim?: string,
  context?: string,
): Promise<OfflineResult> {
  const s = subtle(); // throws before any judgement if verification is impossible

  if (typeof receipt !== "object" || receipt === null) {
    return { ok: false, reason: `not a receipt: got ${typeof receipt}` };
  }
  for (const f of ["signature", "key_id"] as const) {
    if (typeof receipt[f] !== "string") return { ok: false, reason: `not a receipt: missing ${f}` };
  }

  let derived: string;
  try {
    derived = await deriveKeyId(publicKeyHex);
  } catch {
    return { ok: false, reason: "the public key supplied is not valid hex" };
  }
  if (receipt.key_id !== derived) {
    // Deliberately does NOT fetch a key that works. That would restore the trust this
    // function exists to remove.
    return {
      ok: false,
      reason: `wrong key: receipt was signed by ${receipt.key_id}, the key supplied is ${derived}`,
    };
  }

  let valid: boolean;
  try {
    const key = await s.importKey("raw", hexToBytes(publicKeyHex), "Ed25519", false, ["verify"]);
    valid = await s.verify(
      "Ed25519",
      key,
      hexToBytes(receipt.signature as string),
      canonicalBytes(receipt),
    );
  } catch (e) {
    return { ok: false, reason: `could not verify: ${(e as Error).message}` };
  }
  if (!valid) return { ok: false, reason: "SIGNATURE INVALID -- this content is not what was signed" };

  if (claim === undefined) {
    return {
      ok: true,
      reason:
        "signature valid -- NOT checked against any claim; pass claim to confirm this receipt " +
        "vouches for what you are about to act on",
    };
  }
  if ((await sha256Hex(claim)) !== receipt.claim_sha256) {
    return {
      ok: false,
      reason: "SIGNATURE VALID BUT FOR A DIFFERENT CLAIM -- this receipt does not vouch for the claim supplied",
    };
  }
  if (context !== undefined && (await sha256Hex(context)) !== receipt.context_sha256) {
    return {
      ok: false,
      reason: "signature valid and claim matches, but the CONTEXT differs from the one this receipt was issued over",
    };
  }
  if (receipt.test === true) {
    return { ok: true, reason: "signature valid and bound -- but this is a SELF-TEST receipt, not a paid verdict" };
  }
  return { ok: true, reason: "signature valid and bound to the claim supplied" };
}

export interface RequireReceiptOptions {
  /** REQUIRED. A receipt is only ever evidence *about something*. */
  claim: string;
  context?: string;
  /** Allowlist of verdicts that may pass. Defaults to AFFIRMATIVE. */
  accept?: readonly string[];
  /** Seconds. `null` disables the freshness check — an explicit choice, never the default. */
  maxAgeSeconds?: number | null;
  allowTest?: boolean;
  /** Pass a Set you control to make receipts single-use. Written only on success. */
  seen?: Set<string>;
  /** Epoch seconds, for testing. */
  now?: number;
}

export interface CheckResult {
  ok: boolean;
  reason: RejectReason | "ok";
  detail: string;
}

function parseIssuedAt(value: unknown): number | null {
  if (typeof value !== "string" || !value.trim()) return null;
  const t = Date.parse(value.trim());
  return Number.isNaN(t) ? null : t / 1000;
}

/**
 * The non-throwing twin of requireReceipt: `{ ok, reason, detail }`.
 *
 * Still throws OfflineVerifyUnavailable if the runtime cannot verify at all.
 */
export async function checkReceipt(
  receipt: Receipt,
  publicKeyHex: string,
  opts: RequireReceiptOptions,
): Promise<CheckResult> {
  const {
    claim,
    context,
    accept = AFFIRMATIVE,
    maxAgeSeconds = 900,
    allowTest = false,
    seen,
    now,
  } = opts;

  if (typeof claim !== "string" || claim.length === 0) {
    // Not a rejection — a caller error. Silently treating a missing claim as "skip the
    // binding check" would be the exact hole this module exists to close.
    throw new TypeError(
      "requireReceipt/checkReceipt need a non-empty `claim`. A signature-only check is what " +
        "verifyReceiptOffline is for.",
    );
  }

  const res = await verifyReceiptOffline(receipt, publicKeyHex, claim, context);
  if (!res.ok) {
    const notBound = res.reason.includes("DIFFERENT CLAIM") || res.reason.includes("CONTEXT differs");
    return { ok: false, reason: notBound ? "not_bound" : "invalid", detail: res.reason };
  }

  if (receipt.test === true && !allowTest) {
    return {
      ok: false,
      reason: "test_receipt",
      detail:
        "this is a self-test receipt (test: true). It proves the signing chain works and vouches " +
        "for nothing. Pass allowTest: true only in your own tests.",
    };
  }

  const allowed = new Set(accept.map((v) => String(v).trim().toLowerCase()));
  if (allowed.size === 0) {
    return {
      ok: false,
      reason: "no_accepted_verdict",
      detail: "accept is empty, so no verdict could ever pass. Refusing rather than treating an empty allowlist as permission.",
    };
  }
  const unknown = [...allowed].filter((v) => !KNOWN_VERDICTS.has(v));
  if (unknown.length) {
    return {
      ok: false,
      reason: "unknown_accepted_verdict",
      detail:
        `accept names verdict(s) the service never returns: ${JSON.stringify(unknown.sort())}. ` +
        `Valid values are ${JSON.stringify([...KNOWN_VERDICTS].sort())}. Refusing rather than ` +
        `silently never matching.`,
    };
  }

  const verdict = String(receipt.verdict ?? "").trim().toLowerCase();
  if (!allowed.has(verdict)) {
    const why =
      verdict === "uncertain"
        ? "`uncertain` means the engine declined to guess -- that is an abstention, not a yes."
        : verdict === "unsupported"
          ? "`unsupported` means the claim did NOT hold up."
          : "That value is not one this service is contracted to return.";
    return {
      ok: false,
      reason: "verdict_not_accepted",
      detail:
        `the receipt is genuine and is about your claim, but its verdict is "${verdict}", not one ` +
        `of ${JSON.stringify([...allowed].sort())}. ${why}`,
    };
  }

  if (maxAgeSeconds !== null && maxAgeSeconds !== undefined) {
    const issued = parseIssuedAt(receipt.issued_at);
    if (issued === null) {
      return {
        ok: false,
        reason: "no_timestamp",
        detail:
          "freshness was requested but the receipt has no readable issued_at, so its age cannot " +
          "be established. Pass maxAgeSeconds: null to accept it regardless.",
      };
    }
    const current = now ?? Date.now() / 1000;
    const age = current - issued;
    if (age > maxAgeSeconds) {
      return {
        ok: false,
        reason: "stale",
        detail:
          `the receipt is genuine and affirmative, but it was issued ${age.toFixed(0)}s ago and the ` +
          `limit is ${maxAgeSeconds.toFixed(0)}s. A verdict is true as of when it was taken; the ` +
          `world is allowed to change underneath it.`,
      };
    }
    if (age < -FUTURE_TOLERANCE_SECONDS) {
      return {
        ok: false,
        reason: "future_dated",
        detail:
          `the receipt is stamped ${(-age).toFixed(0)}s in the future, beyond the ` +
          `${FUTURE_TOLERANCE_SECONDS}s tolerated for clock skew. Refusing to reason about the age ` +
          `of something that has not happened yet.`,
      };
    }
  }

  if (seen) {
    const rid = receipt.receipt_id;
    if (typeof rid !== "string" || !rid) {
      return {
        ok: false,
        reason: "no_receipt_id",
        detail: "single-use was requested but the receipt has no receipt_id, so replay cannot be detected.",
      };
    }
    if (seen.has(rid)) {
      return {
        ok: false,
        reason: "replayed",
        detail:
          `receipt ${rid} has already authorized an action. One verdict authorizes one action; ` +
          `re-presenting it is how a single check gets claimed for many.`,
      };
    }
    seen.add(rid); // success path only -- a rejected receipt is never burned
  }

  return { ok: true, reason: "ok", detail: "valid, bound to your claim, affirmative, and fresh" };
}

/**
 * Resolve with the receipt, or reject with ReceiptRejected. Never resolves to a falsy "no".
 *
 *     await requireReceipt(receipt, PUBKEY, { claim: "Invoice 4417 is unpaid" });
 *     await sendDunningEmail();   // unreachable unless the receipt vouches for that claim
 *
 * Defaults are the strict ones: only `supported`, 15-minute freshness, self-tests refused.
 * Widen them explicitly so loosening a gate is always visible in a diff.
 */
export async function requireReceipt(
  receipt: Receipt,
  publicKeyHex: string,
  opts: RequireReceiptOptions,
): Promise<Receipt> {
  const { ok, reason, detail } = await checkReceipt(receipt, publicKeyHex, opts);
  if (!ok) throw new ReceiptRejected(reason as RejectReason, detail, receipt);
  return receipt;
}
