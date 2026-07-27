/**
 * Receipt verification and authorization, in JS.
 *
 * Two things are under test and they are not the same thing:
 *   1. CONFORMANCE  -- the JS canonicalization produces the identical bytes Python signs.
 *                      A second implementation that quietly disagrees is worse than none.
 *   2. AUTHORIZATION -- a genuine signature still does not permit an arbitrary action.
 *
 * Every "must be refused" case below signs a REAL receipt with a REAL key and asserts the
 * refusal anyway. Nothing here is forged except where stated.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  AFFIRMATIVE,
  ReceiptRejected,
  canonicalBytes,
  checkReceipt,
  deriveKeyId,
  requireReceipt,
  verifyReceiptOffline,
} from "../dist/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(
  readFileSync(join(HERE, "fixtures", "python_signed_receipt.json"), "utf8"),
);

const CLAIM = "Invoice 4417 is unpaid";
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

let KEY, PUB;
async function keys() {
  if (!KEY) {
    KEY = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    PUB = hex(await crypto.subtle.exportKey("raw", KEY.publicKey));
  }
  return { KEY, PUB };
}

/** A GENUINELY signed receipt. Tests that reject one are rejecting a real signature. */
async function sign({ claim = CLAIM, verdict = "supported", ageSeconds = 0, ...over } = {}) {
  const { KEY, PUB } = await keys();
  const issued = new Date(Date.now() - ageSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "+00:00");
  const r = {
    receipt_id: over.receipt_id ?? `r-${Math.random()}`,
    issued_at: over.issued_at ?? issued,
    service: "VerityLayer",
    endpoint: "/verify",
    claim_sha256: hex(await crypto.subtle.digest("SHA-256", enc.encode(claim))),
    context_sha256: hex(await crypto.subtle.digest("SHA-256", enc.encode(""))),
    verdict,
    confidence: 1,
    key_id: await deriveKeyId(PUB),
    ...over,
  };
  const sig = await crypto.subtle.sign("Ed25519", KEY.privateKey, canonicalBytes(r));
  r.signature = hex(sig);
  return r;
}

// --- 1. CONFORMANCE with the Python signer ------------------------------------------------

test("CONFORMANCE: a receipt signed by PYTHON verifies in JS", async () => {
  const { ok, reason } = await verifyReceiptOffline(
    FIXTURE.receipt,
    FIXTURE.public_key_hex,
    FIXTURE.claim,
    FIXTURE.context,
  );
  assert.ok(ok, `JS rejected a Python-signed receipt: ${reason}`);
});

test("CONFORMANCE: JS canonical bytes match Python's byte length exactly", () => {
  // Includes non-ASCII and an astral-plane character, so any accidental \\uXXXX escaping or
  // UTF-16 mangling changes this number.
  assert.equal(canonicalBytes(FIXTURE.receipt).length, FIXTURE.canonical_utf8_len);
});

test("CONFORMANCE: an integral confidence renders as 1, never 1.0", () => {
  const s = new TextDecoder().decode(canonicalBytes(FIXTURE.receipt));
  assert.ok(s.includes('"confidence":1,'), "integral number rendered as a float");
  assert.ok(!s.includes('"confidence":1.0'), "1.0 would produce different bytes than Python signed");
});

test("CONFORMANCE: the signature field is excluded from its own input", () => {
  assert.ok(!new TextDecoder().decode(canonicalBytes(FIXTURE.receipt)).includes("signature"));
});

test("CONFORMANCE: keys are sorted, so field order in the object cannot matter", async () => {
  const r = FIXTURE.receipt;
  const shuffled = Object.fromEntries(Object.entries(r).reverse());
  assert.deepEqual(canonicalBytes(shuffled), canonicalBytes(r));
});

test("CONFORMANCE: tampering with the Python fixture is detected in JS", async () => {
  const bad = { ...FIXTURE.receipt, verdict: "unsupported" };
  const { ok } = await verifyReceiptOffline(bad, FIXTURE.public_key_hex, FIXTURE.claim);
  assert.equal(ok, false);
});

// --- 2. the six ways a valid signature is still not permission -----------------------------

test("a genuine, fresh, affirmative, bound receipt authorizes", async () => {
  const { PUB } = await keys();
  assert.ok(await requireReceipt(await sign(), PUB, { claim: CLAIM }));
});

test("a real receipt about a DIFFERENT claim is refused", async () => {
  const { PUB } = await keys();
  const r = await sign({ claim: "The sky is blue" });
  await assert.rejects(
    () => requireReceipt(r, PUB, { claim: "Wire $40,000 to account 9931" }),
    (e) => e instanceof ReceiptRejected && e.reason === "not_bound",
  );
});

test("an unsupported verdict is refused", async () => {
  const { PUB } = await keys();
  const { ok, reason, detail } = await checkReceipt(await sign({ verdict: "unsupported" }), PUB, { claim: CLAIM });
  assert.equal(ok, false);
  assert.equal(reason, "verdict_not_accepted");
  assert.match(detail, /did NOT hold up/);
});

test("uncertain is an abstention, not a yes", async () => {
  const { PUB } = await keys();
  const { ok, reason, detail } = await checkReceipt(await sign({ verdict: "uncertain" }), PUB, { claim: CLAIM });
  assert.equal(ok, false);
  assert.equal(reason, "verdict_not_accepted");
  assert.match(detail, /abstention/);
});

test("a stale receipt is refused", async () => {
  const { PUB } = await keys();
  const { ok, reason } = await checkReceipt(await sign({ ageSeconds: 6 * 7 * 86400 }), PUB, { claim: CLAIM });
  assert.equal(ok, false);
  assert.equal(reason, "stale");
});

test("a self-test receipt never gates a real action", async () => {
  const { PUB } = await keys();
  const { ok, reason } = await checkReceipt(await sign({ test: true }), PUB, { claim: CLAIM });
  assert.equal(ok, false);
  assert.equal(reason, "test_receipt");
});

test("a replayed receipt is refused on second use", async () => {
  const { PUB } = await keys();
  const r = await sign();
  const seen = new Set();
  assert.ok(await requireReceipt(r, PUB, { claim: CLAIM, seen }));
  await assert.rejects(
    () => requireReceipt(r, PUB, { claim: CLAIM, seen }),
    (e) => e.reason === "replayed",
  );
});

// --- 3. fail-closed shape ------------------------------------------------------------------

test("a rejected receipt is NOT burned from the replay set", async () => {
  const { PUB } = await keys();
  const r = await sign({ ageSeconds: 99999 });
  const seen = new Set();
  const { ok, reason } = await checkReceipt(r, PUB, { claim: CLAIM, seen });
  assert.equal(ok, false);
  assert.equal(reason, "stale");
  assert.equal(seen.size, 0, "a rejected receipt must not be recorded as spent");
  assert.ok(await requireReceipt(r, PUB, { claim: CLAIM, maxAgeSeconds: null, seen }));
});

test("tampering with the verdict fails on the SIGNATURE, before any policy check", async () => {
  const { PUB } = await keys();
  const r = await sign({ verdict: "unsupported" });
  r.verdict = "supported";
  const { ok, reason } = await checkReceipt(r, PUB, { claim: CLAIM });
  assert.equal(ok, false);
  assert.equal(reason, "invalid");
});

test("an unrecognized verdict cannot sneak through the allowlist", async () => {
  const { PUB } = await keys();
  const r = await sign({ verdict: "definitely_fine_trust_me" });
  const { ok, reason } = await checkReceipt(r, PUB, { claim: CLAIM });
  assert.equal(ok, false, "an unrecognized verdict must never authorize");
  assert.equal(reason, "verdict_not_accepted");
});

test("an empty accept list refuses rather than permits", async () => {
  const { PUB } = await keys();
  const { ok, reason } = await checkReceipt(await sign(), PUB, { claim: CLAIM, accept: [] });
  assert.equal(ok, false);
  assert.equal(reason, "no_accepted_verdict");
});

test("allowlisting a verdict the service never returns is a loud error", async () => {
  const { PUB } = await keys();
  const { ok, reason, detail } = await checkReceipt(await sign(), PUB, {
    claim: CLAIM,
    accept: ["definitely_true"],
  });
  assert.equal(ok, false);
  assert.equal(reason, "unknown_accepted_verdict");
  assert.match(detail, /never returns/);
});

test("freshness required but timestamp unreadable is refused", async () => {
  const { PUB } = await keys();
  const { ok, reason } = await checkReceipt(await sign({ issued_at: "not a date" }), PUB, { claim: CLAIM });
  assert.equal(ok, false);
  assert.equal(reason, "no_timestamp");
});

test("a future-dated receipt beyond clock skew is refused", async () => {
  const { PUB } = await keys();
  const { ok, reason } = await checkReceipt(await sign({ ageSeconds: -9999 }), PUB, { claim: CLAIM });
  assert.equal(ok, false);
  assert.equal(reason, "future_dated");
});

test("small clock skew is tolerated", async () => {
  const { PUB } = await keys();
  const { ok, detail } = await checkReceipt(await sign({ ageSeconds: -30 }), PUB, { claim: CLAIM });
  assert.ok(ok, detail);
});

test("single-use requires a receipt_id rather than silently not deduping", async () => {
  const { KEY, PUB } = await keys();
  const r = await sign();
  delete r.receipt_id;
  delete r.signature;
  r.signature = hex(await crypto.subtle.sign("Ed25519", KEY.privateKey, canonicalBytes(r)));
  const { ok, reason } = await checkReceipt(r, PUB, { claim: CLAIM, seen: new Set() });
  assert.equal(ok, false);
  assert.equal(reason, "no_receipt_id");
});

test("verdict comparison is case- and whitespace-insensitive", async () => {
  const { PUB } = await keys();
  const { ok, detail } = await checkReceipt(await sign({ verdict: "  SUPPORTED  " }), PUB, { claim: CLAIM });
  assert.ok(ok, detail);
});

test("a receipt signed by another key is refused", async () => {
  const other = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const otherPub = hex(await crypto.subtle.exportKey("raw", other.publicKey));
  const { ok, reason } = await checkReceipt(await sign(), otherPub, { claim: CLAIM });
  assert.equal(ok, false);
  assert.equal(reason, "invalid");
});

test("context mismatch is reported as not_bound", async () => {
  const { PUB } = await keys();
  const { ok, reason } = await checkReceipt(await sign(), PUB, { claim: CLAIM, context: "different" });
  assert.equal(ok, false);
  assert.equal(reason, "not_bound");
});

test("a missing claim THROWS rather than silently skipping the binding check", async () => {
  const { PUB } = await keys();
  const r = await sign();
  await assert.rejects(
    () => requireReceipt(r, PUB, {}),
    (e) => e instanceof TypeError,
  );
});

test("verifyReceiptOffline without a claim says the binding was NOT checked", async () => {
  const { PUB } = await keys();
  const { ok, reason } = await verifyReceiptOffline(await sign(), PUB);
  assert.ok(ok);
  assert.match(reason, /NOT checked against any claim/);
});

test("the rejection carries a machine-readable reason and the receipt", async () => {
  const { PUB } = await keys();
  const r = await sign({ verdict: "unsupported" });
  await assert.rejects(
    () => requireReceipt(r, PUB, { claim: CLAIM }),
    (e) => e.reason === "verdict_not_accepted" && e.receipt !== undefined,
  );
});

test("opting out of freshness is explicit and works", async () => {
  const { PUB } = await keys();
  assert.ok(await requireReceipt(await sign({ ageSeconds: 1e7 }), PUB, { claim: CLAIM, maxAgeSeconds: null }));
});

test("AFFIRMATIVE does not contain uncertain", () => {
  assert.ok(!AFFIRMATIVE.includes("uncertain"));
  assert.ok(!AFFIRMATIVE.includes("unsupported"));
});

test("the ./receipt subpath export works without importing the HTTP client", async () => {
  const mod = await import("../dist/receipt.js");
  assert.equal(typeof mod.requireReceipt, "function");
  assert.equal(typeof mod.verifyReceiptOffline, "function");
});
