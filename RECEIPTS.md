# VerityLayer signed receipts — verification spec

Every paid VerityLayer verdict ships an Ed25519-signed receipt. This document is the
normative description of how to verify one **offline**, with no call to VerityLayer at
verification time and no trust in us.

That property is the point. A verdict you have to phone the issuer to check is a verdict you
are trusting the issuer for. This spec exists so you don't have to.

---

## What a receipt looks like

```json
{
  "receipt_id": "cc3282d8-a77e-4b11-9888-a825bb6bb48a",
  "issued_at": "2026-07-26T16:40:41+00:00",
  "service": "VerityLayer",
  "endpoint": "/verify",
  "model_tier": "grounded",
  "claim_sha256": "16825a7bea0466eabb696b2ab2d4d1a7179521640c7d4a5fb90ba02ef282dd20",
  "context_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "verdict": "supported",
  "confidence": 0.97,
  "output_sha256": "10e644febf5cc560164d10d9190ddf38d57c4dc8ca0ec95edc1421f2dae45197",
  "key_id": "ed25519:ea7c47db794239a8",
  "signature": "…hex…"
}
```

`test: true` appears on receipts from `GET /receipt/selftest`. Those are genuinely signed but
are **not** verdicts about anything — treat them as proof the signing chain works, nothing more.

---

## The canonical signing input

Take the receipt object, **remove the `signature` field**, and serialize:

- keys **sorted** lexicographically
- separators `","` and `":"` — no whitespace anywhere
- `ensure_ascii = false` — non-ASCII characters are emitted literally, not `\uXXXX`-escaped
- encode the result as **UTF-8**

Sign/verify **Ed25519** over exactly those bytes.

In Python that is one expression:

```python
json.dumps({k: v for k, v in receipt.items() if k != "signature"},
           sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

### Two things that will bite you

**1. Integral numbers are emitted without a decimal point.** `confidence: 1` is serialized as
`1`, not `1.0`. If your language renders every number as a float you will produce `1.0`, get
different bytes, and the signature will fail on a receipt that is perfectly valid. This is a
deliberate divergence from RFC 8785 (JCS), which mandates the ECMAScript number rendering, and
it is called out here rather than left for you to discover.

**2. Key ordering is by Unicode code point, not UTF-16 code unit.** For every field name in use
today the two are identical, so this only matters if a future field name contains characters
outside the BMP. Also a divergence from JCS.

We are naming both divergences rather than claiming JCS compliance we don't have. If your
verifier follows this document you will get the right bytes.

---

## The key

Fetch it once, then verify forever offline:

```
https://api.veritylayer.dev/.well-known/verity-pubkey.json
https://api.veritylayer.dev/.well-known/did.json          (same key, as did:web)
```

```json
{ "key_id": "ed25519:ea7c47db794239a8",
  "algorithm": "Ed25519",
  "public_key_hex": "d7e3b333958d3e01bf479d2e4d2f6e9306ee5547126c588e686b5ca8b95f0943",
  "created": "2026-07-02" }
```

**`key_id` is derived from the key, so you can confirm you have the right one without asking us:**

```
key_id == "ed25519:" + sha256(raw_32_public_key_bytes).hexdigest()[:16]
```

Check that the receipt's `key_id` matches the one you derive from the key you hold. If it
doesn't, you are holding the wrong key — stop, don't "fall back" to fetching a new one from us,
because at that point you're trusting the issuer again.

---

## Verifying

A complete third-party verifier is included in this repo, importing nothing from VerityLayer:

```bash
python verify_receipt.py receipt.json pubkey.json     # stdlib + `cryptography`
node   verify_receipt.js receipt.json pubkey.json     # zero dependencies
```

Or in-process, if you already use this package:

```python
from verity_guard import verify_receipt_offline
ok, why = verify_receipt_offline(receipt, public_key_hex)
```

---

## What a valid signature does and does not tell you

It tells you: **this exact receipt content was signed by the holder of that key, and nothing in
it has been altered since.** Change one character and verification fails.

It does **not** tell you that the receipt vouches for the thing you are about to do. The receipt
commits to a claim via `claim_sha256`, but a signature check alone never compares that to *your*
claim. To close that gap, recompute it yourself:

```python
claim_sha256 == hashlib.sha256(claim.encode("utf-8")).hexdigest()
```

and compare. `POST /receipt/verify` will also do it for you if you send
`{"receipt": {...}, "claim": "...", "context": "..."}` — it returns `bound: true/false`
alongside `valid`. Sending a bare receipt returns `bound: null`, because signature validity is
all that was checked.

A signed receipt over *some* claim is not authorization for *your* action. Check the binding.

---

## Rotation

Receipts carry the `key_id` that signed them, so a rotated key does not invalidate old receipts —
you verify each against the key named in it. Keep any key you have fetched; we will not remove
`/.well-known/verity-pubkey.json`.
