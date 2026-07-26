#!/usr/bin/env python3
"""Verify a VerityLayer signed receipt OFFLINE. Imports nothing from VerityLayer.

    python verify_receipt.py receipt.json pubkey.json
    python verify_receipt.py receipt.json pubkey.json --claim "the claim it should vouch for"

Needs only the standard library plus `cryptography` (pip install cryptography).

The point of this file is that you should not have to trust us to check our own work. It
makes no network call, and it deliberately shares no code with the service that issues the
receipts - if the two agreed because they were the same code, that would prove nothing.

Get the two inputs once:
    curl -o receipt.json https://api.veritylayer.dev/receipt/selftest
    curl -o pubkey.json  https://api.veritylayer.dev/.well-known/verity-pubkey.json

Full spec: RECEIPTS.md in this repo.
Exit code 0 = signature valid (and bound, if --claim was given). Non-zero otherwise.
"""
from __future__ import annotations

import hashlib
import json
import sys


def canonical_bytes(receipt: dict) -> bytes:
    """The exact bytes that were signed.

    Sorted keys, no whitespace, `signature` excluded, UTF-8, non-ASCII left literal.

    NOTE: integral numbers serialize WITHOUT a decimal point - `confidence: 1` is `1`, not
    `1.0`. A language that renders every number as a float will produce different bytes and
    fail on a perfectly valid receipt. This is a deliberate divergence from RFC 8785 and is
    documented rather than left as a trap.
    """
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def derive_key_id(public_key_hex: str) -> str:
    """key_id is derived from the key, so you can confirm you hold the right one yourself."""
    return "ed25519:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


def verify(receipt: dict, public_key_hex: str) -> tuple[bool, str]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, "this verifier needs `cryptography` - pip install cryptography"

    for field in ("signature", "key_id"):
        if not isinstance(receipt.get(field), str):
            return False, f"not a receipt: missing {field}"

    derived = derive_key_id(public_key_hex)
    if receipt["key_id"] != derived:
        # Do NOT 'helpfully' fetch a different key here. Falling back to asking the issuer
        # for a key that works is exactly the trust this file exists to avoid.
        return False, (f"wrong key: receipt was signed by {receipt['key_id']}, the key you "
                       f"supplied is {derived}")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(receipt["signature"]), canonical_bytes(receipt))
    except InvalidSignature:
        return False, "SIGNATURE INVALID - this content is not what was signed"
    except Exception as e:  # malformed hex, wrong key length, etc.
        return False, f"could not verify: {type(e).__name__}: {e}"
    return True, "signature valid"


def check_binding(receipt: dict, claim: str) -> tuple[bool, str]:
    """A valid signature says WE SIGNED THIS. It does not say this vouches for YOUR claim."""
    want = hashlib.sha256(claim.encode("utf-8")).hexdigest()
    got = receipt.get("claim_sha256")
    if want == got:
        return True, "this receipt was issued for the claim you supplied"
    return False, ("SIGNATURE VALID BUT FOR A DIFFERENT CLAIM - it does not vouch for the "
                   "claim you supplied")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    # /receipt/selftest wraps the receipt; accept either shape.
    return d.get("sample_receipt") or d.get("receipt") or d


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    receipt = _load(argv[0])
    with open(argv[1], encoding="utf-8") as f:
        pub_hex = json.load(f)["public_key_hex"]

    ok, why = verify(receipt, pub_hex)
    print(f"signature : {'VALID' if ok else 'INVALID'} - {why}")
    if not ok:
        return 1

    if receipt.get("test") is True:
        print("warning   : this is a SELF-TEST receipt, not a paid verdict - it proves the "
              "signing chain works and nothing about any real claim")

    print(f"verdict   : {receipt.get('verdict')}  (confidence {receipt.get('confidence')})")
    print(f"endpoint  : {receipt.get('endpoint')}   issued {receipt.get('issued_at')}")

    if "--claim" in argv:
        claim = argv[argv.index("--claim") + 1]
        bound, why_b = check_binding(receipt, claim)
        print(f"binding   : {'BOUND' if bound else 'NOT BOUND'} - {why_b}")
        if not bound:
            return 1
    else:
        print("binding   : not checked - pass --claim \"...\" to confirm this receipt "
              "vouches for the claim you actually care about")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
