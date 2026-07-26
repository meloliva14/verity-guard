"""Verify a signed verdict receipt WITHOUT calling VerityLayer.

`VerityClient.verify_receipt()` asks our server whether our signature is good. That is a
convenience, not a proof — it is the issuer vouching for itself. This module does the real
thing locally: fetch the public key once, then every receipt you ever hold can be checked
with no network call and no trust in us.

Requires `cryptography`, which is NOT a hard dependency of this package (most users only want
the guard). Install with:

    pip install "verity-guard[offline]"

The canonicalization is specified in RECEIPTS.md. A standalone copy of this logic that imports
nothing from this package ships as verify_receipt.py in the repo root, for anyone who would
rather not trust our library either. That is a reasonable position and we shipped for it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional, Tuple


class OfflineVerifyUnavailable(RuntimeError):
    """Raised when `cryptography` is not installed. Never returned as 'invalid' -- a missing
    verifier is not a failed signature, and conflating the two is the fail-open this whole
    package exists to avoid."""


def canonical_bytes(receipt: dict) -> bytes:
    """The exact bytes that were signed: sorted keys, no whitespace, `signature` excluded.

    Integral numbers render WITHOUT a decimal point (`1`, not `1.0`) -- a deliberate
    divergence from RFC 8785, documented in RECEIPTS.md rather than left as a trap.
    """
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def derive_key_id(public_key_hex: str) -> str:
    """key_id is derived from the key, so you can confirm you hold the right one yourself."""
    return "ed25519:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


def verify_receipt_offline(receipt: Any, public_key_hex: str,
                           claim: Optional[str] = None,
                           context: Optional[str] = None) -> Tuple[bool, str]:
    """Return (ok, reason). No network. No trust in the issuer.

    Pass `claim` to also check BINDING. A valid signature proves this content was signed --
    it says nothing about whether the receipt vouches for the action you are about to take.
    Without `claim`, that question is simply not asked, and the reason string says so.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e:  # pragma: no cover - depends on the install
        raise OfflineVerifyUnavailable(
            'offline verification needs `cryptography` -- pip install "verity-guard[offline]"'
        ) from e

    if not isinstance(receipt, dict):
        return False, f"not a receipt: got {type(receipt).__name__}"
    for field in ("signature", "key_id"):
        if not isinstance(receipt.get(field), str):
            return False, f"not a receipt: missing {field}"

    derived = derive_key_id(public_key_hex)
    if receipt["key_id"] != derived:
        # Deliberately does NOT fetch a key that works. That would restore the trust this
        # function exists to remove.
        return False, (f"wrong key: receipt was signed by {receipt['key_id']}, the key "
                       f"supplied is {derived}")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(receipt["signature"]), canonical_bytes(receipt))
    except InvalidSignature:
        return False, "SIGNATURE INVALID -- this content is not what was signed"
    except Exception as e:  # malformed hex, wrong key length
        return False, f"could not verify: {type(e).__name__}: {e}"

    if claim is None:
        return True, ("signature valid -- NOT checked against any claim; pass claim= to "
                      "confirm this receipt vouches for what you are about to act on")

    if hashlib.sha256(claim.encode("utf-8")).hexdigest() != receipt.get("claim_sha256"):
        return False, ("SIGNATURE VALID BUT FOR A DIFFERENT CLAIM -- this receipt does not "
                       "vouch for the claim supplied")
    if context is not None:
        if hashlib.sha256(context.encode("utf-8")).hexdigest() != receipt.get("context_sha256"):
            return False, ("signature valid and claim matches, but the CONTEXT differs from "
                           "the one this receipt was issued over")
    if receipt.get("test") is True:
        return True, ("signature valid and bound -- but this is a SELF-TEST receipt, not a "
                      "paid verdict")
    return True, "signature valid and bound to the claim supplied"
