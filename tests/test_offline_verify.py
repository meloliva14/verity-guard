"""Offline receipt verification -- the claim the whole product rests on.

"Every verdict is Ed25519-signed and independently re-verifiable offline against a published
key, so you never have to trust the issuer." That sentence is only true if someone can
actually do it without calling us. Until now the only shipped path was POST /receipt/verify,
which is the issuer vouching for itself.

These tests use a locally-generated key and a hand-built receipt, so they never depend on the
network or on production being up.
"""
from __future__ import annotations

import json

import pytest

from verity_guard import verify_receipt_offline
from verity_guard.offline import canonical_bytes, derive_key_id

crypto = pytest.importorskip("cryptography", reason="offline extra not installed")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
import hashlib  # noqa: E402


def _signed(claim="the sky is blue", **over):
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    receipt = {
        "receipt_id": "r-1",
        "issued_at": "2026-07-26T00:00:00+00:00",
        "service": "VerityLayer",
        "endpoint": "/verify",
        "model_tier": "grounded",
        "claim_sha256": hashlib.sha256(claim.encode()).hexdigest(),
        "context_sha256": hashlib.sha256(b"").hexdigest(),
        "verdict": "supported",
        "confidence": 1,          # integral on purpose: 1, never 1.0
        "key_id": derive_key_id(pub_hex),
        **over,
    }
    receipt["signature"] = priv.sign(canonical_bytes(receipt)).hex()
    return receipt, pub_hex, claim


def test_a_genuine_receipt_verifies_with_no_network():
    receipt, pub, _ = _signed()
    ok, why = verify_receipt_offline(receipt, pub)
    assert ok, why


def test_tampering_with_the_verdict_breaks_the_signature():
    receipt, pub, _ = _signed()
    receipt["verdict"] = "refuted"
    ok, why = verify_receipt_offline(receipt, pub)
    assert not ok and "INVALID" in why


def test_integral_confidence_is_not_rendered_as_a_float():
    """The documented RFC 8785 divergence. If a verifier emits 1.0 where the signer emitted 1,
    it produces different bytes and rejects a perfectly valid receipt. Pin the behaviour."""
    receipt, pub, _ = _signed()
    assert b'"confidence":1,' in canonical_bytes(receipt), "integral rendered as a float"
    receipt["confidence"] = float(receipt["confidence"])
    ok, _ = verify_receipt_offline(receipt, pub)
    assert not ok, "1 and 1.0 must not both verify -- the canonicalization would be ambiguous"


def test_the_signature_field_is_excluded_from_its_own_input():
    receipt, _, _ = _signed()
    assert b"signature" not in canonical_bytes(receipt)


def test_key_id_is_derivable_so_you_can_confirm_you_hold_the_right_key():
    receipt, pub, _ = _signed()
    assert receipt["key_id"] == derive_key_id(pub)


def test_a_receipt_signed_by_a_different_key_is_refused():
    receipt, _, _ = _signed()
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    ok, why = verify_receipt_offline(receipt, other)
    assert not ok and "wrong key" in why


def test_binding_is_not_checked_unless_you_ask_and_the_reason_says_so():
    receipt, pub, _ = _signed()
    ok, why = verify_receipt_offline(receipt, pub)
    assert ok and "NOT checked against any claim" in why


def test_a_valid_signature_over_a_DIFFERENT_claim_is_not_binding():
    """The whole point. A signature proves we signed something; it never proves the receipt
    vouches for the action you are about to take."""
    receipt, pub, _ = _signed(claim="the sky is blue")
    ok, why = verify_receipt_offline(receipt, pub, claim="wire $40,000 to a stranger")
    assert not ok and "DIFFERENT CLAIM" in why


def test_binding_passes_for_the_claim_it_was_issued_over():
    receipt, pub, claim = _signed()
    ok, why = verify_receipt_offline(receipt, pub, claim=claim)
    assert ok, why


def test_a_selftest_receipt_is_flagged_even_when_valid_and_bound():
    receipt, pub, claim = _signed(test=True)
    ok, why = verify_receipt_offline(receipt, pub, claim=claim)
    assert ok and "SELF-TEST" in why, "a self-test receipt must never read as a paid verdict"
