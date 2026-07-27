"""Every way a VALID signature can still fail to authorize an action.

This file is the point of the feature. Each test below signs a genuine receipt with a real key
-- nothing here is forged except where stated -- and then asserts the gate refuses it anyway.
An agent that says "I checked" should not be able to be wrong about that, and every case here
is a way it could have been.
"""
from __future__ import annotations

import hashlib
import time

import pytest

from verity_guard import (
    ReceiptRejected,
    check_receipt,
    require_receipt,
)
from verity_guard.offline import canonical_bytes, derive_key_id

pytest.importorskip("cryptography", reason="offline extra not installed")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

CLAIM = "Invoice 4417 is unpaid"
PRIV = Ed25519PrivateKey.generate()
PUB = PRIV.public_key().public_bytes_raw().hex()


def sign(claim=CLAIM, verdict="supported", age_seconds=0, **over):
    """A GENUINELY signed receipt. Tests that reject one are rejecting a real signature."""
    issued = time.time() - age_seconds
    r = {
        "receipt_id": over.pop("receipt_id", f"r-{issued}-{verdict}"),
        "issued_at": over.pop(
            "issued_at",
            time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(issued)),
        ),
        "service": "VerityLayer",
        "endpoint": "/verify",
        "claim_sha256": hashlib.sha256(claim.encode()).hexdigest(),
        "context_sha256": hashlib.sha256(b"").hexdigest(),
        "verdict": verdict,
        "confidence": 1,
        "key_id": derive_key_id(PUB),
        **over,
    }
    r["signature"] = PRIV.sign(canonical_bytes(r)).hex()
    return r


# --- the happy path, so the refusals below mean something --------------------------------

def test_a_genuine_fresh_affirmative_bound_receipt_authorizes():
    assert require_receipt(sign(), PUB, claim=CLAIM) is not None


def test_check_receipt_agrees_and_reports_ok():
    ok, reason, _ = check_receipt(sign(), PUB, claim=CLAIM)
    assert ok and reason == "ok"


# --- the six ways a valid signature is still not permission -------------------------------

def test_a_real_receipt_about_a_DIFFERENT_claim_is_refused():
    """The headline case. Perfect signature, wrong subject."""
    r = sign(claim="The sky is blue")
    with pytest.raises(ReceiptRejected) as e:
        require_receipt(r, PUB, claim="Wire $40,000 to account 9931")
    assert e.value.reason == "not_bound"


def test_an_unsupported_verdict_is_refused():
    """We checked, and it was false. That is not permission to act."""
    ok, reason, detail = check_receipt(sign(verdict="unsupported"), PUB, claim=CLAIM)
    assert not ok and reason == "verdict_not_accepted"
    assert "did NOT hold up" in detail


def test_uncertain_is_an_abstention_not_a_yes():
    """The engine returns `uncertain` when it declines to guess. Treating that as permission
    would invert the one property the product sells."""
    ok, reason, detail = check_receipt(sign(verdict="uncertain"), PUB, claim=CLAIM)
    assert not ok and reason == "verdict_not_accepted"
    assert "abstention" in detail


def test_a_stale_receipt_is_refused():
    """True six weeks ago. The world is allowed to move."""
    ok, reason, _ = check_receipt(sign(age_seconds=6 * 7 * 86400), PUB, claim=CLAIM)
    assert not ok and reason == "stale"


def test_a_selftest_receipt_never_gates_a_real_action():
    ok, reason, _ = check_receipt(sign(test=True), PUB, claim=CLAIM)
    assert not ok and reason == "test_receipt"


def test_a_replayed_receipt_is_refused_on_second_use():
    """One verdict authorizes one action."""
    r, seen = sign(), set()
    assert require_receipt(r, PUB, claim=CLAIM, seen=seen)
    with pytest.raises(ReceiptRejected) as e:
        require_receipt(r, PUB, claim=CLAIM, seen=seen)
    assert e.value.reason == "replayed"


# --- fail-closed shape --------------------------------------------------------------------

def test_a_rejected_receipt_is_NOT_burned_from_the_replay_set():
    """A receipt refused for being stale must remain usable if the caller relaxes the limit.
    Burning it on the failure path would let a rejection quietly destroy a valid credential."""
    r, seen = sign(age_seconds=99999), set()
    ok, reason, _ = check_receipt(r, PUB, claim=CLAIM, seen=seen)
    assert not ok and reason == "stale"
    assert seen == set(), "a rejected receipt must not be recorded as spent"
    assert require_receipt(r, PUB, claim=CLAIM, max_age_seconds=None, seen=seen)


def test_tampering_with_the_verdict_is_caught_as_invalid_not_merely_unaccepted():
    """Flipping unsupported->supported must fail on the SIGNATURE, before any policy check."""
    r = sign(verdict="unsupported")
    r["verdict"] = "supported"
    ok, reason, _ = check_receipt(r, PUB, claim=CLAIM)
    assert not ok and reason == "invalid"


def test_an_unknown_verdict_cannot_sneak_through_an_allowlist():
    """Allowlist semantics: a value nobody anticipated must be refused, not tolerated.

    The receipt is GENUINELY signed with that verdict, so the signature check passes and the
    refusal has to come from the allowlist itself -- which is the property under test.
    """
    r = sign(verdict="definitely_fine_trust_me")
    ok, reason, detail = check_receipt(r, PUB, claim=CLAIM, accept=("supported",))
    assert ok is False, "an unrecognized verdict must never authorize"
    assert reason == "verdict_not_accepted", detail


def test_an_empty_accept_list_refuses_rather_than_permits():
    ok, reason, _ = check_receipt(sign(), PUB, claim=CLAIM, accept=())
    assert not ok and reason == "no_accepted_verdict"


def test_allowlisting_a_verdict_the_service_never_returns_is_an_error_not_a_silent_no_match():
    ok, reason, detail = check_receipt(sign(), PUB, claim=CLAIM, accept=("definitely_true",))
    assert not ok and reason == "unknown_accepted_verdict"
    assert "never returns" in detail


def test_freshness_required_but_timestamp_unreadable_is_refused():
    ok, reason, _ = check_receipt(sign(issued_at="not a date"), PUB, claim=CLAIM)
    assert not ok and reason == "no_timestamp"


def test_a_future_dated_receipt_beyond_clock_skew_is_refused():
    ok, reason, _ = check_receipt(sign(age_seconds=-9999), PUB, claim=CLAIM)
    assert not ok and reason == "future_dated"


def test_small_clock_skew_is_tolerated():
    """Two machines disagreeing by a few seconds must not break a legitimate gate."""
    ok, _, detail = check_receipt(sign(age_seconds=-30), PUB, claim=CLAIM)
    assert ok, detail


def test_single_use_requires_a_receipt_id_rather_than_silently_not_deduping():
    r = sign()
    del r["receipt_id"]
    r["signature"] = PRIV.sign(canonical_bytes(r)).hex()   # re-sign: still genuine
    ok, reason, _ = check_receipt(r, PUB, claim=CLAIM, seen=set())
    assert not ok and reason == "no_receipt_id"


def test_verdict_comparison_is_case_and_whitespace_insensitive():
    """'SUPPORTED ' must not slip past an allowlist check for 'supported'."""
    r = sign(verdict="  SUPPORTED  ")
    ok, _, detail = check_receipt(r, PUB, claim=CLAIM)
    assert ok, detail


def test_a_receipt_signed_by_another_key_is_refused():
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    ok, reason, _ = check_receipt(sign(), other, claim=CLAIM)
    assert not ok and reason == "invalid"


def test_context_mismatch_is_reported_as_not_bound():
    ok, reason, _ = check_receipt(sign(), PUB, claim=CLAIM, context="different context")
    assert not ok and reason == "not_bound"


def test_claim_is_required_and_has_no_default():
    """There must be no keyword-free path to a signature-only check. That is the exact
    mistake this module exists to prevent, and a default would make it one omission away."""
    with pytest.raises(TypeError):
        require_receipt(sign(), PUB)          # type: ignore[call-arg]


def test_the_exception_carries_a_machine_readable_reason():
    """So a caller can page a human on a forgery and merely log a stale receipt."""
    with pytest.raises(ReceiptRejected) as e:
        require_receipt(sign(verdict="unsupported"), PUB, claim=CLAIM)
    assert e.value.reason == "verdict_not_accepted"
    assert e.value.receipt is not None


def test_opting_out_of_freshness_is_explicit_and_works():
    assert require_receipt(sign(age_seconds=10**7), PUB, claim=CLAIM, max_age_seconds=None)
