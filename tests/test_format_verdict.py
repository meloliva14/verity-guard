"""format_verdict tests — the string that goes straight to a model.

Two guarantees, both previously broken:
  1. It must never RAISE. It exploded on `res.payment_required` whenever a sync tool path
     (LangChain / CrewAI) was handed an async client and got an un-awaited coroutine.
  2. It must never READ LIKE AN ALLOW when no verdict was produced. A model reading
     "payment_required — settle and retry" could plausibly just... carry on.
"""
from __future__ import annotations

import pytest

from verity_guard import VerityResult, format_verdict

ALLOW = VerityResult({"decision": "allow", "risk": 0.05, "reasons": ["known payee"]})
BLOCK = VerityResult({"decision": "block", "risk": 0.99, "safer_alternative": "ask a human",
                      "reasons": ["new payee", "scraped source"]})
UNREACHABLE = VerityResult({"error": "verity_unreachable: timeout"})
UNPAID = VerityResult({"payment_required": True, "price": "$0.02"})


async def _coro():
    return ALLOW


def test_real_verdicts_render_normally():
    assert "decision=allow" in format_verdict(ALLOW)
    out = format_verdict(BLOCK)
    assert "decision=block" in out and "safer_alternative" in out


NO_DECISION = VerityResult({"risk": 0.1})
GARBLED = VerityResult({"decision": "banana"})


@pytest.mark.parametrize("bad", [UNREACHABLE, UNPAID, NO_DECISION, GARBLED])
def test_non_verdicts_say_NOT_CHECKED_and_warn_against_allow(bad):
    out = format_verdict(bad)
    assert "NOT CHECKED" in out
    assert "do not treat this as an allow" in out.lower()


def test_decisionless_200_is_not_rendered_as_a_cheerful_verdict():
    """It used to render '[verity] decision=None | risk=0.1' with no warning — and on the
    advisory tool paths this string is the ONLY signal the model gets."""
    out = format_verdict(VerityResult({"risk": 0.1}))
    assert "decision=None" not in out
    assert "NOT CHECKED" in out


def test_unawaited_coroutine_does_not_raise_and_does_not_read_as_allow():
    """The exact LangChain/CrewAI sync-path-with-async-client bug: this used to raise
    AttributeError on `.payment_required`."""
    c = _coro()
    try:
        out = format_verdict(c)  # must not raise
    finally:
        c.close()
    assert "NOT CHECKED" in out and "coroutine" in out
    assert "do not treat this as an allow" in out.lower()


def test_arbitrary_junk_does_not_raise():
    for junk in ({"decision": "allow"}, None, 42, "allow"):
        out = format_verdict(junk)
        assert "NOT CHECKED" in out, f"junk {junk!r} rendered as {out!r}"
