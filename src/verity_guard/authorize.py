"""Gate an action on a receipt that actually authorizes it.

`verify_receipt_offline` answers one question: *is this signature real?* That is necessary and
nowhere near sufficient. A receipt is a signed statement that some verdict was issued about
some claim at some time. On its own it authorizes nothing, and every one of these is a valid
signature that must NOT let an action through:

    - a real receipt about a DIFFERENT claim          ("verified" the wrong thing)
    - a real receipt whose verdict was `unsupported`  (we checked, and it was false)
    - a real receipt whose verdict was `uncertain`    (we checked, and we do not know)
    - a real receipt from six weeks ago               (true then; the world moved)
    - a `test: true` self-test receipt                (proves signing works, vouches for nothing)
    - a real receipt already spent on another action  (replayed)

Checking a signature and calling that "verified" is the failure this module exists to prevent.
An agent that says "I checked" should not be able to be wrong about that, and the gap between
"a receipt exists" and "this receipt permits this" is exactly where that lie lives.

Everything here is fail-closed and ALLOWLIST-shaped: a verdict passes only by being named in
`accept`. Unknown, misspelled, and future verdict values are refused, because a gate that
merely fails to recognize a "bad" value is a gate that opens on anything new.

    from verity_guard import require_receipt, ReceiptRejected

    try:
        require_receipt(receipt, PUBKEY, claim="Invoice 4417 is unpaid")
    except ReceiptRejected as e:
        raise   # do NOT send the dunning email

    send_dunning_email()
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Iterable, MutableSet, Optional, Tuple

from .offline import verify_receipt_offline

# Verdicts that mean "the claim held up". Deliberately tiny. `uncertain` is NOT in it: the
# engine returns `uncertain` precisely when it declines to guess, and treating an abstention
# as permission would invert the one property the whole product sells.
AFFIRMATIVE = ("supported",)

# Every verdict the engine is contracted to return. Used ONLY to give a precise error when a
# caller allowlists something that can never appear -- never to decide whether to permit.
_KNOWN_VERDICTS = frozenset({"supported", "unsupported", "uncertain"})

# A receipt stamped slightly in the future is ordinary clock skew between two machines.
# Further out than this and something is wrong enough to stop for.
_FUTURE_TOLERANCE_SECONDS = 120


class ReceiptRejected(Exception):
    """Raised when a receipt does not authorize the action.

    Carries the machine-readable `reason` code as well as the human sentence, so a caller can
    branch on *why* it failed (log a stale receipt, page a human on a forged one) without
    parsing English.
    """

    def __init__(self, reason: str, detail: str, receipt: Any = None) -> None:
        self.reason = reason
        self.detail = detail
        self.receipt = receipt
        super().__init__(f"receipt does not authorize this action [{reason}]: {detail}")


def _parse_issued_at(value: Any) -> Optional[datetime]:
    """Parse the receipt timestamp, or None if it is absent/unusable.

    Returns None rather than raising so the caller decides what an unreadable timestamp means.
    Under a freshness requirement it must mean rejection.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith(("z", "Z")):  # fromisoformat only learned 'Z' in 3.11
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    # A naive timestamp is assumed UTC -- the engine emits offset-aware, so this is defensive.
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def check_receipt(
    receipt: Any,
    public_key_hex: str,
    *,
    claim: str,
    context: Optional[str] = None,
    accept: Iterable[str] = AFFIRMATIVE,
    max_age_seconds: Optional[float] = 900,
    allow_test: bool = False,
    seen: Optional[MutableSet[str]] = None,
    now: Optional[float] = None,
) -> Tuple[bool, str, str]:
    """Return ``(ok, reason_code, detail)``. Never raises for a *rejection*.

    The non-raising twin of :func:`require_receipt`, for callers that would rather branch than
    catch. It still raises ``OfflineVerifyUnavailable`` if `cryptography` is missing, because
    "I could not check" must never be reported in the same shape as "I checked, and no".

    ``claim`` is REQUIRED and has no default. A receipt is only ever evidence *about something*,
    and a signature-only check is what ``verify_receipt_offline`` is for. Making this optional
    would hand callers a one-keyword path to the exact mistake this module prevents.

    ``accept`` is an allowlist of verdicts. ``max_age_seconds=None`` disables the freshness
    check entirely -- an explicit choice, never the default. ``seen`` is any mutable set you
    control; pass one to make receipts single-use, and its ``receipt_id`` is recorded only on
    success, so a rejected receipt is never burned.
    """
    ok, why = verify_receipt_offline(receipt, public_key_hex, claim=claim, context=context)
    if not ok:
        # Distinguish "not addressed to this action" from "not genuine". Both refuse, but a
        # forged signature deserves a different alarm than an honest mismatch.
        code = "not_bound" if "DIFFERENT CLAIM" in why or "CONTEXT differs" in why else "invalid"
        return False, code, why

    if receipt.get("test") is True and not allow_test:
        return False, "test_receipt", (
            "this is a self-test receipt (test: true). It proves the signing chain works and "
            "vouches for nothing. Pass allow_test=True only in your own tests."
        )

    allowed = {str(v).strip().lower() for v in accept}
    if not allowed:
        return False, "no_accepted_verdict", (
            "accept= is empty, so no verdict could ever pass. Refusing rather than treating an "
            "empty allowlist as permission."
        )
    unknown = allowed - _KNOWN_VERDICTS
    if unknown:
        return False, "unknown_accepted_verdict", (
            f"accept= names verdict(s) the service never returns: {sorted(unknown)}. Valid "
            f"values are {sorted(_KNOWN_VERDICTS)}. Refusing rather than silently never matching."
        )

    verdict = str(receipt.get("verdict", "")).strip().lower()
    if verdict not in allowed:
        return False, "verdict_not_accepted", (
            f"the receipt is genuine and is about your claim, but its verdict is "
            f"{verdict!r}, not one of {sorted(allowed)}. "
            + ("`uncertain` means the engine declined to guess -- that is an abstention, not a yes."
               if verdict == "uncertain" else
               "`unsupported` means the claim did NOT hold up."
               if verdict == "unsupported" else
               "That value is not one this service is contracted to return.")
        )

    if max_age_seconds is not None:
        issued = _parse_issued_at(receipt.get("issued_at"))
        if issued is None:
            return False, "no_timestamp", (
                "freshness was requested but the receipt has no readable issued_at, so its age "
                "cannot be established. Pass max_age_seconds=None to accept it regardless."
            )
        current = time.time() if now is None else now
        age = current - issued.timestamp()
        if age > max_age_seconds:
            return False, "stale", (
                f"the receipt is genuine and affirmative, but it was issued {age:.0f}s ago and "
                f"the limit is {max_age_seconds:.0f}s. A verdict is true as of when it was "
                f"taken; the world is allowed to change underneath it."
            )
        if age < -_FUTURE_TOLERANCE_SECONDS:
            return False, "future_dated", (
                f"the receipt is stamped {-age:.0f}s in the future, beyond the "
                f"{_FUTURE_TOLERANCE_SECONDS}s tolerated for clock skew. Refusing to reason "
                f"about the age of something that has not happened yet."
            )

    if seen is not None:
        rid = receipt.get("receipt_id")
        if not isinstance(rid, str) or not rid:
            return False, "no_receipt_id", (
                "single-use was requested but the receipt has no receipt_id, so replay cannot "
                "be detected."
            )
        if rid in seen:
            return False, "replayed", (
                f"receipt {rid} has already authorized an action. One verdict authorizes one "
                f"action; re-presenting it is how a single check gets claimed for many."
            )
        seen.add(rid)  # only on the success path -- a rejected receipt is never burned

    return True, "ok", "valid, bound to your claim, affirmative, and fresh"


def require_receipt(
    receipt: Any,
    public_key_hex: str,
    *,
    claim: str,
    context: Optional[str] = None,
    accept: Iterable[str] = AFFIRMATIVE,
    max_age_seconds: Optional[float] = 900,
    allow_test: bool = False,
    seen: Optional[MutableSet[str]] = None,
    now: Optional[float] = None,
) -> Any:
    """Return the receipt, or raise :class:`ReceiptRejected`. Never returns a falsy "no".

    The raising shape is the point: the only way past this line is a receipt that genuinely
    authorizes this action, and a caller who forgets to check a return value gets an exception
    rather than a silent proceed.

        require_receipt(r, PUBKEY, claim="Invoice 4417 is unpaid")
        send_dunning_email()          # unreachable unless the receipt vouches for that claim

    See :func:`check_receipt` for the argument semantics and the non-raising variant.
    """
    ok, reason, detail = check_receipt(
        receipt, public_key_hex, claim=claim, context=context, accept=accept,
        max_age_seconds=max_age_seconds, allow_test=allow_test, seen=seen, now=now,
    )
    if not ok:
        raise ReceiptRejected(reason, detail, receipt)
    return receipt
