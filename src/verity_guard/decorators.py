"""Framework-agnostic helpers shared by every adapter.

- ``format_verdict`` turns a VerityResult into a compact, agent-readable line.
- ``BlockedAction`` is the exception raised when a guarded call is blocked.
- ``guard`` / ``aguard`` decorate a plain function so it is gated by guard_action
  before it runs — the simplest possible wire-in, no framework required.
"""
from __future__ import annotations

import functools
import inspect
import json
from typing import Any, Awaitable, Callable, Optional

from .client import VerityResult

GUARD_TOOL_DESC = (
    "Independent fail-closed safety gate. BEFORE any irreversible action (a payment/spend, an "
    "outbound message, a destructive command, a data share, a publish), describe the action and "
    "call this. Returns allow / review / block with an honest risk score, concrete reasons, and a "
    "safer alternative when it blocks — plus an Ed25519-signed, independently re-verifiable receipt. "
    "Priced per call via x402; allow/review/block cost the same (no block-to-bill). If it blocks, do "
    "NOT take the action — follow the safer alternative."
)


class BlockedAction(Exception):
    """Raised when guard_action returns ``block`` for a guarded call."""

    def __init__(self, result: VerityResult) -> None:
        self.result = result
        safer = result.safer_alternative or "no safer alternative supplied"
        super().__init__(f"VerityLayer blocked this action (risk={result.risk}). Safer: {safer}")


class GuardUnavailable(Exception):
    """Raised when guard_action did not return a usable verdict, so the action MUST NOT run.

    This is the exception that makes "fail-closed" true in code instead of only in the
    README. A guard that could not answer is not the same as a guard that said yes.
    """

    def __init__(self, result: Any, problem: str) -> None:
        self.result = result
        self.problem = problem
        super().__init__(
            f"VerityLayer could not produce a verdict ({problem}). Fail-closed: the guarded "
            f"action was NOT taken. Resolve the guard or seek human approval before retrying."
        )


# Every decision value the services are contracted to return, across all endpoints.
# Gates must recognize a verdict, not merely fail to recognize a block.
KNOWN_DECISIONS = frozenset({
    "allow", "review", "block",                       # guard_action / sieve
    "supported", "unsupported", "uncertain",          # verify / cite
    "clean", "suspicious", "injection",               # sentinel
    "publish",                                        # sieve
    "contains_pii", "contains_secret",                # redact
})


def _normalized(decision: Any) -> str:
    """Compare decisions case- and whitespace-insensitively. 'BLOCK' must never slip past a
    check for 'block' and execute the action it was meant to stop."""
    return str(decision).strip().lower()


def _close_awaitable(res: Any) -> None:
    """Best-effort close of an un-awaited coroutine so it doesn't emit a RuntimeWarning
    on GC. Cosmetic only — the fail-closed decision has already been made by then."""
    close = getattr(res, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def verdict_problem(res: Any) -> Optional[str]:
    """Return why ``res`` is not a usable verdict, or ``None`` if it is one.

    THE FAIL-CLOSED CHOKEPOINT. Every enforcement path must call this before it decides
    to run anything, because the obvious check is silently backwards:

        ``VerityResult.blocked`` is ``decision == "block"``, and ``decision`` is ``None``
        for a network error, for an unsettled 402, and for an un-awaited coroutine. So
        ``if res.blocked:`` reads False in all three cases and falls through to *execute*
        the very action nobody verified. That is fail-OPEN — the exact opposite of what
        this product sells.

    Fail-closed means: proceed only on an affirmative verdict. No verdict => no action.
    """
    if inspect.isawaitable(res):
        return ("guard returned an un-awaited coroutine — an async client was used on a "
                "synchronous path; use the async API (aguard/ainvoke) or a sync VerityClient")
    if not isinstance(res, VerityResult):
        return f"guard returned {type(res).__name__}, not a VerityResult"
    if res.payment_required:
        return f"payment_required ({res.price}) — the check was never performed"
    if res.get("error"):
        return f"guard unreachable: {res.get('error')}"
    if res.decision is None:
        return "guard returned no decision"
    if _normalized(res.decision) not in KNOWN_DECISIONS:
        # An ALLOWLIST, not a denylist. The gates ask "did it block?", so anything that is
        # not exactly "block" would otherwise proceed — including a garbled decision, and
        # (worst) a case variant of the block verdict itself: "BLOCK" != "block", so a real
        # block would have executed the action.
        return f"guard returned an unrecognized decision {res.decision!r}"
    return None


_NOT_CHECKED = "No verdict exists — do not treat this as an allow."


def format_verdict(res: Any) -> str:
    """Compact one-line summary an agent/LLM can read back.

    Defensive on purpose. This string is handed straight to a model, so it must (a) never
    raise — it used to explode on ``res.payment_required`` when a sync tool path was given
    an async client and got an un-awaited coroutine — and (b) never read like an allow when
    no verdict was produced.
    """
    # Drive off the SAME chokepoint the gates use, so the string can never disagree with
    # them. Hand-listing the cases here is what let a decision-less 200 render as the
    # cheerful "[verity] decision=None | risk=0.1" — with no warning — on the advisory
    # tool paths (LangChain/CrewAI/OpenAI-Agents build_guard_tool), where this string IS
    # the entire enforcement signal the model ever sees.
    problem = verdict_problem(res)
    if problem:
        _close_awaitable(res)
        if isinstance(res, VerityResult) and res.payment_required:
            return (f"[verity] NOT CHECKED — payment_required ({res.price}); settle via "
                    f"x402 and retry. {_NOT_CHECKED}")
        return f"[verity] NOT CHECKED — {problem}. {_NOT_CHECKED}"
    parts = [f"[verity] decision={res.decision}", f"risk={res.risk}"]
    if res.reasons:
        parts.append("reasons: " + "; ".join(str(r) for r in res.reasons[:4]))
    if res.blocked and res.safer_alternative:
        parts.append("safer_alternative: " + res.safer_alternative)
    rid = (res.receipt or {}).get("receipt_id") if res.receipt else None
    if rid:
        parts.append(f"receipt={rid}")
    return " | ".join(parts)


def describe_call(fn_name: str, args: tuple, kwargs: dict) -> str:
    """Default action description for a wrapped function call."""
    try:
        a = json.dumps(list(args), default=str)[:400]
        k = json.dumps(kwargs, default=str)[:400]
    except Exception:
        a, k = str(args)[:400], str(kwargs)[:400]
    return f"Call `{fn_name}` with args={a} kwargs={k}"


async def _guard_any(client: Any, action: str, *, context: Optional[str], policy: Optional[str],
                     tier: Optional[str]) -> VerityResult:
    """Call ``client.guard`` whether the client is sync or async."""
    res = client.guard(action, context=context, policy=policy, tier=tier)
    if inspect.isawaitable(res):
        res = await res
    return res


def guard(client: Any, *, policy: Optional[str] = None, tier: str = "quick",
          describe: Optional[Callable[..., str]] = None, on_block: str = "raise") -> Callable:
    """Decorate a **sync** function so guard_action gates it before it runs.

    on_block="raise" -> raise BlockedAction; on_block="return" -> return the verdict summary
    string instead of running the function. ``review``/``allow`` always proceed.
    """
    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            action = describe(*args, **kwargs) if describe else describe_call(fn.__name__, args, kwargs)
            res = client.guard(action, policy=policy, tier=tier)
            problem = verdict_problem(res)
            if problem:  # no verdict is NOT permission to proceed
                _close_awaitable(res)
                raise GuardUnavailable(res, problem)
            if res.blocked:
                if on_block == "return":
                    return format_verdict(res)
                raise BlockedAction(res)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def aguard(client: Any, *, policy: Optional[str] = None, tier: str = "quick",
           describe: Optional[Callable[..., str]] = None, on_block: str = "raise") -> Callable:
    """Async counterpart of :func:`guard` (works with sync or async clients)."""
    def deco(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            action = describe(*args, **kwargs) if describe else describe_call(fn.__name__, args, kwargs)
            res = await _guard_any(client, action, context=None, policy=policy, tier=tier)
            problem = verdict_problem(res)
            if problem:  # no verdict is NOT permission to proceed
                raise GuardUnavailable(res, problem)
            if res.blocked:
                if on_block == "return":
                    return format_verdict(res)
                raise BlockedAction(res)
            return await fn(*args, **kwargs)
        return wrapper
    return deco
