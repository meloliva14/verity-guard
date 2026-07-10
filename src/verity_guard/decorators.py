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


def format_verdict(res: VerityResult) -> str:
    """Compact one-line summary an agent/LLM can read back."""
    if res.payment_required:
        return f"[verity] payment_required ({res.price}) — settle via x402 and retry."
    if res.get("error"):
        return f"[verity] error: {res.get('error')}"
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
            if res.blocked:
                if on_block == "return":
                    return format_verdict(res)
                raise BlockedAction(res)
            return await fn(*args, **kwargs)
        return wrapper
    return deco
