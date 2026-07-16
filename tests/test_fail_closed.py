"""Fail-closed enforcement tests — the contract the whole product rests on.

These exist because the adapters shipped with ZERO tests and a fail-OPEN gate slipped
through: every enforcement path asked ``if res.blocked:``, and ``VerityResult.blocked``
is ``decision == "block"``, which is False when the guard is unreachable, when a 402 was
never settled, and when an async client's coroutine was never awaited. All three fell
through to "execute the unverified action".

The invariant under test, stated once: **the guarded action runs only on an affirmative,
non-blocking verdict. No verdict => no action. Ever.**
"""
from __future__ import annotations

import sys
import types

import pytest

# --- stub langchain_core so the LangGraph adapter is testable without the dep ----------
if "langchain_core.messages" not in sys.modules:
    _lc = types.ModuleType("langchain_core")
    _msgs = types.ModuleType("langchain_core.messages")

    class ToolMessage:  # minimal stand-in
        def __init__(self, content, tool_call_id, name):
            self.content = content
            self.tool_call_id = tool_call_id
            self.name = name

    _msgs.ToolMessage = ToolMessage
    _lc.messages = _msgs
    sys.modules["langchain_core"] = _lc
    sys.modules["langchain_core.messages"] = _msgs

from verity_guard import (  # noqa: E402
    BlockedAction,
    GuardUnavailable,
    VerityResult,
    aguard,
    guard,
    verdict_problem,
)
from verity_guard.integrations.langgraph import GuardedToolNode  # noqa: E402

BLOCK = VerityResult({"decision": "block", "risk": 0.99, "safer_alternative": "ask a human"})
ALLOW = VerityResult({"decision": "allow", "risk": 0.05})
REVIEW = VerityResult({"decision": "review", "risk": 0.5})
UNREACHABLE = VerityResult({"error": "verity_unreachable: timeout"})
UNPAID = VerityResult({"payment_required": True, "price": "$0.02"})
NO_DECISION = VerityResult({"risk": 0.1})


class _SyncClient:
    def __init__(self, verdict):
        self._v = verdict
        self.calls = 0

    def guard(self, action, **kw):
        self.calls += 1
        return self._v


class _AsyncClient:
    """Mirrors AsyncVerityClient: .guard() is a coroutine function."""

    def __init__(self, verdict):
        self._v = verdict
        self.calls = 0

    async def guard(self, action, **kw):
        self.calls += 1
        return self._v


class _Tool:
    name = "wire_money"

    def __init__(self):
        self.ran = False

    def invoke(self, args):
        self.ran = True
        return "SENT $4000"


def _state(name="wire_money", args=None):
    msg = types.SimpleNamespace(
        tool_calls=[{"name": name, "args": args or {"amount": 4000}, "id": "call_1"}]
    )
    return {"messages": [msg]}


# ── verdict_problem: the chokepoint ───────────────────────────────────────────────────
def test_verdict_problem_accepts_real_verdicts():
    for v in (BLOCK, ALLOW, REVIEW):
        assert verdict_problem(v) is None


@pytest.mark.parametrize("bad,frag", [
    (UNREACHABLE, "unreachable"),
    (UNPAID, "payment_required"),
    (NO_DECISION, "no decision"),
    ({"decision": "allow"}, "not a VerityResult"),
])
def test_verdict_problem_rejects_non_verdicts(bad, frag):
    problem = verdict_problem(bad)
    assert problem is not None and frag in problem


def test_verdict_problem_detects_unawaited_coroutine():
    coro = _AsyncClient(ALLOW).guard("x")
    try:
        problem = verdict_problem(coro)
        assert problem is not None and "coroutine" in problem
    finally:
        coro.close()


# ── THE REGRESSION: the reported fail-open ────────────────────────────────────────────
def test_regression_async_client_on_sync_path_never_executes_blocked_tool():
    """Pre-0.1.1: AsyncVerityClient + the sync path => guard() returned an un-awaited
    coroutine, getattr(coro, "blocked", False) was False, and a `block` verdict with
    risk=0.99 EXECUTED the tool anyway. It must now fail loud and never run."""
    tool = _Tool()
    node = GuardedToolNode([tool], _AsyncClient(BLOCK))
    with pytest.raises(GuardUnavailable):
        node.invoke(_state())
    assert tool.ran is False, "FAIL-OPEN REGRESSION: a blocked tool executed"


def test_regression_async_client_on_call_path_never_executes():
    tool = _Tool()
    node = GuardedToolNode([tool], _AsyncClient(BLOCK))
    with pytest.raises(GuardUnavailable):
        node(_state())  # LangGraph also calls nodes as plain callables
    assert tool.ran is False


# ── GuardedToolNode: fail-closed on every non-verdict ─────────────────────────────────
@pytest.mark.parametrize("verdict", [UNREACHABLE, UNPAID, NO_DECISION])
def test_toolnode_does_not_execute_without_a_verdict(verdict):
    tool = _Tool()
    node = GuardedToolNode([tool], _SyncClient(verdict))
    out = node.invoke(_state())["messages"]
    assert tool.ran is False, "FAIL-OPEN: tool ran without a verdict"
    assert "NOT EXECUTED" in out[0].content


def test_toolnode_does_not_execute_on_block():
    tool = _Tool()
    node = GuardedToolNode([tool], _SyncClient(BLOCK))
    out = node.invoke(_state())["messages"]
    assert tool.ran is False
    assert "BLOCKED" in out[0].content and "ask a human" in out[0].content


def test_toolnode_executes_on_allow():
    """The other half of correctness: a real allow must still run (no over-blocking)."""
    tool = _Tool()
    node = GuardedToolNode([tool], _SyncClient(ALLOW))
    out = node.invoke(_state())["messages"]
    assert tool.ran is True
    assert "SENT $4000" in out[0].content


def test_toolnode_review_proceeds_by_default_but_stops_when_configured():
    t1 = _Tool()
    GuardedToolNode([t1], _SyncClient(REVIEW)).invoke(_state())
    assert t1.ran is True, "documented default: only `block` stops"

    t2 = _Tool()
    out = GuardedToolNode([t2], _SyncClient(REVIEW), review_blocks=True).invoke(_state())["messages"]
    assert t2.ran is False and "BLOCKED" in out[0].content


@pytest.mark.asyncio
async def test_toolnode_async_path_is_fail_closed():
    tool = _Tool()
    out = (await GuardedToolNode([tool], _AsyncClient(UNREACHABLE)).ainvoke(_state()))["messages"]
    assert tool.ran is False, "FAIL-OPEN: async path ran an unverified tool"
    assert "NOT EXECUTED" in out[0].content


@pytest.mark.asyncio
async def test_toolnode_async_path_blocks_and_allows():
    blocked = _Tool()
    await GuardedToolNode([blocked], _AsyncClient(BLOCK)).ainvoke(_state())
    assert blocked.ran is False

    allowed = _Tool()
    await GuardedToolNode([allowed], _AsyncClient(ALLOW)).ainvoke(_state())
    assert allowed.ran is True


# ── decorators: same invariant ────────────────────────────────────────────────────────
@pytest.mark.parametrize("verdict", [UNREACHABLE, UNPAID, NO_DECISION])
def test_guard_decorator_fails_closed_without_a_verdict(verdict):
    ran = {"v": False}

    @guard(_SyncClient(verdict))
    def wire():
        ran["v"] = True
        return "sent"

    with pytest.raises(GuardUnavailable):
        wire()
    assert ran["v"] is False, "FAIL-OPEN: @guard ran the function without a verdict"


def test_guard_decorator_still_blocks_and_allows():
    ran = {"v": False}

    @guard(_SyncClient(BLOCK))
    def blocked_fn():
        ran["v"] = True

    with pytest.raises(BlockedAction):
        blocked_fn()
    assert ran["v"] is False

    @guard(_SyncClient(ALLOW))
    def allowed_fn():
        return "ok"

    assert allowed_fn() == "ok"


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", [UNREACHABLE, UNPAID])
async def test_aguard_fails_closed_without_a_verdict(verdict):
    ran = {"v": False}

    @aguard(_AsyncClient(verdict))
    async def wire():
        ran["v"] = True

    with pytest.raises(GuardUnavailable):
        await wire()
    assert ran["v"] is False, "FAIL-OPEN: @aguard ran the function without a verdict"


@pytest.mark.asyncio
async def test_aguard_still_blocks_and_allows():
    @aguard(_AsyncClient(BLOCK))
    async def blocked_fn():
        return "ran"

    with pytest.raises(BlockedAction):
        await blocked_fn()

    @aguard(_AsyncClient(ALLOW))
    async def allowed_fn():
        return "ok"

    assert await allowed_fn() == "ok"
