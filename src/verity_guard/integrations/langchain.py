"""LangChain adapter.

    from verity_guard import VerityClient
    from verity_guard.integrations.langchain import build_guard_tool

    v = VerityClient(http=my_x402_client)          # x402-wrapped httpx.Client / requests.Session
    tools = [..., build_guard_tool(v)]             # give the agent an explicit guard tool

Or gate any existing tool's function with the framework-agnostic decorator:

    from verity_guard import guard
    @guard(v, policy="No new payees without review.")
    def wire_funds(to: str, amount: float): ...
"""
from __future__ import annotations

from typing import Any, Optional

from ..decorators import GUARD_TOOL_DESC, _guard_any, format_verdict


def build_guard_tool(client: Any, *, tier: str = "quick", name: str = "verity_guard_action",
                     default_policy: Optional[str] = None) -> Any:
    """Return a LangChain ``StructuredTool`` the agent can call before acting.

    Works with any LangChain-compatible agent (tool-calling / ReAct), sync or async, with a
    ``VerityClient`` or an ``AsyncVerityClient``. Requires ``langchain-core``
    (install extra: ``verity-guard[langchain]``).
    """
    from langchain_core.tools import StructuredTool

    def _guard(action: str, context: str = "", policy: str = "") -> str:
        res = client.guard(action, context=context or None, policy=policy or default_policy, tier=tier)
        return format_verdict(res)  # honest (and non-raising) if `res` is an un-awaited coroutine

    async def _aguard(action: str, context: str = "", policy: str = "") -> str:
        res = await _guard_any(client, action, context=context or None,
                               policy=policy or default_policy, tier=tier)
        return format_verdict(res)

    return StructuredTool.from_function(
        func=_guard,
        coroutine=_aguard,  # without this an async agent could never await the check properly
        name=name,
        description=GUARD_TOOL_DESC,
    )


def build_verify_tool(client: Any, *, tier: str = "grounded", name: str = "verity_verify_fact",
                      default_policy: Optional[str] = None) -> Any:
    """Return a LangChain ``StructuredTool`` that fact-checks a claim (grounded, signed receipt)."""
    from langchain_core.tools import StructuredTool

    def _verify(claim: str, context: str = "") -> str:
        res = client.verify(claim, context=context or None, tier=tier)
        return format_verdict(res)

    async def _averify(claim: str, context: str = "") -> str:
        import inspect
        res = client.verify(claim, context=context or None, tier=tier)
        if inspect.isawaitable(res):
            res = await res
        return format_verdict(res)

    return StructuredTool.from_function(
        func=_verify,
        coroutine=_averify,
        name=name,
        description=(
            "Reality-check a factual CLAIM before acting on or repeating it. Returns "
            "supported / unsupported / uncertain with a calibrated confidence, live-web reasoning, "
            "and an Ed25519-signed receipt. Fail-closed: abstains rather than guess."
        ),
    )
