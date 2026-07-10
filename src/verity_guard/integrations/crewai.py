"""CrewAI adapter.

    from verity_guard import VerityClient
    from verity_guard.integrations.crewai import build_guard_tool

    guard = build_guard_tool(VerityClient(http=my_x402_client),
                             default_policy="No new payees without human review.")
    agent = Agent(role="Treasurer", tools=[guard, ...])

Requires ``crewai`` (install extra: ``verity-guard[crewai]``).
"""
from __future__ import annotations

from typing import Any, Optional, Type

from ..decorators import GUARD_TOOL_DESC, format_verdict


def build_guard_tool(client: Any, *, tier: str = "quick",
                     default_policy: Optional[str] = None) -> Any:
    """Return a CrewAI ``BaseTool`` instance the agent can call before acting."""
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field

    class _GuardArgs(BaseModel):
        action: str = Field(..., description="The action the agent is about to take.")
        context: str = Field("", description="Optional situation/background.")
        policy: str = Field("", description="Optional rules that must not be violated.")

    class VerityGuardTool(BaseTool):
        name: str = "verity_guard_action"
        description: str = GUARD_TOOL_DESC
        args_schema: Type[BaseModel] = _GuardArgs

        def _run(self, action: str, context: str = "", policy: str = "") -> str:
            res = client.guard(action, context=context or None,
                               policy=policy or default_policy, tier=tier)
            return format_verdict(res)

    return VerityGuardTool()


def build_verify_tool(client: Any, *, tier: str = "grounded") -> Any:
    """Return a CrewAI ``BaseTool`` that fact-checks a claim (grounded, signed receipt)."""
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field

    class _VerifyArgs(BaseModel):
        claim: str = Field(..., description="The factual claim to verify.")
        context: str = Field("", description="Optional surrounding context.")

    class VerityVerifyTool(BaseTool):
        name: str = "verity_verify_fact"
        description: str = (
            "Reality-check a factual claim before acting on or repeating it. Returns "
            "supported/unsupported/uncertain with calibrated confidence, live-web reasoning, and a "
            "signed, independently re-verifiable receipt. Fail-closed: abstains rather than guess."
        )
        args_schema: Type[BaseModel] = _VerifyArgs

        def _run(self, claim: str, context: str = "") -> str:
            res = client.verify(claim, context=context or None, tier=tier)
            return format_verdict(res)

    return VerityVerifyTool()
