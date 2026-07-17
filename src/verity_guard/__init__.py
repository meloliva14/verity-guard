"""verity-guard — a fail-closed verify-before-you-act gate for AI agents.

Quick start (no wallet needed to try — a 402 is surfaced you can inspect):

    from verity_guard import VerityClient
    v = VerityClient()                       # pass an x402-wrapped client to auto-pay
    res = v.guard("Wire $4,000 to 0x9a3f… (invoice #221)",
                  policy="No new payees without human review.")
    print(res.decision, res.risk)            # e.g. block 0.9
    if res.receipt:
        print(v.verify_receipt(res.receipt).valid)   # True — free, independent

Framework adapters (lazy-imported):

    from verity_guard.integrations import langchain, langgraph, crewai, openai_agents
"""
from __future__ import annotations

from .client import (
    AsyncVerityClient,
    ENGINE_DEFAULT,
    SUITE_DEFAULT,
    VerityClient,
    VerityError,
    VerityResult,
)
from .decorators import (
    BlockedAction,
    GUARD_TOOL_DESC,
    GuardUnavailable,
    aguard,
    format_verdict,
    guard,
    verdict_problem,
)
from .payer import async_x402_payer, wallet_address, x402_payer

__version__ = "0.2.2"

__all__ = [
    "VerityClient",
    "AsyncVerityClient",
    "x402_payer",
    "async_x402_payer",
    "wallet_address",
    "VerityResult",
    "VerityError",
    "BlockedAction",
    "GuardUnavailable",
    "verdict_problem",
    "guard",
    "aguard",
    "format_verdict",
    "GUARD_TOOL_DESC",
    "ENGINE_DEFAULT",
    "SUITE_DEFAULT",
    "__version__",
]
