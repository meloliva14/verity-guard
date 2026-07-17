"""OpenAI Agents SDK adapter.

Three ways to wire VerityLayer in, strongest last:

1. A guard TOOL the agent can call:
       from verity_guard.integrations.openai_agents import build_guard_tool
       agent = Agent(name="Treasurer", tools=[build_guard_tool(v), ...])

2. An OUTPUT guardrail that verifies the agent's final answer (fact-check / safety):
       from verity_guard.integrations.openai_agents import build_output_guardrail
       agent = Agent(..., output_guardrails=[build_output_guardrail(v, mode="guard",
                        policy="No new payees without human review.")])

3. A per-TOOL-CALL input guardrail (newer SDKs) — the highest-frequency, always-on gate:
       from verity_guard.integrations.openai_agents import build_tool_input_guardrail
       my_tool.tool_input_guardrails = [build_tool_input_guardrail(v)]

Works with a sync ``VerityClient`` or an ``AsyncVerityClient``. Requires
``openai-agents`` (install extra: ``verity-guard[openai-agents]``).
"""
from __future__ import annotations

import json
from typing import Any, Optional

from ..decorators import GUARD_TOOL_DESC, _guard_any, format_verdict, verdict_problem


def _no_verdict_info(problem: str) -> dict:
    """What a guardrail reports when the check did not happen.

    Fail-closed: a guardrail that cannot verify must TRIP, not wave the action through.
    ``res.blocked`` is False for a network error and for an unsettled 402, so trusting it
    alone silently turns every guardrail here into a no-op at exactly the wrong moment.
    """
    return {
        "verity_error": problem,
        "decision": None,
        "note": "The check did not complete. Fail-closed: treated as unsafe, not allowed.",
    }


def build_guard_tool(client: Any, *, tier: str = "quick",
                     default_policy: Optional[str] = None) -> Any:
    """Return an OpenAI-Agents ``function_tool`` the agent can call before acting."""
    from agents import function_tool

    async def verity_guard_action(action: str, context: str = "", policy: str = "") -> str:
        res = await _guard_any(client, action, context=context or None,
                               policy=policy or default_policy, tier=tier)
        return format_verdict(res)  # already honest about errors / payment_required

    # The description IS the wire-in for a discretionary tool: an empty one means the model
    # never calls it. @function_tool reads the docstring AT DECORATION, so setting __doc__
    # afterwards (as this used to) could leave the tool with no description at all. Set it
    # first, and also pass description_override where the installed SDK supports it.
    verity_guard_action.__doc__ = GUARD_TOOL_DESC
    try:
        return function_tool(verity_guard_action, description_override=GUARD_TOOL_DESC)
    except TypeError:  # older SDKs without description_override
        return function_tool(verity_guard_action)


def build_output_guardrail(client: Any, *, mode: str = "guard", tier: str = "quick",
                           policy: Optional[str] = None) -> Any:
    """Return an ``@output_guardrail`` that trips when the agent's output is unsafe.

    mode="guard"  -> run guard_action over the final output (treat it as a proposed action).
    mode="verify" -> fact-check the final output as a claim; trips on unsupported.
    """
    from agents import GuardrailFunctionOutput, output_guardrail

    @output_guardrail
    async def verity_output_guardrail(ctx: Any, agent: Any, output: Any) -> GuardrailFunctionOutput:
        text = output if isinstance(output, str) else json.dumps(output, default=str)
        if mode == "verify":
            res = client.verify(text, tier=("grounded" if tier == "quick" else tier))
            import inspect
            if inspect.isawaitable(res):
                res = await res
            problem = verdict_problem(res)
            tripwire = True if problem else res.decision_is("unsupported")
        else:
            res = await _guard_any(client, text, context="final agent output",
                                   policy=policy, tier=tier)
            problem = verdict_problem(res)
            tripwire = True if problem else res.blocked
        info = _no_verdict_info(problem) if problem else dict(res)
        return GuardrailFunctionOutput(output_info=info, tripwire_triggered=tripwire)

    return verity_output_guardrail


def build_input_guardrail(client: Any, *, tier: str = "quick") -> Any:
    """Return an ``@input_guardrail`` that screens incoming user input for prompt-injection."""
    from agents import GuardrailFunctionOutput, input_guardrail

    @input_guardrail
    async def verity_input_guardrail(ctx: Any, agent: Any, user_input: Any) -> GuardrailFunctionOutput:
        text = user_input if isinstance(user_input, str) else json.dumps(user_input, default=str)
        res = client.detect_injection(text, tier=tier)
        import inspect
        if inspect.isawaitable(res):
            res = await res
        problem = verdict_problem(res)
        tripwire = True if problem else res.decision_is("injection", "suspicious")
        info = _no_verdict_info(problem) if problem else dict(res)
        return GuardrailFunctionOutput(output_info=info, tripwire_triggered=tripwire)

    return verity_input_guardrail


def build_tool_input_guardrail(client: Any, *, tier: str = "quick",
                               policy: Optional[str] = None, review_blocks: bool = False) -> Any:
    """Return a per-tool-call input guardrail (newer Agents SDKs).

    This is the highest-frequency wire-in: it guards the ARGUMENTS of every tool call
    right before execution. Attach to a tool's ``tool_input_guardrails``. Falls back with
    a clear error if the installed SDK lacks tool-level guardrails.
    """
    try:
        from agents import ToolInputGuardrailData, tool_input_guardrail  # type: ignore
        from agents.guardrail import ToolGuardrailFunctionOutput  # type: ignore
    except Exception as e:  # pragma: no cover - depends on SDK version
        raise ImportError(
            "This openai-agents version lacks tool-level guardrails. Upgrade openai-agents, or use "
            "build_guard_tool / build_output_guardrail instead."
        ) from e

    @tool_input_guardrail
    async def verity_tool_guard(data: ToolInputGuardrailData) -> "ToolGuardrailFunctionOutput":
        call = getattr(data, "context", data)
        name = getattr(getattr(call, "tool_call", None), "name", "tool")
        args = getattr(getattr(call, "tool_call", None), "arguments", "")
        res = await _guard_any(client, f"Execute tool `{name}` with arguments {str(args)[:800]}",
                               context=None, policy=policy, tier=tier)
        problem = verdict_problem(res)
        if problem:  # no verdict is NOT permission to run the tool
            return ToolGuardrailFunctionOutput.reject_content(
                message=(f"NOT EXECUTED — VerityLayer could not verify this call ({problem}). "
                         f"Fail-closed: resolve the guard or get human approval."),
                output_info=_no_verdict_info(problem))
        stop = res.blocked or (review_blocks and res.decision_is("review"))
        if stop:
            msg = f"BLOCKED by VerityLayer (risk={res.risk}). {res.safer_alternative or ''}".strip()
            return ToolGuardrailFunctionOutput.reject_content(message=msg, output_info=dict(res))
        return ToolGuardrailFunctionOutput.allow(output_info=dict(res))

    return verity_tool_guard
