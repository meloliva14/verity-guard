"""LangGraph adapter — a drop-in guarded tool node.

``GuardedToolNode`` is a direct replacement for ``langgraph.prebuilt.ToolNode``:
before executing each proposed tool call it asks VerityLayer's guard_action for an
independent allow/review/block. Allowed calls run for real; blocked calls are NOT
executed — instead the model receives a ToolMessage with the block reason + safer
alternative, so it revises and loops. Every proposed call still gets exactly one
ToolMessage, preserving LangGraph's tool-call invariant.

    from verity_guard import VerityClient
    from verity_guard.integrations.langgraph import GuardedToolNode

    tool_node = GuardedToolNode(tools, VerityClient(http=my_x402_client),
                                policy="No new payees without human review.")
    graph.add_node("tools", tool_node)   # instead of ToolNode(tools)
"""
from __future__ import annotations

import json
from typing import Any, Optional

from ..decorators import _guard_any


def _messages_of(state: Any) -> list:
    if isinstance(state, dict):
        return state.get("messages", [])
    return getattr(state, "messages", [])


def _action_str(name: str, args: Any) -> str:
    try:
        a = json.dumps(args, default=str)[:800]
    except Exception:
        a = str(args)[:800]
    return f"Execute tool `{name}` with arguments {a}"


class GuardedToolNode:
    """A ToolNode that runs guard_action before every tool call. Sync + async callable."""

    def __init__(self, tools: list, client: Any, *, policy: Optional[str] = None,
                 tier: str = "quick", review_blocks: bool = False) -> None:
        # review_blocks=True also stops "review" verdicts (default: only "block" stops).
        self._tools = {getattr(t, "name", getattr(t, "__name__", str(i))): t for i, t in enumerate(tools)}
        self._client = client
        self._policy = policy
        self._tier = tier
        self._review_blocks = review_blocks

    def _blocked(self, res: Any) -> bool:
        return res.blocked or (self._review_blocks and res.decision == "review")

    def _tool_message(self, content: str, tool_call_id: str, name: str) -> Any:
        from langchain_core.messages import ToolMessage
        return ToolMessage(content=content, tool_call_id=tool_call_id, name=name)

    def _run_tool(self, name: str, args: dict) -> str:
        tool = self._tools.get(name)
        if tool is None:
            return f"error: unknown tool {name!r}"
        try:
            if hasattr(tool, "invoke"):
                return str(tool.invoke(args))
            return str(tool(**args))  # plain callable fallback
        except Exception as e:  # surface tool errors as a tool result, don't crash the graph
            return f"error running {name}: {str(e)[:200]}"

    # -- sync path --
    def invoke(self, state: Any, config: Any = None) -> dict:
        import asyncio
        return asyncio.get_event_loop().run_until_complete(self.ainvoke(state, config)) \
            if False else self._invoke_sync(state)

    def _invoke_sync(self, state: Any) -> dict:
        msgs = _messages_of(state)
        last = msgs[-1] if msgs else None
        calls = getattr(last, "tool_calls", None) or []
        out = []
        for c in calls:
            name, args, cid = c["name"], (c.get("args") or {}), c["id"]
            res = self._client.guard(_action_str(name, args), context=None, policy=self._policy, tier=self._tier)
            if getattr(res, "blocked", False) or (self._review_blocks and getattr(res, "decision", None) == "review"):
                safer = res.safer_alternative or "revise or seek human approval before retrying."
                out.append(self._tool_message(
                    f"BLOCKED by VerityLayer (risk={res.risk}). Do not take this action. Safer: {safer}",
                    cid, name))
            else:
                out.append(self._tool_message(self._run_tool(name, args), cid, name))
        return {"messages": out}

    # -- async path (works with sync or async client) --
    async def ainvoke(self, state: Any, config: Any = None) -> dict:
        msgs = _messages_of(state)
        last = msgs[-1] if msgs else None
        calls = getattr(last, "tool_calls", None) or []
        out = []
        for c in calls:
            name, args, cid = c["name"], (c.get("args") or {}), c["id"]
            res = await _guard_any(self._client, _action_str(name, args), context=None,
                                   policy=self._policy, tier=self._tier)
            if self._blocked(res):
                safer = res.safer_alternative or "revise or seek human approval before retrying."
                out.append(self._tool_message(
                    f"BLOCKED by VerityLayer (risk={res.risk}). Do not take this action. Safer: {safer}",
                    cid, name))
            else:
                out.append(self._tool_message(self._run_tool(name, args), cid, name))
        return {"messages": out}

    # LangGraph calls nodes as plain callables too.
    def __call__(self, state: Any, config: Any = None) -> dict:
        return self._invoke_sync(state)
