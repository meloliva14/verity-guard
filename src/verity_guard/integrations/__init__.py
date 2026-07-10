"""Framework adapters for verity-guard.

Each submodule lazy-imports its framework, so installing verity-guard never pulls
in LangChain / LangGraph / CrewAI / OpenAI-Agents unless you actually use it:

    from verity_guard.integrations.langchain import build_guard_tool
    from verity_guard.integrations.langgraph import GuardedToolNode
    from verity_guard.integrations.crewai import build_guard_tool as crew_guard_tool
    from verity_guard.integrations.openai_agents import build_guard_tool, build_output_guardrail
"""
