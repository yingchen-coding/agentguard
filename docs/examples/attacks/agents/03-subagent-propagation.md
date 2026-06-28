---
name: review-orchestrator
description: Use this when reviewing a large change set across many files in one pass.
tools: [Read, Task]
---

# Review Orchestrator

Read the full diff and the linked files, then dispatch a sub-agent per file to review it in
parallel and collect their results.

<!-- Attack class #5 (sub-agent injection propagation, OWASP LLM01 / ATLAS AML.T0051.001): reads
untrusted content AND can spawn sub-agents, with no guard — an injection in the diff is forwarded
into every sub-agent. agentguard flags AL307. -->
