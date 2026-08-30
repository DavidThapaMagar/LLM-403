# Agent Security Lab

A hands-on research project exploring security for AI agents — built from
the ground up as a security gateway that sits between an LLM agent and
every tool it can touch.

## The Question This Project Answers

Every check in this system exists to answer one question, with growing
precision as the project has developed:

> Is this agent authorized to perform this action, on this resource, for
> this task, with this authority, given the sequence of actions that led
> here?

## Architecture
AI Agent
↓
Security Gateway ──→ Event Log ──→ Dashboard (LLM403)
↓
Policy Engine (permissions · risk · trajectory · delegation)
↓
Tool (files · shell · knowledge base · MCP tool · browser)
↓
Egress Scrubber
↓
Response


No tool call reaches the outside world without passing through the
gateway first, and no response leaves the agent without passing through
the egress scrubber last.

## Status: Phases 1–5 Complete

### Phase 1 — Foundation
Basic tools, a file sandbox, a policy engine, a security gateway, a tool
router, native LLM function calling, a hard step limit, and the first
indirect prompt-injection experiment.

### Phase 2 — Attack Lab
A growing library of prompt-injection attacks — direct asks, disguised
asks, social engineering, "implied prior agreement" framing, stored/
persistent injection, command injection via injection, path traversal,
unauthorized writes, and multi-step trajectory attacks (soft redirect,
required-format redirect, fused single-step exfiltration).

### Phase 3 — Authorization
Turned a flat allow-list into a real authorization system:
- **Agent identity** — every agent has an ID and a name
- **Task IDs** — every request gets a unique, traceable ticket
- **Task-scoped permissions** — different task types get different access,
  always bounded by a global ceiling
- **Short-lived grants** — permissions can expire mid-task by step count
- **Action-level authorization** — one unified decision point
  (`is_action_allowed`) instead of duplicated per-action logic
- **Risk levels** — every action carries a LOW/MEDIUM/HIGH risk tag, and
  each task type has a `max_risk` it's trusted with, independent of
  whether the specific resource is on an allow-list

### Phase 4 — Observability
- Structured JSON event logging for every gateway decision
- `gateway/trace.py` — full step-by-step execution trace for any task
- `gateway/metrics.py` — aggregate stats: block rates by action, risk,
  and work type; most-frequently-blocked resources
- **LLM403** — an interactive HTML dashboard (`gateway/dashboard.py`):
  summary cards, live filters and search, click-to-expand resource info
  (with real file content and auto-classified attack tags), and
  click-to-expand task traces. Fully self-contained, no server required.

### Phase 5 — Advanced Agent Security
- **Multi-agent delegation** — a task can spawn bounded sub-tasks
  (`TaskContext.spawn_child`); a child's effective permissions are always
  the intersection of its own and every ancestor's, recursively, so
  delegation can only narrow access, never grant more
- **Trajectory policies** — the gateway watches sequences, not just single
  actions; a task that racks up repeated blocked attempts gets locked out
  of further actions entirely
- **Agent-to-agent injection** — tested whether an injected instruction
  survives being paraphrased by one agent and read by a second agent that
  never touches the original source
- **RAG poisoning** — a mock knowledge-base search where a poisoned
  document has to compete for relevance against legitimate ones, rather
  than being handed to the agent directly
- **MCP security** — tested tool *description* poisoning (an attack
  surface distinct from tool *output* poisoning); this is the one test
  in the whole project where the model actually attempted the attack and
  the **gateway itself** — not model judgment — was the thing that
  stopped it
- **Browser-agent attacks** — a mock webpage with content hidden from
  human view (CSS `display:none`) but present in the raw text a browsing
  agent reads
- **Data-egress controls** — a last-resort output scrubber
  (`gateway/egress.py`) that checks the agent's final response for
  literal leaked content from protected files, independent of every
  upstream defense

## Project Structure
agent/
llm_agent.py — the agent loop, tool definitions, model calls
tools.py — raw tool implementations (unguarded)

gateway/
context.py — TaskContext: identity, delegation, trajectory history
permissions.py — task-scoped permission sets, recursive delegation logic
policy.py — is_action_allowed: the single authorization decision point
risk.py — LOW/MEDIUM/HIGH risk classification per action+resource
trajectory.py — sequence-based policies (repeated-blocked-attempts lockout)
gateway.py — secure_* wrappers: every tool call's real entry point
router.py — maps tool names to secure_* functions
events.py — structured JSON logging of every decision
trace.py — CLI: full trace for one task
metrics.py — CLI: aggregate stats across all events
dashboard.py — generates the interactive LLM403 HTML dashboard
rag.py — mock keyword-based knowledge-base search
web.py — mock browser (URL → local HTML file)
egress.py — output scrubber: catches literal leaks in final output
test_*.py — attack tests and verification tests, one per finding

attacks/ — planted prompt-injection files, v1 through v7c and a2a
knowledge_base/ — RAG documents, 3 legitimate + 1 poisoned
web_pages/ — mock webpages, 2 legitimate + 1 with hidden injection
sandbox/ — notes.txt (readable/writable) and secrets.txt (the target)
logs/ — event log + generated dashboard (gitignored)


## Running It

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # openai, python-dotenv, etc.
```

Any `gateway/test_*.py` file runs standalone:

```bash
python -m gateway.test_task_scoped_permissions
python -m gateway.test_mcp_tool_poisoning     # makes a real LLM call
```

Generate the dashboard after running a batch of tests:

```bash
python -m gateway.dashboard
# then open logs/dashboard.html
```

## Known Limitations

Documented honestly rather than hidden, in the same spirit as the rest
of this project:

- **No content-length limit on writes.** `secure_write_file` doesn't cap
  content size, so an unbounded write can still get through — a
  resource-exhaustion gap, found during Phase 2 adversarial-argument
  testing and not yet closed.
- **The egress scrubber only catches literal matches.** It checks for
  the exact text of a protected file appearing in the agent's output.
  A reversed, base64-encoded, letter-spelled, translated, or paraphrased
  leak would not be caught. This is a known weakness of simple
  output-side DLP in general, not unique to this implementation — a
  stronger version would need semantic/pattern-based detection.
- **Delegated sub-tasks don't share a step budget with their parent.**
  A child gets its own fresh `steps_taken` counter rather than drawing
  down from the parent's remaining steps — a reasonable first version,
  but not fully airtight for long delegation chains.
- **Most Phase 5 results demonstrate model-level resistance, not gateway
  enforcement.** Across delegation, trajectory, agent-to-agent, RAG, and
  browser tests, the model never actually attempted the disallowed
  action, so the gateway's authorization logic was never exercised as a
  backstop in those cases. The MCP security test is the one exception,
  where the model *did* attempt the attack and the gateway is what
  actually stopped it — the strongest evidence in the project that the
  authorization layer, not just model behavior, is doing real work.
