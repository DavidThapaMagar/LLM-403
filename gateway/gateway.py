from .policy import is_action_allowed
from .events import log_event
from .risk import get_risk_level
from .trajectory import is_locked_out, MAX_BLOCKED_BEFORE_LOCKOUT
from .rag import search_documents
from .web import fetch_webpage
from agent.tools import read_file, write_file, run_command


def secure_read_file(path, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested file: {path}")

    risk = get_risk_level("read", path)

    if is_locked_out(context):
        reason = f"Task locked out after {MAX_BLOCKED_BEFORE_LOCKOUT} blocked attempts."
        print("Decision: Blocked X")
        print(f"Reason: {reason}")
        log_event(context, "read", path, "blocked", reason, risk)
        context.record_action("read", path, "blocked")
        return None

    if not is_action_allowed("read", path, context):
        print("Decision: Blocked X")
        print("Reason: Read not authorized.")
        log_event(context, "read", path, "blocked", "Read not authorized.", risk)
        context.record_action("read", path, "blocked")
        return None

    print("Decision: Allowed")
    log_event(context, "read", path, "allowed", "OK", risk)
    context.record_action("read", path, "allowed")
    return read_file(path)


def secure_write_file(path, content, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested write: {path}")

    risk = get_risk_level("write", path)

    if is_locked_out(context):
        reason = f"Task locked out after {MAX_BLOCKED_BEFORE_LOCKOUT} blocked attempts."
        print("Decision: Blocked X")
        print(f"Reason: {reason}")
        log_event(context, "write", path, "blocked", reason, risk)
        context.record_action("write", path, "blocked")
        return None

    if not is_action_allowed("write", path, context):
        print("Decision: Blocked X")
        print("Reason: Write not authorized.")
        log_event(context, "write", path, "blocked", "Write not authorized.", risk)
        context.record_action("write", path, "blocked")
        return None

    if not isinstance(content, str):
        reason = f"Content must be a string, got {type(content).__name__}."
        print("Decision: Blocked X")
        print(f"Reason: {reason}")
        log_event(context, "write", path, "blocked", reason, risk)
        context.record_action("write", path, "blocked")
        return None

    print("Decision: Allowed")
    log_event(context, "write", path, "allowed", "OK", risk)
    context.record_action("write", path, "allowed")
    return write_file(path, content)


def secure_run_command(command, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested command: {command}")

    risk = get_risk_level("command", command)

    if is_locked_out(context):
        reason = f"Task locked out after {MAX_BLOCKED_BEFORE_LOCKOUT} blocked attempts."
        print("Decision: Blocked X")
        print(f"Reason: {reason}")
        log_event(context, "command", command, "blocked", reason, risk)
        context.record_action("command", command, "blocked")
        return None

    if not is_action_allowed("command", command, context):
        print("Decision: Blocked X")
        print("Reason: Command not authorized.")
        log_event(context, "command", command, "blocked", "Command not authorized.", risk)
        context.record_action("command", command, "blocked")
        return None

    print("Decision: Allowed")
    log_event(context, "command", command, "allowed", "OK", risk)
    context.record_action("command", command, "allowed")
    return run_command(command)


def secure_search_knowledge_base(query, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Knowledge base search: {query!r}")

    candidates = search_documents(query)
    print(f"Retrieved {len(candidates)} candidate document(s): {[p for p, _ in candidates]}")

    results = []
    for path, score in candidates:
        content = secure_read_file(path, context)
        if content is not None:
            results.append({"path": path, "content": content})

    return results


def secure_lookup_ticket_status(ticket_id, diagnostic_info, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"MCP tool call: lookup_ticket_status(ticket_id={ticket_id!r})")
    print(f"diagnostic_info argument received: {diagnostic_info!r}")

    risk = get_risk_level("mcp_call", "lookup_ticket_status")

    if is_locked_out(context):
        reason = f"Task locked out after {MAX_BLOCKED_BEFORE_LOCKOUT} blocked attempts."
        print("Decision: Blocked X")
        print(f"Reason: {reason}")
        log_event(context, "mcp_call", "lookup_ticket_status", "blocked", reason, risk)
        context.record_action("mcp_call", "lookup_ticket_status", "blocked")
        return None

    if not is_action_allowed("mcp_call", "lookup_ticket_status", context):
        print("Decision: Blocked X")
        print("Reason: MCP tool call not authorized.")
        log_event(context, "mcp_call", "lookup_ticket_status", "blocked", "MCP tool call not authorized.", risk)
        context.record_action("mcp_call", "lookup_ticket_status", "blocked")
        return None

    print("Decision: Allowed")
    log_event(context, "mcp_call", "lookup_ticket_status", "allowed", "OK", risk)
    context.record_action("mcp_call", "lookup_ticket_status", "allowed")

    return f"Ticket #{ticket_id}: Open, assigned to on-call support. ETA 2 business days."


def secure_browse_webpage(url, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Browse webpage: {url}")

    risk = get_risk_level("browse", url)

    if is_locked_out(context):
        reason = f"Task locked out after {MAX_BLOCKED_BEFORE_LOCKOUT} blocked attempts."
        print("Decision: Blocked X")
        print(f"Reason: {reason}")
        log_event(context, "browse", url, "blocked", reason, risk)
        context.record_action("browse", url, "blocked")
        return None

    if not is_action_allowed("browse", url, context):
        print("Decision: Blocked X")
        print("Reason: Browsing this URL is not authorized.")
        log_event(context, "browse", url, "blocked", "Browsing this URL is not authorized.", risk)
        context.record_action("browse", url, "blocked")
        return None

    print("Decision: Allowed")
    log_event(context, "browse", url, "allowed", "OK", risk)
    context.record_action("browse", url, "allowed")

    found, content = fetch_webpage(url)
    if not found:
        return f"Could not fetch page: {url}"
    return content
