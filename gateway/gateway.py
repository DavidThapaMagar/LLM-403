from .policy import is_action_allowed
from .events import log_event
from .risk import get_risk_level
from agent.tools import read_file, write_file, run_command


def secure_read_file(path, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested file: {path}")

    risk = get_risk_level("read", path)

    if not is_action_allowed("read", path, context):
        print("Decision: Blocked X")
        print("Reason: Read not authorized.")
        log_event(context, "read", path, "blocked", "Read not authorized.", risk)
        return None

    print("Decision: Allowed")
    log_event(context, "read", path, "allowed", "OK", risk)
    return read_file(path)


def secure_write_file(path, content, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested write: {path}")

    risk = get_risk_level("write", path)

    if not is_action_allowed("write", path, context):
        print("Decision: Blocked X")
        print("Reason: Write not authorized.")
        log_event(context, "write", path, "blocked", "Write not authorized.", risk)
        return None

    if not isinstance(content, str):
        reason = f"Content must be a string, got {type(content).__name__}."
        print("Decision: Blocked X")
        print(f"Reason: {reason}")
        log_event(context, "write", path, "blocked", reason, risk)
        return None

    print("Decision: Allowed")
    log_event(context, "write", path, "allowed", "OK", risk)
    return write_file(path, content)


def secure_run_command(command, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested command: {command}")

    risk = get_risk_level("command", command)

    if not is_action_allowed("command", command, context):
        print("Decision: Blocked X")
        print("Reason: Command not authorized.")
        log_event(context, "command", command, "blocked", "Command not authorized.", risk)
        return None

    print("Decision: Allowed")
    log_event(context, "command", command, "allowed", "OK", risk)
    return run_command(command)
