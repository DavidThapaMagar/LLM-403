from .policy import is_action_allowed
from agent.tools import read_file, write_file, run_command


def secure_read_file(path, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested file: {path}")

    if not is_action_allowed("read", path, context):
        print("Decision: Blocked X")
        print("Reason: Read not authorized.")
        return None

    print("Decision: Allowed")
    return read_file(path)


def secure_write_file(path, content, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested write: {path}")

    if not is_action_allowed("write", path, context):
        print("Decision: Blocked X")
        print("Reason: Write not authorized.")
        return None

    if not isinstance(content, str):
        print("Decision: Blocked X")
        print(f"Reason: Content must be a string, got {type(content).__name__}.")
        return None

    print("Decision: Allowed")
    return write_file(path, content)


def secure_run_command(command, context):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Task: {context.task_id} | Agent: {context.agent_name}")
    print(f"Requested command: {command}")

    if not is_action_allowed("command", command, context):
        print("Decision: Blocked X")
        print("Reason: Command not authorized.")
        return None

    print("Decision: Allowed")
    return run_command(command)
