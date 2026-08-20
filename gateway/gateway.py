from .policy import is_file_allowed, is_write_allowed, is_command_allowed
from agent.tools import read_file, write_file, run_command

def secure_read_file(path):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Requested file: {path}")

    if not is_file_allowed(path):
       print("Decision: Blocked X")
       print("Reason: File is not authorized.")
       return None

    print("Decision: Allowed")
    return read_file(path)


def secure_write_file(path, content):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Requested write: {path}")

    if not is_write_allowed(path):
       print("Decision: Blocked X")
       print("Reason: File is not authorized for writing.")
       return None
    
    if not isinstance(content, str):
       print("Decision: Blocked X")
       print(f"Reason: Content must be a string, got {type(content).__name__}.")
       return None

    print("Decision: Allowed")
    return write_file(path, content)


def secure_run_command(command):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Requested command: {command}")

    if not is_command_allowed(command):
       print("Decision: Blocked X")
       print("Reason: Command is not authorized.")
       return None

    print("Decision: Allowed")
    return run_command(command)
