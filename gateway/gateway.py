from .policy import is_file_allowed
from agent.tools import read_file

def secure_read_file(path):
    print(f"\n[SECURITY GATEWAY]")
    print(f"Requested file: {path}")

    if not is_file_allowed(path):
       print("Decision: Blocked X")
       print("Reason: File is not authorized.")
       return None

    print("Decision: Allowed")
    return read_file(path)
