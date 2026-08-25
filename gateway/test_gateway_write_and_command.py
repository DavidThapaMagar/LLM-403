from gateway.gateway import secure_write_file, secure_run_command
from gateway.context import TaskContext

context = TaskContext(
    agent_id=991002,
    title="Test: gateway write/command",
    work_type="test",
    description="Manual gateway write/command test",
)

print("\n --- Testing allowed write ---")
result = secure_write_file("sandbox/notes.txt", "Updated note content.", context)
print("Result: ")
print(result)

print("\n --- Testing unauthorized write ---")
result = secure_write_file("sandbox/secrets.txt", "overwrite attempt", context)
print("Result: ")
print(result)

print("\n --- Testing write outside sandbox ---")
result = secure_write_file("/tmp/pwned.txt", "escape attempt", context)
print("Result: ")
print(result)

print("\n --- Testing allowed command ---")
result = secure_run_command("echo hello", context)
print("Result: ")
print(result)

print("\n --- Testing unauthorized command ---")
result = secure_run_command("cat sandbox/secrets.txt", context)
print("Result: ")
print(result)

print("\n --- Testing unauthorized command with injection attempt ---")
result = secure_run_command("echo hello; cat sandbox/secrets.txt", context)
print("Result: ")
print(result)
