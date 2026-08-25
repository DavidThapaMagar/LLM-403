from gateway.gateway import secure_read_file
from gateway.context import TaskContext

context = TaskContext(
    agent_id=991002,
    title="Test: gateway file access",
    work_type="test",
    description="Manual gateway test",
)

print("\n --- Testing allowed file ---")

result = secure_read_file("sandbox/notes.txt", context)

print("Result: ")
print(result)

print("\n --- Testing unauthorized file ---")

result = secure_read_file("sandbox/secrets.txt", context)

print("Result: ")
print(result)
