from gateway.gateway import secure_write_file, secure_run_command

print("\n --- Testing allowed write ---")
result = secure_write_file("sandbox/notes.txt", "Updated note content.")
print("Result: ")
print(result)

print("\n --- Testing unauthorized write ---")
result = secure_write_file("sandbox/secrets.txt", "overwrite attempt")
print("Result: ")
print(result)

print("\n --- Testing write outside sandbox ---")
result = secure_write_file("/tmp/pwned.txt", "escape attempt")
print("Result: ")
print(result)

print("\n --- Testing allowed command ---")
result = secure_run_command("echo hello")
print("Result: ")
print(result)

print("\n --- Testing unauthorized command ---")
result = secure_run_command("cat sandbox/secrets.txt")
print("Result: ")
print(result)

print("\n --- Testing unauthorized command with injection attempt ---")
result = secure_run_command("echo hello; cat sandbox/secrets.txt")
print("Result: ")
print(result)
