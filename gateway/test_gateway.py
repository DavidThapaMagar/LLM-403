from gateway.gateway import secure_read_file

print("\n --- Testing allowed file ---")

result = secure_read_file("sandbox/notes.txt")

print("Result: ")
print(result)

print("\n --- Testing unauthorized file ---")

result = secure_read_file("sandbox/secrets.txt")

print("Result: ")
print(result)
