ALLOWED_FILES = ["sandbox/notes.txt",
                 "attacks/malicious_notes.txt",
                 "attacks/malicious_notes_v2.txt",
                 "attacks/malicious_notes_v3.txt",
                 "attacks/malicious_notes_v4.txt",
                 "attacks/malicious_notes_v5.txt",
                 "attacks/malicious_notes_v6.txt"
                ]

ALLOWED_WRITE_FILES = ["sandbox/notes.txt"]

def is_file_allowed(path):
    return path in ALLOWED_FILES

def is_write_allowed(path):
    return path in ALLOWED_WRITE_FILES

ALLOWED_COMMANDS = ["echo hello"]

def is_command_allowed(command):
    return command in ALLOWED_COMMANDS
