ALLOWED_FILES = ["sandbox/notes.txt",
                 "attacks/malicious_notes.txt",
                 "attacks/malicious_notes_v2.txt"
                ]

def is_file_allowed(path):
    return path in ALLOWED_FILES
