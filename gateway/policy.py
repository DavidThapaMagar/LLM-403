ALLOWED_FILES = ["sandbox/notes.txt"]

def is_file_allowed(path):
    return path in ALLOWED_FILES
