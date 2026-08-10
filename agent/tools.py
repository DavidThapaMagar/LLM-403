def read_file(path):
	with open(path, "r") as file:
		return file.read()

def write_file(path, content):
	with open(path, "w") as file:
		file.write(content)
	return f"Successfully wrote to {path}"

def run_command(command):
	import subprocess

	result = subprocess.run(
		command,
		shell = True,
		capture_output = True,
		text = True
	)
	return result.stdout
