from tools import read_file, write_file, run_command

def main():
        print("=== Agent Security Lab ===")
        print("Available Tools")
        print("1. read_file")
        print("2. write_file")
        print("3. run_command")
        print()

        while True:
                choice = input("Choose a tool (or q to quit): ")
                if choice == "q":
                    break

                if choice == "1":
                    path = input("File path: ")
                    result = read_file(path)
                    print(result)

                elif choice == "2":
                    path = input("File path: ")
                    content = input("Content: ")
                    result = write_file(path, content)
                    print(result)

                elif choice == "3":
                    command = input("Command: ")
                    result = run_command
                    print(result)
                else:
                    print("Invalid Choice.")

if __name__ == "__main__":
        main()
