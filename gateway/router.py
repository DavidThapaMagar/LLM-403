from gateway.gateway import secure_read_file, secure_write_file, secure_run_command

def execute_tool(tool_name, arguements):
    if tool_name == "read_file":
       return secure_read_file(arguements["path"])
   
    if tool_name == "write_file":
       return secure_write_file(arguements["path"], arguements["content"])
   
    if tool_name == "run_command":
       return secure_run_command(arguements["command"])

    print(f"Tool not found: {tool_name}")
    return None
