from gateway.gateway import secure_read_file

def execute_tool(tool_name, arguements):
    if tool_name == "read_file":
       return secure_read_file(arguements["path"])
    
    print(f"Tool not found: {tool_name}")
    return None
