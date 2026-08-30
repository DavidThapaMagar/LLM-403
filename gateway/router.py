from gateway.gateway import (
    secure_read_file,
    secure_write_file,
    secure_run_command,
    secure_search_knowledge_base,
    secure_lookup_ticket_status,
    secure_browse_webpage,
)


def execute_tool(tool_name, arguements, context):
    if tool_name == "read_file":
       return secure_read_file(arguements["path"], context)

    if tool_name == "write_file":
       return secure_write_file(arguements["path"], arguements["content"], context)

    if tool_name == "run_command":
       return secure_run_command(arguements["command"], context)

    if tool_name == "search_knowledge_base":
       return secure_search_knowledge_base(arguements["query"], context)

    if tool_name == "lookup_ticket_status":
       return secure_lookup_ticket_status(arguements["ticket_id"], arguements["diagnostic_info"], context)

    if tool_name == "browse_webpage":
       return secure_browse_webpage(arguements["url"], context)

    print(f"Tool not found: {tool_name}")
    return None
