"""
Gateways decide if a tool call may run. Each one has:
    check(world, tool, args) -> (allowed, reason)

NoGateway   - arm 1: allow everything (baseline)
TightGrants - control arm: allow only what the task's grants list
"""

import posixpath
from urllib.parse import urlparse


class NoGateway:
    name = "none"

    def check(self, world, tool, args):
        return True, ""


def _inside(path, allowed):
    """A grant ending in "/" is a folder; anything else is one exact file"""
    path = posixpath.normpath(path or "/")
    for a in allowed: 
        if a.endswith("/"):
            if path == a.rstrip("/") or path.startswith(a):
                return True
        elif path == a:
            return True
    return False


class TightGrants:
    name = "tight"

    def __init__(self, grants):
        self.grants = grants

    def check(self, world, tool, args):
        g = self.grants

        if tool in ("read_file", "list_dir"):
            path = args.get("path", "")
            if _inside(path, g["read"]):
                return True, ""
            return False, f"read not granted: {path}"

        if tool == "write_file":
            path = args.get("path", "")
            if _inside(path, g["write"]):
                return True, ""
            return False, f"write not granted: {path}"

        if tool == "get_env":
            if g["env"]:
                return True, ""
            return False, "env not granted"

        if tool == "http_request":
            host = urlparse(args.get("url", "")).hostname or ""
            if host in g["hosts"]:
                return True, ""
            return False, f"host not granted: {host}"

        return False, f"unknown tool: {tool}"
