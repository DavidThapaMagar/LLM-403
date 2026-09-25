"""
Replay a scripted trace against a fresh simulated world.

Run from repo root:
    python -m lab_v2.replay lab_v2/traces/legit_sales_report.json
    python -m lab_v2.replay lab_v2/traces/legit_sales_report.json tight
"""

import json
import sys

from .world import World
from .tools import execute
from .tasks import TASKS
from .gateways import NoGateway, TightGrants


def make_gateway(name, task):
    if name == "none":
        return NoGateway()
    if name == "tight":
        return TightGrants(task["grants"])
    raise SystemExit(f"unknown gateway: {name}")


def replay(trace, gateway):
    world = World()
    for step in trace["steps"]:
        result = execute(world, step["tool"], step["args"], gateway)
        print(f"{step['tool']}({step['args']}) -> {str(result)[:70]!r}")
    return world


def main(path, gateway_name="none"):
    with open(path) as f:
        trace = json.load(f)
    task = TASKS[trace["task_id"]]
    gateway = make_gateway(gateway_name, task)

    print(f"=== {trace['name']} ({trace['kind']}) | gateway: {gateway.name} ===")
    print(f"Task: {task['prompt']}\n")
    world = replay(trace, gateway)
    print(f"\nTask done: {task['check'](world)}")
    print(f"Denied calls: {world.denied}")
    print(f"Canaries seen by agent: {sorted(world.acquired) or 'none'}")
    print(f"Canaries leaked outside: {sorted(world.leaked_canaries()) or 'none'}")


if __name__ == "__main__":
    main(*sys.argv[1:])
