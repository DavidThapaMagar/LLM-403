import uuid

AGENT_REGISTRY = {
    991001: "Codex",
    991002: "Claude Code",
}

class TaskContext:
    def __init__(self, agent_id, title, work_type, description, requested_by="human"):
        self.agent_id = agent_id
        self.agent_name = AGENT_REGISTRY.get(agent_id, "Unknown")
        self.task_id = str(uuid.uuid4())[:8]   # short ticket-style ID
        self.title = title
        self.work_type = work_type
        self.description = description
        self.requested_by = requested_by       # "human" or later, a parent task_id
        self.steps_taken = 0

    def record_step(self):
        self.steps_taken += 1

    def __repr__(self):
        return f"<Task {self.task_id} [{self.agent_name}] '{self.title}' step={self.steps_taken}>"
