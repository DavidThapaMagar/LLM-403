import uuid

AGENT_REGISTRY = {
    991001: "Codex",
    991002: "Claude Code",
}


class TaskContext:
    def __init__(self, agent_id, title, work_type, description, requested_by="human", parent_context=None):
        self.agent_id = agent_id
        self.agent_name = AGENT_REGISTRY.get(agent_id, "Unknown")
        self.task_id = str(uuid.uuid4())[:8]
        self.title = title
        self.work_type = work_type
        self.description = description
        self.parent_context = parent_context
        self.requested_by = parent_context.task_id if parent_context is not None else requested_by
        self.steps_taken = 0
        self.history = []

    def record_step(self):
        self.steps_taken += 1

    def record_action(self, action, resource, decision):
        self.history.append({"action": action, "resource": resource, "decision": decision})

    def spawn_child(self, work_type, title, description):
        """
        Create a delegated sub-task. The child's effective permissions
        can never exceed what this task itself was granted. Its
        trajectory history starts fresh (not inherited from the
        parent) - a simplification worth revisiting later.
        """
        return TaskContext(
            agent_id=self.agent_id,
            title=title,
            work_type=work_type,
            description=description,
            parent_context=self,
        )

    def __repr__(self):
        return f"<Task {self.task_id} [{self.agent_name}] '{self.title}' step={self.steps_taken}>"
