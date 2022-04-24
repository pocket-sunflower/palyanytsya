from textual.message import Message

from utils.supervisor import AttackSupervisorState


class SupervisorStateUpdated(Message, bubble=True):
    new_state: AttackSupervisorState

class TestFire(Message, bubble=True):
    pass
