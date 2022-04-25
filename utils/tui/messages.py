from textual import events
from textual._types import MessageTarget
from textual.message import Message

from utils.supervisor import AttackSupervisorState


class SupervisorStateUpdated(Message, bubble=True):
    def __init__(self, sender: MessageTarget, new_state: AttackSupervisorState):
        Message.__init__(self, sender)
        self.new_state = new_state


class SelectedAttackIndexUpdated(Message, bubble=True):
    def __init__(self, sender: MessageTarget, new_index: int):
        Message.__init__(self, sender)
        self.new_index = new_index


class SelectedMenuIndexUpdated(Message, bubble=True):
    def __init__(self, sender: MessageTarget, new_index: int):
        Message.__init__(self, sender)
        self.new_index = new_index


class KeyPressed(Message):
    def __init__(self, sender: MessageTarget, key: events.Key):
        Message.__init__(self, sender)
        self.key = key


