from enum import Enum
from typing import Optional


class Channels (Enum):
    Mail = 1
    Slack = 2


class Notification(object):
    def __init__(self, channel: Channels, text: Optional[str] = None):
        self.event_id: int = None  # this is so that we can match Slack and Mail notification for the same event
        self.channel: Channels = channel
        self.text: str = text or ""


class MailNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Mail)
        self.recipient_email: str = None
        self.subject: str = None


class SlackNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Slack)
        self.connection_id: int = None
