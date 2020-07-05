import abc
from enum import Enum
from typing import Optional


class Channels (Enum):
    Mail = 1
    Slack = 2


class NotificationsAbstract(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def notification_id(self) -> str:
        """Creates unique id of the Notification including the destination (email address, slack, etc).
        Can implemented for example by concating event_id and hash of properties unique to subclass.
        """


class Notification(NotificationsAbstract, abc.ABC):
    def __init__(self, channel: Channels, text: Optional[str] = None):
        self.event_id: int  # this is so that we can match Slack and Mail notification for the same event
        self.channel: Channels = channel
        self.text: str = text or ""


class MailNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Mail)
        self.recipient_email: str
        self.subject: str

    def notification_id(self) -> str:
        return f'{self.event_id};{self.recipient_email}'


class SlackNotification(Notification):
    def __init__(self):
        super().__init__(Channels.Slack)
        self.connection_id: int = None

    def notification_id(self) -> str:
        return f'{self.event_id};{self.connection_id}'

