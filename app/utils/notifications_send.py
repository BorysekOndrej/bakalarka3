from notifiers import get_notifier
import app.db_models as db_models


def slack_send_msg(slack_configuration: db_models.SlackConnections, msg: str):
    return slack_send_msg_via_webhook(slack_configuration.webhook_url, msg)


def slack_send_msg_via_webhook(webhook: str, msg: str):
    p = get_notifier('slack')
    return p.notify(webhook_url=webhook, message=msg)

