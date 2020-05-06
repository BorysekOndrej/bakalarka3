import app.utils.notifications_mail as notifications_mail


def schedule_notifications(changed_targets):
    send_notifications()


def send_notifications(planned_notifications=None):
    notifications_mail.send_mail("contact+bakalarka@borysek.net", "Subject1", "Body1")
