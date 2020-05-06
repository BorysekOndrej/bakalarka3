import smtplib, ssl
from config import MailConfig


# based on https://realpython.com/python-send-email/
def send_mail(recipient, subject, body):

    # context = ssl.create_default_context()
    # with smtplib.SMTP_SSL(MailConfig.hostname, MailConfig.port, context=context) as server:

    with smtplib.SMTP(MailConfig.hostname, MailConfig.port) as server:
        # server.login(MailConfig.username, MailConfig.password)

        message = f"""\
        Subject: {subject}

        {body}"""

        server.sendmail(MailConfig.sender_email, recipient, message)

        server.quit()
