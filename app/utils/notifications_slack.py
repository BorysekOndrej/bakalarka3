from slack import WebClient
from slack.errors import SlackApiError


def send_message(msg, api_token=None, channel='#notificationstest'):
    try:
        client = WebClient(token=api_token)
        response = client.chat_postMessage(
            channel=channel,
            text=msg)
        assert response["message"]["text"] == msg
    except SlackApiError as e:
        # You will get a SlackApiError if "ok" is False
        assert e.response["ok"] is False
        assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
        print(f"Got an error: {e.response['error']}")
        return False
    return True
