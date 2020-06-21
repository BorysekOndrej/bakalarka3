from slack import WebClient
from slack.errors import SlackApiError

from config import SlackConfig


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


def finish_auth():
    # This function is adopted from Slack documentation.
    from flask import request

    # Retrieve the auth code from the request params
    auth_code = request.args['code']

    # An empty string is a valid token for this request
    client = WebClient(token="")

    # Request the auth tokens from Slack
    response = client.oauth_v2_access(
        client_id=SlackConfig.client_id,
        client_secret=SlackConfig.client_secret,
        code=auth_code,
        redirect_uri=SlackConfig.local_post_install_url
    )
    return response.data, response.status_code
