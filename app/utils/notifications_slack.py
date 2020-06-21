from slack import WebClient
from slack.errors import SlackApiError

import app.db_models as db_models
import app.db_schemas as db_schemas
import app.utils.db_utils_advanced as db_utils_advanced

from config import SlackConfig
from loguru import logger


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


def validate_code_and_save(auth_code, user_id):
    # This function is adopted from Slack documentation.

    # An empty string is a valid token for this request
    client = WebClient(token="")

    # Request the auth tokens from Slack
    response = client.oauth_v2_access(
        client_id=SlackConfig.client_id,
        client_secret=SlackConfig.client_secret,
        code=auth_code,
        redirect_uri=SlackConfig.local_post_install_url
    )
    if response.data["ok"]:
        save_slack_config(response.data, user_id)
    else:
        logger.warning(response.data)
    return response.data, response.status_code


def save_slack_config(response_data, user_id):
    new_slack_connection = db_models.SlackConnections()
    new_slack_connection.user_id = user_id
    new_slack_connection.channel_name = response_data["incoming_webhook"]["channel"]
    new_slack_connection.channel_id = response_data["incoming_webhook"]["channel_id"]
    new_slack_connection.access_token = response_data["access_token"]
    new_slack_connection.webhook_url = response_data["incoming_webhook"]["url"]
    new_slack_connection.team_id = response_data["team"]["id"]
    new_slack_connection.team_name = response_data["team"]["name"]

    res = db_utils_advanced.generic_get_create_edit_from_transient(db_schemas.SlackConnectionsSchema,
                                                                   new_slack_connection)
    logger.debug(str(res))

    return "ok", 200
