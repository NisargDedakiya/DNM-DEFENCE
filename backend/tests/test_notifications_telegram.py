from unittest.mock import MagicMock, patch

from app.services import notifications


def test_send_telegram_message_skips_without_token():
    with patch("app.services.notifications.settings") as mock_settings:
        mock_settings.TELEGRAM_BOT_TOKEN = ""
        with patch("app.services.notifications.httpx.post") as mock_post:
            result = notifications.send_telegram_message("chat123", "hello")
    mock_post.assert_not_called()
    assert result is False


def test_send_telegram_message_skips_without_chat_id():
    with patch("app.services.notifications.settings") as mock_settings:
        mock_settings.TELEGRAM_BOT_TOKEN = "fake-token"
        with patch("app.services.notifications.httpx.post") as mock_post:
            result = notifications.send_telegram_message("", "hello")
    mock_post.assert_not_called()
    assert result is False


def test_send_telegram_message_success():
    resp = MagicMock()
    resp.status_code = 200
    with patch("app.services.notifications.settings") as mock_settings:
        mock_settings.TELEGRAM_BOT_TOKEN = "fake-token"
        with patch("app.services.notifications.httpx.post", return_value=resp) as mock_post:
            result = notifications.send_telegram_message("chat123", "hello")
    assert result is True
    call_url = mock_post.call_args.args[0]
    assert "fake-token" in call_url
    assert mock_post.call_args.kwargs["json"]["chat_id"] == "chat123"


def test_send_telegram_message_failure_status():
    resp = MagicMock()
    resp.status_code = 400
    resp.text = "Bad Request"
    with patch("app.services.notifications.settings") as mock_settings:
        mock_settings.TELEGRAM_BOT_TOKEN = "fake-token"
        with patch("app.services.notifications.httpx.post", return_value=resp):
            result = notifications.send_telegram_message("chat123", "hello")
    assert result is False
