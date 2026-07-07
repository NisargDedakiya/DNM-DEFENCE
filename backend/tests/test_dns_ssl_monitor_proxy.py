from unittest.mock import MagicMock, patch

from app.services.dns_ssl_monitor import _get_https_proxy_url, _connect_via_proxy, _open_tcp_connection


def test_get_https_proxy_url_returns_none_when_unset(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    assert _get_https_proxy_url() is None


def test_get_https_proxy_url_reads_https_proxy_env_var(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:8080")
    assert _get_https_proxy_url() == "http://proxy.internal:8080"


def test_get_https_proxy_url_ignores_non_http_scheme(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "socks5://proxy.internal:1080")
    assert _get_https_proxy_url() is None


def test_connect_via_proxy_sends_connect_request_and_returns_socket_on_200():
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b"HTTP/1.1 200 Connection Established\r\n\r\n"
    with patch("app.services.dns_ssl_monitor.socket.create_connection", return_value=fake_sock) as mock_create:
        result = _connect_via_proxy("http://proxy.internal:8080", "example.com", 443, timeout=5)
    assert result is fake_sock
    mock_create.assert_called_once_with(("proxy.internal", 8080), timeout=5)
    sent = fake_sock.sendall.call_args.args[0]
    assert b"CONNECT example.com:443 HTTP/1.1" in sent


def test_connect_via_proxy_raises_on_non_200_response():
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b"HTTP/1.1 403 Forbidden\r\n\r\n"
    with patch("app.services.dns_ssl_monitor.socket.create_connection", return_value=fake_sock):
        try:
            _connect_via_proxy("http://proxy.internal:8080", "example.com", 443, timeout=5)
            assert False, "expected ConnectionError"
        except ConnectionError:
            pass
    fake_sock.close.assert_called_once()


def test_open_tcp_connection_uses_direct_socket_without_proxy(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    with patch("app.services.dns_ssl_monitor.socket.create_connection", return_value=MagicMock()) as mock_create:
        _open_tcp_connection("example.com", 443, timeout=5)
    mock_create.assert_called_once_with(("example.com", 443), timeout=5)


def test_open_tcp_connection_tunnels_through_proxy_when_configured(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:8080")
    with patch("app.services.dns_ssl_monitor._connect_via_proxy", return_value=MagicMock()) as mock_proxy_connect:
        _open_tcp_connection("example.com", 443, timeout=5)
    mock_proxy_connect.assert_called_once_with("http://proxy.internal:8080", "example.com", 443, 5)
