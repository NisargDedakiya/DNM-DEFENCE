import os
from unittest.mock import MagicMock, patch

from app.services.dfir_log_analysis import (
    parse_cloudtrail_json, parse_azure_activity_log, parse_gcp_audit_log,
    parse_syslog, parse_web_access_log, parse_palo_alto_log,
    detect_auth_anomalies, extract_iocs, generate_log_narrative,
)


def test_parse_cloudtrail_json_extracts_core_fields():
    data = {"Records": [
        {"eventTime": "2026-01-01T00:00:00Z", "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
         "sourceIPAddress": "1.2.3.4", "userIdentity": {"userName": "alice"}, "errorCode": "Failed authentication"},
        {"eventTime": "2026-01-01T00:05:00Z", "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com",
         "sourceIPAddress": "5.6.7.8", "userIdentity": {"userName": "bob"}},
    ]}
    events = parse_cloudtrail_json(data)
    assert len(events) == 2
    assert events[0]["outcome"] == "failure"
    assert events[1]["outcome"] == "success"
    assert events[0]["user"] == "alice"


def test_parse_cloudtrail_json_flags_console_login_failure_without_error_code():
    """Real AWS CloudTrail ConsoleLogin failures set responseElements.ConsoleLogin
    to "Failure" and carry no errorCode at all -- this is the actual wire format
    for a brute-forced console login attempt, the most common real-world case."""
    data = {"Records": [
        {"eventTime": "2026-01-01T00:00:00Z", "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
         "sourceIPAddress": "1.2.3.4", "userIdentity": {"userName": "alice"},
         "responseElements": {"ConsoleLogin": "Failure"}},
    ]}
    events = parse_cloudtrail_json(data)
    assert events[0]["outcome"] == "failure"


def test_parse_azure_activity_log_extracts_core_fields():
    data = {"value": [
        {"eventTimestamp": "2026-01-01T00:00:00Z", "operationName": {"value": "Microsoft.Compute/vm/write"},
         "caller": "alice@example.com", "callerIpAddress": "1.2.3.4", "resourceId": "/vm/1", "status": {"value": "Failed"}},
    ]}
    events = parse_azure_activity_log(data)
    assert len(events) == 1
    assert events[0]["outcome"] == "failure"
    assert events[0]["user"] == "alice@example.com"


def test_parse_gcp_audit_log_handles_entries_key():
    data = {"entries": [
        {"timestamp": "2026-01-01T00:00:00Z",
         "protoPayload": {"methodName": "google.iam.SetPolicy", "authenticationInfo": {"principalEmail": "alice@example.com"},
                           "requestMetadata": {"callerIp": "1.2.3.4"}, "status": {}}},
    ]}
    events = parse_gcp_audit_log(data)
    assert len(events) == 1
    assert events[0]["outcome"] == "success"
    assert events[0]["source_ip"] == "1.2.3.4"


def test_parse_gcp_audit_log_handles_bare_list():
    data = [{"timestamp": "2026-01-01T00:00:00Z", "protoPayload": {"methodName": "x", "status": {"code": 7}}}]
    events = parse_gcp_audit_log(data)
    assert events[0]["outcome"] == "failure"


def test_parse_syslog_extracts_failed_ssh_login():
    line = "Jan  1 00:00:01 fileserver sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
    events = parse_syslog(line)
    assert len(events) == 1
    assert events[0]["source_ip"] == "1.2.3.4"
    assert events[0]["outcome"] == "failure"
    assert events[0]["host"] == "fileserver"


def test_parse_syslog_ignores_unmatched_lines():
    assert parse_syslog("not a syslog line at all") == []


def test_parse_web_access_log_extracts_combined_format():
    line = '1.2.3.4 - - [10/Oct/2023:13:55:36 +0000] "GET /admin HTTP/1.1" 404 162 "-" "curl/7.68.0"'
    events = parse_web_access_log(line)
    assert len(events) == 1
    assert events[0]["source_ip"] == "1.2.3.4"
    assert events[0]["outcome"] == "failure"


def test_parse_palo_alto_log_basic_csv():
    line = "2026/01/01 00:00:00,1.2.3.4,fs01,deny,extra_field"
    events = parse_palo_alto_log(line)
    assert len(events) == 1
    assert events[0]["source_ip"] == "1.2.3.4"
    assert events[0]["outcome"] == "failure"


def test_detect_auth_anomalies_flags_repeated_failures():
    events = [{"outcome": "failure", "user": "admin", "source_ip": "1.2.3.4", "timestamp": None} for _ in range(6)]
    anomalies = detect_auth_anomalies(events, failure_threshold=5)
    assert any(a["anomaly_type"] == "repeated_auth_failure" and a["subject"] == "admin" for a in anomalies)


def test_detect_auth_anomalies_flags_off_hours_access():
    events = [{"outcome": "success", "user": "alice", "source_ip": "1.2.3.4", "timestamp": "2026-01-01T03:00:00Z"}]
    anomalies = detect_auth_anomalies(events)
    assert any(a["anomaly_type"] == "off_hours_access" for a in anomalies)


def test_detect_auth_anomalies_quiet_on_normal_activity():
    events = [{"outcome": "success", "user": "alice", "source_ip": "1.2.3.4", "timestamp": "2026-01-01T14:00:00Z"}]
    assert detect_auth_anomalies(events) == []


def test_extract_iocs_finds_ips_and_dedupes():
    events = [
        {"source_ip": "1.2.3.4", "raw": "connection from 1.2.3.4 to evil.example.com", "event_type": "conn"},
        {"source_ip": "1.2.3.4", "raw": "connection from 1.2.3.4 to evil.example.com", "event_type": "conn"},
    ]
    iocs = extract_iocs(events)
    ips = [i for i in iocs if i["ioc_type"] == "ip" and i["value"] == "1.2.3.4"]
    domains = [i for i in iocs if i["ioc_type"] == "domain"]
    assert len(ips) == 1
    assert any(d["value"] == "evil.example.com" for d in domains)


def test_extract_iocs_finds_hashes():
    events = [{"source_ip": None, "raw": "dropped file with hash d41d8cd98f00b204e9800998ecf8427e", "event_type": "file_write"}]
    iocs = extract_iocs(events)
    assert any(i["ioc_type"] == "hash" for i in iocs)


def test_generate_log_narrative_grounded_in_events():
    events = [{"timestamp": "2026-01-01T00:00:00Z", "event_type": "ConsoleLogin", "user": "alice", "source_ip": "1.2.3.4", "outcome": "failure"}]
    anomalies = [{"anomaly_type": "repeated_auth_failure", "subject": "alice", "count": 6, "detail": "6 failed logins"}]
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="Narrative body.")]
    with patch("app.services.dfir_log_analysis._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        narrative = generate_log_narrative(events, anomalies)
    assert narrative == "Narrative body."
    prompt = mock_client_factory.return_value.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "ConsoleLogin" in prompt
    assert "6 failed logins" in prompt


def test_generate_log_narrative_handles_no_events():
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="No activity found.")]
    with patch("app.services.dfir_log_analysis._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        narrative = generate_log_narrative([], [])
    assert narrative == "No activity found."


def test_parse_evtx_raises_on_missing_file():
    from app.services.dfir_log_analysis import parse_evtx
    try:
        parse_evtx("/nonexistent/path.evtx")
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass
