from app.services import mobile_traffic

SAMPLE_HAR = {
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/v1/users?id=42",
                    "headers": [{"name": "Authorization", "value": "Bearer abc.def.ghi"}],
                    "postData": {},
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "content": {"text": '{"email": "jane@example.com"}'},
                },
            },
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/v1/login",
                    "headers": [],
                    "postData": {"text": "api_key=sk_live_abcdef1234567890"},
                },
                "response": {"status": 200, "headers": [], "content": {"text": ""}},
            },
        ]
    }
}


def test_parse_har_flattens_entries():
    entries = mobile_traffic.parse_har(SAMPLE_HAR)
    assert len(entries) == 2
    assert entries[0]["method"] == "GET"
    assert entries[0]["url"] == "https://api.example.com/v1/users?id=42"


def test_discover_endpoints_dedupes_by_method_host_path():
    entries = mobile_traffic.parse_har(SAMPLE_HAR)
    endpoints = mobile_traffic.discover_endpoints(entries)
    assert len(endpoints) == 2
    paths = {e["path"] for e in endpoints}
    assert paths == {"/v1/users", "/v1/login"}
    users_ep = next(e for e in endpoints if e["path"] == "/v1/users")
    assert users_ep["query_params"] == ["id"]


def test_detect_sensitive_data_flags_jwt_email_and_api_key():
    entries = mobile_traffic.parse_har(SAMPLE_HAR)
    hits = mobile_traffic.detect_sensitive_data(entries)
    types_found = {h["type"] for h in hits}
    assert "email" in types_found
    assert "api_key_param" in types_found


def test_classify_auth_headers_splits_by_authorization_presence():
    entries = mobile_traffic.parse_har(SAMPLE_HAR)
    result = mobile_traffic.classify_auth_headers(entries)
    assert "https://api.example.com/v1/users?id=42" in result["authenticated_endpoints"]
    assert "https://api.example.com/v1/login" in result["unauthenticated_endpoints"]


def test_generate_openapi_lite_builds_paths_from_endpoints():
    endpoints = [{"method": "GET", "host": "api.example.com", "path": "/v1/users", "query_params": ["id"]}]
    doc = mobile_traffic.generate_openapi_lite(endpoints)
    assert doc["openapi"] == "3.0.0"
    assert "/v1/users" in doc["paths"]
    assert "get" in doc["paths"]["/v1/users"]


def test_analyze_har_import_end_to_end():
    result = mobile_traffic.analyze_har_import(SAMPLE_HAR)
    assert result["endpoint_count"] == 2
    assert len(result["discovered_endpoints"]) == 2
    assert len(result["sensitive_data_hits"]) > 0
    assert "authenticated_endpoints" in result["auth_classification"]
    assert result["openapi_lite"]["openapi"] == "3.0.0"


def test_analyze_har_import_accepts_json_string():
    import json
    result = mobile_traffic.analyze_har_import(json.dumps(SAMPLE_HAR))
    assert result["endpoint_count"] == 2
