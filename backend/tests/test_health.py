def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"


def test_health_has_no_auth_requirement(client):
    """Health check must stay reachable without a token — it's what load balancers poll."""
    r = client.get("/health")
    assert r.status_code != 401
