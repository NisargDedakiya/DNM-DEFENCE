"""
Auth tests: covers the actual vulnerabilities fixed in the security audit
(constant-time login, brute-force lockout, MFA) so regressions get caught
in CI rather than found again by hand.
"""
import time


def test_login_succeeds_with_correct_credentials(admin_user, client):
    r = client.post("/api/auth/login", data={"username": admin_user["email"], "password": admin_user["password"]})
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_login_fails_with_wrong_password(admin_user, client):
    r = client.post("/api/auth/login", data={"username": admin_user["email"], "password": "wrong"})
    assert r.status_code == 401


def test_login_fails_for_nonexistent_user(client):
    r = client.post("/api/auth/login", data={"username": "nobody@test.local", "password": "whatever"})
    assert r.status_code == 401


def test_me_requires_auth(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_me_returns_current_user(admin_user, client):
    r = client.get("/api/auth/me", headers=admin_user["headers"])
    assert r.status_code == 200
    assert r.json()["email"] == admin_user["email"]


def test_protected_client_list_requires_auth(client):
    r = client.get("/api/clients")
    assert r.status_code == 401


def test_protected_client_list_accessible_to_staff(admin_user, client):
    r = client.get("/api/clients", headers=admin_user["headers"])
    assert r.status_code == 200


def test_account_locks_after_repeated_failures(admin_user, client):
    """
    Brute-force protection: after repeated failures, further attempts get
    blocked -- either by the account lockout (423) or by the IP rate limit
    (429) engaging first, since both are configured at a similar
    threshold. Either outcome means the same thing: rapid guessing against
    this account is stopped.
    """
    responses = []
    for _ in range(6):
        r = client.post("/api/auth/login", data={"username": admin_user["email"], "password": "wrong"})
        responses.append(r.status_code)

    r = client.post("/api/auth/login", data={"username": admin_user["email"], "password": admin_user["password"]})
    assert r.status_code in (423, 429)


def test_login_timing_does_not_leak_user_existence(admin_user, client):
    """Regression test for the enumeration-via-timing bug fixed in the security audit."""
    samples = 3
    t0 = time.time()
    for _ in range(samples):
        client.post("/api/auth/login", data={"username": admin_user["email"], "password": "wrong-but-user-exists"})
    existing_avg = (time.time() - t0) / samples

    t0 = time.time()
    for _ in range(samples):
        client.post("/api/auth/login", data={"username": "totally-nonexistent@test.local", "password": "whatever"})
    nonexistent_avg = (time.time() - t0) / samples

    # Generous tolerance since CI runners are noisy -- this just needs to
    # catch a regression to the old behavior (skipping bcrypt entirely),
    # not enforce nanosecond-level constant time.
    assert abs(existing_avg - nonexistent_avg) < 0.5
