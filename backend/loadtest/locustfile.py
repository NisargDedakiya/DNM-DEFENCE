"""
Load/performance testing with Locust. Simulates realistic portal traffic
patterns rather than hammering a single endpoint -- a security portal's
actual load looks like staff checking dashboards and findings lists, not
constant writes.

Usage:
    1. Get a real auth token first (see README's "Run it" section for
       the login curl example), export it:
         export LOCUST_AUTH_TOKEN="eyJ..."
         export LOCUST_CLIENT_ID="<a real client_id from your DB>"
    2. Run:
         locust -f loadtest/locustfile.py --host http://localhost:8000

Then open http://localhost:8089 to configure user count/spawn rate and
watch live latency/failure-rate charts. Start small (10-20 users) against
a local dev instance before pointing this at anything resembling
production, and never run this against infrastructure you don't own.
"""
import os

from locust import HttpUser, task, between

AUTH_TOKEN = os.environ.get("LOCUST_AUTH_TOKEN", "")
CLIENT_ID = os.environ.get("LOCUST_CLIENT_ID", "")


class PortalUser(HttpUser):
    """Simulates a staff user checking in on a client's security posture -- the most common real traffic pattern."""
    wait_time = between(1, 4)  # seconds between actions, mimicking human click pacing rather than a tight loop

    def on_start(self):
        self.headers = {"Authorization": f"Bearer {AUTH_TOKEN}"} if AUTH_TOKEN else {}

    @task(5)
    def view_health(self):
        # Unauthenticated, high-frequency in reality (load balancer polling) -- weighted heavily on purpose
        self.client.get("/health", name="/health")

    @task(3)
    def list_clients(self):
        self.client.get("/api/clients", headers=self.headers, name="/api/clients [list]")

    @task(4)
    def view_client_findings(self):
        if CLIENT_ID:
            self.client.get(f"/api/clients/{CLIENT_ID}/findings", headers=self.headers, name="/api/clients/{id}/findings")

    @task(3)
    def view_client_assets(self):
        if CLIENT_ID:
            self.client.get(f"/api/clients/{CLIENT_ID}/assets", headers=self.headers, name="/api/clients/{id}/assets")

    @task(2)
    def view_scans(self):
        if CLIENT_ID:
            self.client.get(f"/api/clients/{CLIENT_ID}/scans", headers=self.headers, name="/api/clients/{id}/scans")

    @task(2)
    def view_compliance_summary(self):
        if CLIENT_ID:
            self.client.get(f"/api/clients/{CLIENT_ID}/compliance/summary", headers=self.headers, name="/api/clients/{id}/compliance/summary")

    @task(1)
    def view_reports(self):
        if CLIENT_ID:
            self.client.get(f"/api/clients/{CLIENT_ID}/reports", headers=self.headers, name="/api/clients/{id}/reports")


class AuthStressUser(HttpUser):
    """
    Separate user class specifically for testing login endpoint behavior
    under load -- run this in isolation (not mixed with PortalUser) to
    verify the rate limiter holds up correctly under concurrent load
    rather than only single-request testing.
    """
    wait_time = between(0.5, 1.5)

    @task
    def attempt_login(self):
        self.client.post(
            "/api/auth/login",
            data={"username": "loadtest@nonexistent.example", "password": "wrong"},
            name="/api/auth/login [expect 401 or 429]",
        )
