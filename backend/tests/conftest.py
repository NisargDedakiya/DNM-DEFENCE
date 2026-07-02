"""
Shared pytest fixtures. Uses ONE sqlite database for the whole test
session (set via env before any app module is imported, avoiding
Python's import-caching issues with per-test module reloading), and
resets tables between tests by dropping and recreating them. This keeps
tests isolated without needing Postgres/Redis, so the suite runs in CI
without the full docker-compose stack.
"""
import os
import uuid

_TEST_DB_PATH = os.path.join(os.path.dirname(__file__), "_pytest_session.db")
if os.path.exists(_TEST_DB_PATH):
    os.remove(_TEST_DB_PATH)

os.environ["ENV"] = "development"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_PATH}"
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
os.environ.setdefault("ENCRYPTION_KEY", "")

import pytest
from fastapi.testclient import TestClient

from app.core.database import Base, engine
from app.main import app as fastapi_app


@pytest.fixture
def client():
    """Fresh tables and a reset rate limiter for every test -- otherwise the shared in-memory limiter state (correct behavior in production) causes later tests to spuriously hit 429s from earlier tests' login attempts."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    from app.core.security_middleware import limiter
    limiter.reset()

    with TestClient(fastapi_app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def admin_user(client):
    """Creates an admin user directly in the DB and returns its credentials + a ready-to-use auth header."""
    from app.core.database import SessionLocal
    from app.core.auth import hash_password
    from app.models.models import User, UserRole

    email, password = "admin@test.local", "TestPassword123!"
    db = SessionLocal()
    db.add(User(id=str(uuid.uuid4()), email=email, hashed_password=hash_password(password), role=UserRole.admin))
    db.commit()
    db.close()

    resp = client.post("/api/auth/login", data={"username": email, "password": password})
    token = resp.json()["access_token"]
    return {"email": email, "password": password, "token": token, "headers": {"Authorization": f"Bearer {token}"}}
