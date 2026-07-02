"""
One-time bootstrap: creates the first admin account. Every subsequent
staff account is created via POST /api/auth/register-staff (which
requires an existing admin token) — this script exists only to solve
that chicken-and-egg problem on a fresh database.

Usage (inside the api container or with the right DATABASE_URL set):
    python -m app.scripts.create_admin admin@yourcompany.com
"""
import getpass
import sys

from app.core.auth import hash_password
from app.core.database import SessionLocal
from app.models.models import User, UserRole


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m app.scripts.create_admin <email>")
        sys.exit(1)

    import os
    email = sys.argv[1]
    password = os.environ.get("ADMIN_PASSWORD")
    if not password:
        password = getpass.getpass("Password: ")
    confirm = os.environ.get("ADMIN_PASSWORD")
    if not confirm:
        confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        sys.exit(1)

    db = SessionLocal()
    try:
        if db.query(User).filter_by(email=email).first():
            print(f"A user with email {email} already exists.")
            sys.exit(1)
        user = User(email=email, hashed_password=hash_password(password), role=UserRole.admin)
        db.add(user)
        db.commit()
        print(f"Admin account created: {email}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
