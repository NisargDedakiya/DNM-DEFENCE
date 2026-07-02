"""
Authentication & authorization.

Three roles:
  - admin/analyst: your team. Full access across all clients (analyst
    just can't manage other users).
  - client: a client-side portal user, hard-scoped to their own
    client_id. Every {client_id} path param is checked against the
    token's client_id for this role — a client user literally cannot
    construct a URL that reads another client's data.

Tokens are short-lived JWTs (access token only, no refresh token
rotation yet — see roadmap note in README for that upgrade).
"""
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.models import User, UserRole

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# A pre-computed bcrypt hash of a random value, used to keep login response
# time constant whether or not the email exists — prevents timing-based
# user enumeration (verify_password against a real hash vs. skipping the
# hash entirely takes measurably different time).
_DUMMY_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEeO7VyzVj9weeQZQmWQq3M4EquHBz6dHFO"

ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 hours
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return pwd_context.hash(password[:72])  # bcrypt silently truncates beyond 72 bytes -- truncate explicitly and consistently


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain[:72], hashed)


def verify_password_constant_time(plain: str | None, hashed: str | None) -> bool:
    """Always runs a real bcrypt comparison, even with no real hash, so response timing doesn't leak whether the account exists."""
    return pwd_context.verify((plain or "")[:72], hashed or _DUMMY_HASH)


def create_access_token(user: User) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user.id, "email": user.email, "role": user.role.value,
        "client_id": user.client_id, "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token",
                             headers={"WWW-Authenticate": "Bearer"})


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated",
                             headers={"WWW-Authenticate": "Bearer"})
    payload = decode_token(token)
    user = db.query(User).get(payload.get("sub"))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    return user


def require_staff(user: User = Depends(get_current_user)) -> User:
    """Admin or analyst only — blocks client-role users from staff-only actions (e.g. onboarding a new client)."""
    if user.role not in (UserRole.admin, UserRole.analyst):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Staff access required")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin access required")
    return user


def require_client_access(client_id: str, user: User = Depends(get_current_user)) -> User:
    """
    The core tenant-isolation check. Staff (admin/analyst) can access any
    client. A client-role user can only access the client_id embedded in
    their own token — this is what actually prevents cross-client data
    leaks, not just UI hiding.
    """
    if user.role in (UserRole.admin, UserRole.analyst):
        return user
    if user.role == UserRole.client and user.client_id == client_id:
        return user
    raise HTTPException(status.HTTP_403_FORBIDDEN, "You do not have access to this client's data")
