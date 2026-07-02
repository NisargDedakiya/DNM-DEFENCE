import base64
from datetime import datetime, timedelta
from io import BytesIO

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.auth import (
    hash_password, verify_password, verify_password_constant_time, create_access_token,
    get_current_user, require_admin, require_staff,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.security_middleware import limiter
from app.models.models import User, UserRole, Client

router = APIRouter(prefix="/api/auth", tags=["auth"])


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    role: str
    client_id: str | None
    mfa_enabled: bool


class StaffRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    role: UserRole = UserRole.analyst


class ClientUserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    client_id: str


class MfaVerify(BaseModel):
    code: str


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/login", response_model=TokenOut)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    OAuth2 password flow. Form fields: 'username' (email), 'password',
    and if the account has MFA enabled, append the 6-digit TOTP code to
    the password field separated by a colon, e.g. password="hunter2:123456"
    (this keeps the endpoint OAuth2-form-compatible without adding a
    non-standard field the spec doesn't define).

    Rate-limited (RATE_LIMIT_LOGIN) and brute-force protected: an account
    locks for LOGIN_LOCKOUT_MINUTES after LOGIN_LOCKOUT_ATTEMPTS
    consecutive failures, independent of the IP-based rate limit above.
    """
    raw_password = form.password
    mfa_code = None
    if ":" in raw_password:
        raw_password, mfa_code = raw_password.rsplit(":", 1)

    user = db.query(User).filter_by(email=form.username).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(423, f"Account temporarily locked due to repeated failed logins. Try again in {remaining} minute(s).")

    def _fail(reason: str):
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= settings.LOGIN_LOCKOUT_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
                user.failed_login_attempts = 0
            db.commit()
        log_action(db, action="auth.login_failed", detail={"email": form.username, "reason": reason}, ip_address=_client_ip(request))
        raise HTTPException(401, "Incorrect email, password, or MFA code")

    password_ok = verify_password_constant_time(raw_password, user.hashed_password if user else None)
    if not user or not password_ok or not user.is_active:
        return _fail("bad_credentials")

    if settings.MFA_REQUIRED_FOR_STAFF and user.role in (UserRole.admin, UserRole.analyst) and not user.mfa_enabled:
        raise HTTPException(403, "MFA enrollment required for staff accounts before login. Call /api/auth/mfa/enroll after an initial password-only login is disabled.")

    if user.mfa_enabled:
        if not mfa_code or not pyotp.TOTP(user.mfa_secret).verify(mfa_code, valid_window=1):
            return _fail("bad_mfa_code")

    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    log_action(db, action="auth.login_success", user=user, ip_address=_client_ip(request))
    return TokenOut(access_token=create_access_token(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.post("/mfa/enroll")
def enroll_mfa(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Step 1 of MFA enrollment: generates a TOTP secret and returns a QR
    code (base64 PNG) for the user's authenticator app. MFA isn't enabled
    yet -- call /mfa/confirm with a valid code to activate it.
    """
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    db.commit()

    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=settings.APP_NAME)
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    log_action(db, action="auth.mfa_enroll_started", user=user, ip_address=_client_ip(request))
    return {"secret": secret, "qr_code_png_base64": qr_b64, "otpauth_uri": uri}


@router.post("/mfa/confirm")
@limiter.limit("10/minute")
def confirm_mfa(payload: MfaVerify, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Step 2: verifies the user can produce a valid code, then flips mfa_enabled on. Rate-limited -- a 6-digit TOTP code is brute-forceable without this."""
    if not user.mfa_secret:
        raise HTTPException(400, "Call /mfa/enroll first")
    if not pyotp.TOTP(user.mfa_secret).verify(payload.code, valid_window=1):
        raise HTTPException(400, "Invalid MFA code")
    user.mfa_enabled = True
    db.commit()
    log_action(db, action="auth.mfa_enabled", user=user, ip_address=_client_ip(request))
    return {"message": "MFA enabled"}


@router.post("/mfa/disable")
def disable_mfa(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    user.mfa_enabled = False
    user.mfa_secret = None
    db.commit()
    log_action(db, action="auth.mfa_disabled", user=user, ip_address=_client_ip(request))
    return {"message": "MFA disabled"}


@router.post("/register-staff", response_model=UserOut, status_code=201)
def register_staff(payload: StaffRegister, request: Request, db: Session = Depends(get_db),
                    admin: User = Depends(require_admin)):
    """Admin-only -- creates another admin/analyst account. The very first admin must be seeded via CLI (see README)."""
    if db.query(User).filter_by(email=payload.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(email=payload.email, hashed_password=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, action="user.create_staff", user=admin, resource_type="user", resource_id=user.id,
               detail={"created_email": user.email, "role": user.role.value}, ip_address=_client_ip(request))
    return user


@router.post("/register-client-user", response_model=UserOut, status_code=201)
def register_client_user(payload: ClientUserRegister, request: Request, db: Session = Depends(get_db),
                          staff: User = Depends(require_staff)):
    """Staff-only -- provisions a portal login for a client's team, scoped to that client_id."""
    if not db.query(Client).get(payload.client_id):
        raise HTTPException(404, "Client not found")
    if db.query(User).filter_by(email=payload.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(email=payload.email, hashed_password=hash_password(payload.password),
                role=UserRole.client, client_id=payload.client_id)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, action="user.create_client_user", user=staff, client_id=payload.client_id,
               resource_type="user", resource_id=user.id, detail={"created_email": user.email},
               ip_address=_client_ip(request))
    return user
