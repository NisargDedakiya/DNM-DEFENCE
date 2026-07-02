"""
Encrypts/decrypts cloud credentials before they touch the database.
CloudAccount.encrypted_credentials must NEVER hold plaintext — this is the
only place that's allowed to see decrypted keys, and only in memory,
never logged.
"""
import json

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _get_fernet() -> Fernet:
    if not settings.ENCRYPTION_KEY:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
            "and put it in .env as ENCRYPTION_KEY."
        )
    return Fernet(settings.ENCRYPTION_KEY.encode())


def encrypt_credentials(credentials: dict) -> str:
    """credentials, e.g. {'access_key_id': '...', 'secret_access_key': '...'} -> encrypted string for DB storage."""
    f = _get_fernet()
    raw = json.dumps(credentials).encode()
    return f.encrypt(raw).decode()


def decrypt_credentials(encrypted: str) -> dict:
    f = _get_fernet()
    try:
        raw = f.decrypt(encrypted.encode())
    except InvalidToken:
        raise ValueError("Could not decrypt cloud credentials — wrong ENCRYPTION_KEY or corrupted data.")
    return json.loads(raw.decode())
