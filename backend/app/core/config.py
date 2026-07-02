"""
Central configuration. All settings are pulled from environment variables
(see .env.example). Nothing here should be hardcoded per-client — this file
defines platform-wide config only.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    APP_NAME: str = "Track1 Automation Platform"
    ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "change-me-in-production"
    ENCRYPTION_KEY: str = ""  # Fernet key (base64, 32 bytes) for cloud credential encryption — generate with Fernet.generate_key()

    # Database
    DATABASE_URL: str = "postgresql://track1:track1@localhost:5432/track1"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # Anthropic
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"

    # External recon/intel APIs (all optional — features degrade gracefully if absent)
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    HIBP_API_KEY: str = ""
    DEHASHED_API_KEY: str = ""
    GITHUB_TOKEN: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # Notification delivery
    SENDGRID_API_KEY: str = ""
    ALERT_FROM_EMAIL: str = "alerts@track1platform.example"
    SLACK_BOT_TOKEN: str = ""  # optional — used only if a client doesn't have their own webhook set
    AUTO_SEND_CRITICAL_ALERTS: bool = False  # if False, alerts are drafted+logged but never auto-sent

    # Security
    ALLOWED_ORIGINS: str = "http://localhost:5173"  # comma-separated; set to your real portal domain(s) in prod
    API_VERSION: str = "v1"
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_LOGIN: str = "5/minute"
    LOGIN_LOCKOUT_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15
    FORCE_HTTPS: bool = False  # set True in production so HSTS + secure redirects apply
    MFA_REQUIRED_FOR_STAFF: bool = False  # if True, admin/analyst accounts must enroll MFA to get a token
    CLOUD_CREDENTIAL_ROTATION_DAYS: int = 90  # flags cloud accounts whose credentials haven't been rotated

    # Observability
    SENTRY_DSN: str = ""  # leave empty to disable error tracking entirely
    ENABLE_METRICS: bool = True  # exposes /metrics for Prometheus scraping

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    # Cloud (per-client credentials live in DB, encrypted — these are platform-level fallbacks only)
    AWS_DEFAULT_REGION: str = "us-east-1"

    # Scan tuning
    SUBDOMAIN_SCAN_INTERVAL_HOURS: int = 24
    PORT_SCAN_INTERVAL_HOURS: int = 168  # weekly
    MAX_CONCURRENT_SCANS_PER_CLIENT: int = 2


settings = Settings()
