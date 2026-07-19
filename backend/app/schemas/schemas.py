from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator


class ClientCreate(BaseModel):
    name: str
    root_domain: str
    industry: str | None = None
    contact_email: EmailStr
    slack_webhook_url: str | None = None
    plan: str | None = None  # subscription tier at onboarding; defaults to the model default if omitted

    @field_validator("slack_webhook_url")
    @classmethod
    def validate_slack_webhook(cls, v: str | None) -> str | None:
        """
        SSRF guard: this URL is later POSTed to server-side (notifications
        service). Without this check, a malicious or careless value here
        could be used to make the server issue requests to internal
        network addresses or the cloud metadata endpoint. Only genuine
        Slack incoming-webhook URLs are accepted.
        """
        if v is None:
            return v
        if not v.startswith("https://hooks.slack.com/services/"):
            raise ValueError("slack_webhook_url must be a genuine Slack incoming webhook URL (https://hooks.slack.com/services/...)")
        return v


class ClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    root_domain: str
    industry: str | None
    contact_email: str
    plan: str
    onboarded_at: datetime
    is_active: bool


class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    port_number: int
    protocol: str
    service_name: str | None
    service_version: str | None
    is_dangerous: bool


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    asset_type: str
    value: str
    source: str | None
    first_seen: datetime
    last_seen: datetime
    is_alive: bool
    tech_stack: dict
    risk_score: float
    ports: list[PortOut] = []


class ScanRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scan_type: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    new_assets_found: int
    new_findings_found: int
    error_message: str | None


class ScanTriggerResponse(BaseModel):
    message: str
    task_id: str
