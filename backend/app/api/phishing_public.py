"""
SE-2 — public (unauthenticated) phishing tracking endpoints. These are
hit by target employees clicking a simulated phishing email, not by
portal users, so they deliberately sit outside require_client_access.

Privacy-conscious by design: the credential-harvest landing page never
accepts or stores the submitted password itself -- only the boolean fact
that a submission happened, matching the existing PhishingResult
convention (see models.py).
"""
import base64

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import PhishingCampaign, PhishingTarget
from datetime import datetime

router = APIRouter(prefix="/api/phishing-track", tags=["phishing"])

_TRANSPARENT_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")

_LANDING_PAGE_HTML = """<!doctype html><html><head><title>Sign in</title></head>
<body style="font-family: sans-serif; max-width: 380px; margin: 80px auto;">
<h2>Sign in required</h2>
<form method="post" action="submit">
  <p><label>Email<br><input type="email" name="email" style="width:100%"></label></p>
  <p><label>Password<br><input type="password" name="password" style="width:100%"></label></p>
  <button type="submit">Sign in</button>
</form>
</body></html>"""

_SUBMIT_REDIRECT_HTML = """<!doctype html><html><body style="font-family: sans-serif; max-width: 480px; margin: 80px auto;">
<h2>This was a simulated phishing test</h2>
<p>You just interacted with an authorized security awareness exercise run by your organization. No real credentials were captured or stored.
Ask your security team for tips on spotting the warning signs next time.</p>
</body></html>"""


@router.get("/{token}/pixel.gif")
def track_open(token: str, db: Session = Depends(get_db)):
    """1x1 transparent GIF returned unconditionally (even for an unknown token) so a failed lookup can't be distinguished from a real hit by the client rendering it."""
    target = db.query(PhishingTarget).filter_by(tracking_token=token).first()
    if target and not target.opened:
        target.opened = True
        target.opened_at = datetime.utcnow()
        campaign = db.query(PhishingCampaign).get(target.campaign_id)
        if campaign:
            campaign.opened_count += 1
        db.commit()
    return Response(content=_TRANSPARENT_GIF, media_type="image/gif")


@router.get("/{token}/landing", response_class=HTMLResponse)
def track_click(token: str, db: Session = Depends(get_db)):
    target = db.query(PhishingTarget).filter_by(tracking_token=token).first()
    if target and not target.clicked:
        target.clicked = True
        target.clicked_at = datetime.utcnow()
        campaign = db.query(PhishingCampaign).get(target.campaign_id)
        if campaign:
            campaign.clicked_count += 1
        db.commit()
    return HTMLResponse(_LANDING_PAGE_HTML)


@router.post("/{token}/submit", response_class=HTMLResponse)
def track_submit(token: str, db: Session = Depends(get_db)):
    """Deliberately does not read/store the posted email/password fields -- only that a submission event occurred."""
    target = db.query(PhishingTarget).filter_by(tracking_token=token).first()
    if target and not target.submitted_credentials:
        target.submitted_credentials = True
        target.submitted_at = datetime.utcnow()
        campaign = db.query(PhishingCampaign).get(target.campaign_id)
        if campaign:
            campaign.credential_submitted_count += 1
        db.commit()
    return HTMLResponse(_SUBMIT_REDIRECT_HTML)
