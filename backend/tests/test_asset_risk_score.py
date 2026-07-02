import uuid

from app.core.database import SessionLocal
from app.models.models import Client, Asset, AssetType, Finding, Severity, FindingStatus
from app.workers.tasks import snapshot_client_metrics_all_clients


def test_snapshot_task_computes_per_asset_risk_score(client):
    db = SessionLocal()
    c = Client(id=str(uuid.uuid4()), name="Asset Risk Co", root_domain="asset-risk.example.com",
               contact_email="a@asset-risk.example.com")
    db.add(c)
    db.commit()

    risky_asset = Asset(id=str(uuid.uuid4()), client_id=c.id, asset_type=AssetType.subdomain, value="risky.asset-risk.example.com")
    quiet_asset = Asset(id=str(uuid.uuid4()), client_id=c.id, asset_type=AssetType.subdomain, value="quiet.asset-risk.example.com")
    db.add_all([risky_asset, quiet_asset])
    db.commit()

    db.add(Finding(id=str(uuid.uuid4()), client_id=c.id, asset_id=risky_asset.id, title="Critical on risky asset",
                    severity=Severity.critical, status=FindingStatus.new, dedup_hash=str(uuid.uuid4())))
    db.add(Finding(id=str(uuid.uuid4()), client_id=c.id, asset_id=risky_asset.id, title="High on risky asset",
                    severity=Severity.high, status=FindingStatus.new, dedup_hash=str(uuid.uuid4())))
    # Resolved findings shouldn't count toward risk
    db.add(Finding(id=str(uuid.uuid4()), client_id=c.id, asset_id=quiet_asset.id, title="Resolved on quiet asset",
                    severity=Severity.critical, status=FindingStatus.resolved, dedup_hash=str(uuid.uuid4())))
    db.commit()

    risky_id, quiet_id, client_id = risky_asset.id, quiet_asset.id, c.id
    db.close()

    snapshot_client_metrics_all_clients.run()

    db = SessionLocal()
    risky = db.query(Asset).get(risky_id)
    quiet = db.query(Asset).get(quiet_id)
    assert risky.risk_score == 35  # 25 (critical) + 10 (high)
    assert quiet.risk_score == 0  # only a resolved finding, doesn't count
