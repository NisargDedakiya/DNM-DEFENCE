import uuid

from app.models.models import CloudAccount, CloudProvider
from app.services import cspm


def _fake_account(provider):
    return CloudAccount(
        id=str(uuid.uuid4()), client_id=str(uuid.uuid4()), provider=provider,
        account_identifier="test-account", encrypted_credentials="unused-for-this-test",
    )


def test_discover_gcp_assets_degrades_gracefully_without_sdk():
    # google-cloud SDK isn't installed in the test environment (it's an
    # optional dependency, same as for audit_gcp) -- should log a warning
    # and return an empty list, never raise.
    assets = cspm.discover_gcp_assets(_fake_account(CloudProvider.gcp))
    assert assets == []


def test_discover_azure_assets_degrades_gracefully_without_sdk():
    assets = cspm.discover_azure_assets(_fake_account(CloudProvider.azure))
    assert assets == []


def test_discover_cloud_assets_dispatches_by_provider():
    # AWS dispatch would need real/mocked boto3 creds to go further, but we
    # can confirm the dispatch table itself is complete and routes GCP/Azure
    # to their (gracefully-degrading) functions without raising.
    assert cspm.discover_cloud_assets(_fake_account(CloudProvider.gcp)) == []
    assert cspm.discover_cloud_assets(_fake_account(CloudProvider.azure)) == []
    assert set(cspm.CLOUD_ASSET_DISCOVERY_DISPATCH.keys()) == {CloudProvider.aws, CloudProvider.gcp, CloudProvider.azure}
