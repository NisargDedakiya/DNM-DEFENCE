"""
Tests the GCP IAM over-privilege check and Azure Key Vault / AD security
defaults checks added in Phase 5, using sys.modules injection rather than
installing the real (heavy, optional) cloud SDKs -- same philosophy CI
already uses: these packages aren't required to test the platform's own
logic, only to talk to a real cloud account.
"""
import sys
import types
import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.models.models import CloudAccount, CloudProvider


def _fake_account(provider):
    return CloudAccount(
        id=str(uuid.uuid4()), client_id=str(uuid.uuid4()), provider=provider,
        account_identifier="test-project", encrypted_credentials="unused-for-this-test",
    )


@pytest.fixture
def fake_gcp_modules():
    """Injects minimal fake google.cloud.storage / googleapiclient.discovery / google.oauth2.service_account modules."""
    google_mod = types.ModuleType("google")
    google_cloud_mod = types.ModuleType("google.cloud")
    google_cloud_storage_mod = types.ModuleType("google.cloud.storage")
    google_oauth2_mod = types.ModuleType("google.oauth2")
    google_oauth2_sa_mod = types.ModuleType("google.oauth2.service_account")
    googleapiclient_mod = types.ModuleType("googleapiclient")
    googleapiclient_discovery_mod = types.ModuleType("googleapiclient.discovery")

    # storage.Client(...).list_buckets() -> [] (skip the bucket-policy branch)
    fake_storage_client_cls = MagicMock(return_value=MagicMock(list_buckets=MagicMock(return_value=[])))
    google_cloud_storage_mod.Client = fake_storage_client_cls

    google_oauth2_sa_mod.Credentials = MagicMock(
        from_service_account_info=MagicMock(return_value=MagicMock())
    )

    modules = {
        "google": google_mod, "google.cloud": google_cloud_mod, "google.cloud.storage": google_cloud_storage_mod,
        "google.oauth2": google_oauth2_mod, "google.oauth2.service_account": google_oauth2_sa_mod,
        "googleapiclient": googleapiclient_mod, "googleapiclient.discovery": googleapiclient_discovery_mod,
    }
    with patch.dict(sys.modules, modules):
        yield googleapiclient_discovery_mod


def test_audit_gcp_flags_direct_owner_editor_grants_to_users(fake_gcp_modules):
    from app.services import cspm

    def fake_build(service_name, version, credentials=None, cache_discovery=False):
        client = MagicMock()
        if service_name == "compute":
            client.firewalls.return_value.list.return_value.execute.return_value = {"items": []}
        elif service_name == "sqladmin":
            client.instances.return_value.list.return_value.execute.return_value = {"items": []}
        elif service_name == "cloudresourcemanager":
            client.projects.return_value.getIamPolicy.return_value.execute.return_value = {
                "bindings": [
                    {"role": "roles/owner", "members": ["user:risky@example.com", "serviceAccount:sa@project.iam.gserviceaccount.com"]},
                    {"role": "roles/viewer", "members": ["user:safe@example.com"]},
                ]
            }
        return client

    fake_gcp_modules.build = fake_build

    with patch("app.services.cspm.decrypt_credentials", return_value={"service_account_json": {}}):
        findings = cspm.audit_gcp(_fake_account(CloudProvider.gcp))

    over_priv = [f for f in findings if f["issue"] == "gcp_iam_over_privilege"]
    assert len(over_priv) == 1
    assert "risky@example.com" in over_priv[0]["resource"]


def test_audit_gcp_ignores_service_accounts_and_narrow_roles(fake_gcp_modules):
    from app.services import cspm

    def fake_build(service_name, version, credentials=None, cache_discovery=False):
        client = MagicMock()
        if service_name == "compute":
            client.firewalls.return_value.list.return_value.execute.return_value = {"items": []}
        elif service_name == "sqladmin":
            client.instances.return_value.list.return_value.execute.return_value = {"items": []}
        elif service_name == "cloudresourcemanager":
            client.projects.return_value.getIamPolicy.return_value.execute.return_value = {
                "bindings": [
                    {"role": "roles/owner", "members": ["serviceAccount:sa@project.iam.gserviceaccount.com"]},
                    {"role": "roles/viewer", "members": ["user:safe@example.com"]},
                ]
            }
        return client

    fake_gcp_modules.build = fake_build

    with patch("app.services.cspm.decrypt_credentials", return_value={"service_account_json": {}}):
        findings = cspm.audit_gcp(_fake_account(CloudProvider.gcp))

    assert not any(f["issue"] == "gcp_iam_over_privilege" for f in findings)


@pytest.fixture
def fake_azure_modules():
    azure_mod = types.ModuleType("azure")
    azure_identity_mod = types.ModuleType("azure.identity")
    azure_mgmt_mod = types.ModuleType("azure.mgmt")
    azure_mgmt_storage_mod = types.ModuleType("azure.mgmt.storage")
    azure_mgmt_network_mod = types.ModuleType("azure.mgmt.network")
    azure_mgmt_keyvault_mod = types.ModuleType("azure.mgmt.keyvault")

    azure_identity_mod.ClientSecretCredential = MagicMock(
        return_value=MagicMock(get_token=MagicMock(return_value=MagicMock(token="fake-token")))
    )
    azure_mgmt_storage_mod.StorageManagementClient = MagicMock(
        return_value=MagicMock(storage_accounts=MagicMock(list=MagicMock(return_value=[])))
    )
    azure_mgmt_network_mod.NetworkManagementClient = MagicMock(
        return_value=MagicMock(network_security_groups=MagicMock(list_all=MagicMock(return_value=[])))
    )

    modules = {
        "azure": azure_mod, "azure.identity": azure_identity_mod, "azure.mgmt": azure_mgmt_mod,
        "azure.mgmt.storage": azure_mgmt_storage_mod, "azure.mgmt.network": azure_mgmt_network_mod,
        "azure.mgmt.keyvault": azure_mgmt_keyvault_mod,
    }
    with patch.dict(sys.modules, modules):
        yield azure_mgmt_keyvault_mod


def test_audit_azure_flags_overbroad_keyvault_access_policy(fake_azure_modules):
    from app.services import cspm

    fake_vault = MagicMock()
    fake_vault.id = "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/myvault"
    fake_vault.name = "myvault"

    fake_policy = MagicMock()
    fake_policy.object_id = "principal-123"
    fake_policy.permissions.keys = ["all"]
    fake_policy.permissions.secrets = []
    fake_policy.permissions.certificates = []

    fake_details = MagicMock()
    fake_details.properties.access_policies = [fake_policy]

    fake_kv_client = MagicMock()
    fake_kv_client.vaults.list.return_value = [fake_vault]
    fake_kv_client.vaults.get.return_value = fake_details
    fake_azure_modules.KeyVaultManagementClient = MagicMock(return_value=fake_kv_client)

    with patch("app.services.cspm.decrypt_credentials", return_value={"tenant_id": "t", "client_id": "c", "client_secret": "s"}), \
         patch("app.services.cspm.httpx.get") as mock_graph_get:
        mock_graph_get.return_value = MagicMock(status_code=403)  # no Policy.Read.All -- expected/common
        findings = cspm.audit_azure(_fake_account(CloudProvider.azure))

    overbroad = [f for f in findings if f["issue"] == "keyvault_overbroad_access_policy"]
    assert len(overbroad) == 1
    assert "myvault" in overbroad[0]["resource"]
    assert "keys" in overbroad[0]["detail"]


def test_audit_azure_flags_disabled_security_defaults(fake_azure_modules):
    from app.services import cspm

    fake_kv_client = MagicMock()
    fake_kv_client.vaults.list.return_value = []
    fake_azure_modules.KeyVaultManagementClient = MagicMock(return_value=fake_kv_client)

    with patch("app.services.cspm.decrypt_credentials", return_value={"tenant_id": "t", "client_id": "c", "client_secret": "s"}), \
         patch("app.services.cspm.httpx.get") as mock_graph_get:
        mock_graph_get.return_value = MagicMock(status_code=200, json=MagicMock(return_value={"isEnabled": False}))
        findings = cspm.audit_azure(_fake_account(CloudProvider.azure))

    assert any(f["issue"] == "azuread_security_defaults_disabled" for f in findings)


def test_audit_azure_security_defaults_check_degrades_gracefully_on_403(fake_azure_modules):
    from app.services import cspm

    fake_kv_client = MagicMock()
    fake_kv_client.vaults.list.return_value = []
    fake_azure_modules.KeyVaultManagementClient = MagicMock(return_value=fake_kv_client)

    with patch("app.services.cspm.decrypt_credentials", return_value={"tenant_id": "t", "client_id": "c", "client_secret": "s"}), \
         patch("app.services.cspm.httpx.get") as mock_graph_get:
        mock_graph_get.return_value = MagicMock(status_code=403)
        findings = cspm.audit_azure(_fake_account(CloudProvider.azure))  # must not raise

    assert not any(f["issue"] == "azuread_security_defaults_disabled" for f in findings)
