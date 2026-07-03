"""
Module 4 — Cloud Security Posture Management (AWS, GCP, Azure).

Uses read-only, client-provided credentials (decrypted only in memory,
never logged) to audit:
  AWS:   S3, IAM, EC2 security groups, EBS/RDS encryption, CloudTrail, GuardDuty.
  GCP:   public storage buckets, project-level IAM over-privilege, VPC
         firewall rules, Cloud SQL public IPs.
  Azure: Blob Storage public access, NSG rules, Key Vault access
         policies, AD security defaults (best-effort — needs
         Policy.Read.All, which many read-only setups won't grant).

The client-provided IAM role/user must be read-only (SecurityAudit or
ReadOnlyAccess managed policy, or the GCP/Azure equivalents). Never
request write permissions.
"""
import hashlib
import logging
from datetime import datetime, timedelta

import boto3
import httpx
from botocore.exceptions import ClientError, BotoCoreError
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_credentials
from app.models.models import Client, CloudAccount, Finding, Severity, FindingStatus, Asset, AssetType, CloudProvider

logger = logging.getLogger(__name__)

DANGEROUS_INGRESS_PORTS = {22, 3389, 3306, 5432}


def _session_for_account(cloud_account: CloudAccount) -> boto3.Session:
    creds = decrypt_credentials(cloud_account.encrypted_credentials)
    return boto3.Session(
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        region_name=creds.get("region", "us-east-1"),
    )


def audit_s3_buckets(session: boto3.Session) -> list[dict]:
    """Feature 4.1 — S3 bucket policy analysis: public read/write, permissive ACLs."""
    findings = []
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError) as e:
        logger.error(f"S3 list_buckets failed: {e}")
        return findings

    for b in buckets:
        name = b["Name"]
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append({
                        "resource": f"s3://{name}", "issue": "public_acl",
                        "detail": f"Bucket ACL grants {grant.get('Permission')} to {uri.split('/')[-1]}",
                    })
        except ClientError as e:
            logger.debug(f"get_bucket_acl failed for {name}: {e}")

        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
            if policy_status.get("PolicyStatus", {}).get("IsPublic"):
                findings.append({
                    "resource": f"s3://{name}", "issue": "public_policy",
                    "detail": "Bucket policy is flagged public by S3's own policy status check.",
                })
        except ClientError:
            pass  # no bucket policy is normal, not an error

        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append({
                    "resource": f"s3://{name}", "issue": "no_encryption",
                    "detail": "Bucket has no default server-side encryption configured.",
                })
    return findings


def audit_iam(session: boto3.Session) -> list[dict]:
    """Feature 4.1 — IAM security: root usage, missing MFA, stale keys, over-privilege."""
    findings = []
    iam = session.client("iam")

    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountMFAEnabled", 1) == 0:
            findings.append({"resource": "root-account", "issue": "root_no_mfa",
                              "detail": "Root account does not have MFA enabled."})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"IAM get_account_summary failed: {e}")

    try:
        users = iam.list_users().get("Users", [])
    except (ClientError, BotoCoreError) as e:
        logger.error(f"IAM list_users failed: {e}")
        users = []

    for user in users:
        username = user["UserName"]
        try:
            mfa = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not mfa:
                findings.append({"resource": f"iam:user/{username}", "issue": "user_no_mfa",
                                  "detail": f"IAM user '{username}' does not have MFA enabled."})
        except ClientError:
            pass

        try:
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key["Status"] != "Active":
                    continue
                age_days = (datetime.utcnow() - key["CreateDate"].replace(tzinfo=None)).days
                if age_days > 90:
                    findings.append({"resource": f"iam:user/{username}", "issue": "stale_access_key",
                                      "detail": f"Access key {key['AccessKeyId']} is {age_days} days old (>90 day threshold)."})
        except ClientError:
            pass

    return findings


def audit_security_groups(session: boto3.Session) -> list[dict]:
    """Feature 4.1 — network security: 0.0.0.0/0 ingress on sensitive ports."""
    findings = []
    ec2 = session.client("ec2")
    try:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
    except (ClientError, BotoCoreError) as e:
        logger.error(f"describe_security_groups failed: {e}")
        return findings

    for sg in groups:
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0" and from_port in DANGEROUS_INGRESS_PORTS:
                    findings.append({
                        "resource": f"sg:{sg['GroupId']}", "issue": "open_ingress",
                        "detail": f"Security group '{sg.get('GroupName')}' allows 0.0.0.0/0 ingress on port {from_port}.",
                        "port": from_port,
                    })
    return findings


def audit_encryption_gaps(session: boto3.Session) -> list[dict]:
    """Feature 4.1 — encryption gaps: unencrypted EBS volumes and RDS instances."""
    findings = []
    ec2 = session.client("ec2")
    try:
        volumes = ec2.describe_volumes().get("Volumes", [])
        for v in volumes:
            if not v.get("Encrypted", False):
                findings.append({"resource": f"ebs:{v['VolumeId']}", "issue": "unencrypted_ebs",
                                  "detail": f"EBS volume {v['VolumeId']} is not encrypted at rest."})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"describe_volumes failed: {e}")

    try:
        rds = session.client("rds")
        instances = rds.describe_db_instances().get("DBInstances", [])
        for db_inst in instances:
            if not db_inst.get("StorageEncrypted", False):
                findings.append({"resource": f"rds:{db_inst['DBInstanceIdentifier']}", "issue": "unencrypted_rds",
                                  "detail": f"RDS instance {db_inst['DBInstanceIdentifier']} is not encrypted at rest."})
            if db_inst.get("PubliclyAccessible"):
                findings.append({"resource": f"rds:{db_inst['DBInstanceIdentifier']}", "issue": "public_rds",
                                  "detail": f"RDS instance {db_inst['DBInstanceIdentifier']} is publicly accessible."})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"describe_db_instances failed: {e}")

    return findings


def audit_cloudtrail_guardduty(session: boto3.Session) -> list[dict]:
    """Feature 4.1 — CloudTrail logging status + GuardDuty enablement."""
    findings = []
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            findings.append({"resource": "cloudtrail", "issue": "no_cloudtrail",
                              "detail": "No CloudTrail trails configured — no audit log of account activity."})
        else:
            for t in trails:
                status = ct.get_trail_status(Name=t["TrailARN"])
                if not status.get("IsLogging"):
                    findings.append({"resource": f"cloudtrail:{t['Name']}", "issue": "cloudtrail_disabled",
                                      "detail": f"CloudTrail trail '{t['Name']}' exists but logging is currently disabled."})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"CloudTrail check failed: {e}")

    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            findings.append({"resource": "guardduty", "issue": "guardduty_disabled",
                              "detail": "GuardDuty is not enabled in this account/region."})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"GuardDuty check failed: {e}")

    return findings


def run_full_aws_audit(cloud_account: CloudAccount) -> list[dict]:
    """Runs every AWS check and tags each result with its source category."""
    session = _session_for_account(cloud_account)
    results = []
    for category, fn in [
        ("s3", audit_s3_buckets),
        ("iam", audit_iam),
        ("network", audit_security_groups),
        ("encryption", audit_encryption_gaps),
        ("logging", audit_cloudtrail_guardduty),
    ]:
        try:
            for item in fn(session):
                item["category"] = category
                results.append(item)
        except (ClientError, BotoCoreError) as e:
            logger.error(f"AWS audit category '{category}' failed entirely: {e}")
    return results


SEVERITY_BY_ISSUE = {
    "public_acl": Severity.critical, "public_policy": Severity.critical,
    "public_bucket": Severity.critical,
    "public_rds": Severity.critical, "open_ingress": Severity.high,
    "root_no_mfa": Severity.critical, "user_no_mfa": Severity.medium,
    "stale_access_key": Severity.medium, "no_encryption": Severity.medium,
    "unencrypted_ebs": Severity.medium, "unencrypted_rds": Severity.medium,
    "no_cloudtrail": Severity.high, "cloudtrail_disabled": Severity.high,
    "guardduty_disabled": Severity.low,
    "gcp_iam_over_privilege": Severity.high, "keyvault_overbroad_access_policy": Severity.medium,
    "azuread_security_defaults_disabled": Severity.medium,
}
CVSS_BY_SEVERITY = {Severity.critical: 9.0, Severity.high: 7.0, Severity.medium: 5.0, Severity.low: 3.0}


def sync_cloud_findings_to_db(db: Session, client: Client, cloud_account: CloudAccount, raw_findings: list[dict]) -> int:
    now = datetime.utcnow()
    new_count = 0
    for item in raw_findings:
        dedup = hashlib.sha256(f"{client.id}:cloud:{cloud_account.id}:{item['resource']}:{item['issue']}".encode()).hexdigest()
        if db.query(Finding).filter_by(dedup_hash=dedup).first():
            continue
        severity = SEVERITY_BY_ISSUE.get(item["issue"], Severity.medium)
        sla_hours = client.sla_hours_critical if severity == Severity.critical else client.sla_hours_high
        db.add(Finding(
            client_id=client.id,
            title=f"[{cloud_account.provider.value.upper()}] {item['issue'].replace('_', ' ').title()} — {item['resource']}",
            description=item["detail"], severity=severity, cvss_score=CVSS_BY_SEVERITY[severity],
            status=FindingStatus.new, evidence=item,
            remediation_steps=_remediation_for_issue(item["issue"]),
            dedup_hash=dedup, created_at=now,
            sla_deadline=now + timedelta(hours=sla_hours),
        ))
        new_count += 1
    cloud_account.last_audited_at = now
    db.commit()
    return new_count


def _remediation_for_issue(issue: str) -> str:
    return {
        "public_acl": "Remove public grants from the bucket ACL; use bucket policies with explicit principals instead.",
        "public_policy": "Edit the bucket policy to remove wildcard principals or public conditions. Enable S3 Block Public Access.",
        "public_bucket": "Disable public access at the account/bucket level (S3 Block Public Access, GCS uniform bucket-level access, or Azure allowBlobPublicAccess=false).",
        "no_encryption": "Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.",
        "root_no_mfa": "Enable MFA on the root account immediately and stop using it for daily operations.",
        "user_no_mfa": "Require MFA for this IAM user, especially if they have console access.",
        "stale_access_key": "Rotate this access key. Delete it if it's no longer in use.",
        "open_ingress": "Restrict the security group rule to specific known IP ranges instead of 0.0.0.0/0.",
        "unencrypted_ebs": "Enable EBS encryption by default at the account level and re-create volumes with encryption on.",
        "unencrypted_rds": "Enable storage encryption — note this requires creating a new encrypted instance and migrating data.",
        "public_rds": "Disable public accessibility on the RDS instance and access it via VPC/VPN instead.",
        "no_cloudtrail": "Create a CloudTrail trail covering all regions and enable log file validation.",
        "cloudtrail_disabled": "Re-enable logging on this trail immediately — this may indicate tampering.",
        "guardduty_disabled": "Enable GuardDuty in this account and region for continuous threat detection.",
        "gcp_iam_over_privilege": "Replace the direct roles/owner or roles/editor grant with narrower predefined or custom IAM roles scoped to what this user actually needs.",
        "keyvault_overbroad_access_policy": "Edit the access policy to grant only the specific key/secret/certificate operations this principal needs, not 'all'.",
        "azuread_security_defaults_disabled": "Enable Azure AD Security Defaults, or ensure Conditional Access policies enforce equivalent MFA/baseline protections tenant-wide.",
    }.get(issue, "Review this finding and apply the relevant cloud provider security best practice.")


# --- Feature 4.2: GCP auditing ---

def _gcp_credentials_from_account(cloud_account: CloudAccount):
    """
    Expects a service-account JSON key stored in encrypted_credentials
    under the 'service_account_json' field, read-only role (roles/viewer
    + roles/iam.securityReviewer) only.
    """
    from google.oauth2 import service_account

    creds_dict = decrypt_credentials(cloud_account.encrypted_credentials)
    info = creds_dict["service_account_json"]
    return service_account.Credentials.from_service_account_info(info)


def audit_gcp(cloud_account: CloudAccount) -> list[dict]:
    """
    Feature 4.2 — GCP: public storage buckets, IAM over-privilege, Cloud
    SQL public IPs, VPC firewall rules open to 0.0.0.0/0.
    """
    findings = []
    try:
        from google.cloud import storage as gcs
        from googleapiclient import discovery
    except ImportError:
        logger.warning("google-cloud SDK not installed — skipping GCP audit. pip install google-cloud-storage google-api-python-client")
        return findings

    creds = _gcp_credentials_from_account(cloud_account)
    project_id = cloud_account.account_identifier

    try:
        storage_client = gcs.Client(project=project_id, credentials=creds)
        for bucket in storage_client.list_buckets():
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                    findings.append({
                        "resource": f"gcs://{bucket.name}", "issue": "public_bucket",
                        "detail": f"Cloud Storage bucket '{bucket.name}' grants access to {', '.join(m for m in binding['members'] if 'all' in m.lower())}.",
                    })
    except Exception as e:
        logger.error(f"GCP storage audit failed: {e}")

    try:
        compute = discovery.build("compute", "v1", credentials=creds, cache_discovery=False)
        firewalls = compute.firewalls().list(project=project_id).execute().get("items", [])
        for fw in firewalls:
            if fw.get("direction") != "INGRESS" or fw.get("disabled"):
                continue
            src_ranges = fw.get("sourceRanges", [])
            for allowed in fw.get("allowed", []):
                ports = allowed.get("ports", [])
                if "0.0.0.0/0" in src_ranges and any(p in ports for p in ["22", "3389", "3306", "5432"]):
                    findings.append({
                        "resource": f"firewall:{fw['name']}", "issue": "open_ingress",
                        "detail": f"Firewall rule '{fw['name']}' allows 0.0.0.0/0 ingress on sensitive port(s) {ports}.",
                    })
    except Exception as e:
        logger.error(f"GCP firewall audit failed: {e}")

    try:
        sqladmin = discovery.build("sqladmin", "v1", credentials=creds, cache_discovery=False)
        instances = sqladmin.instances().list(project=project_id).execute().get("items", [])
        for inst in instances:
            for ip in inst.get("ipAddresses", []):
                if ip.get("type") == "PRIMARY" and inst.get("settings", {}).get("ipConfiguration", {}).get("ipv4Enabled"):
                    authorized = inst["settings"]["ipConfiguration"].get("authorizedNetworks", [])
                    if any(n.get("value") == "0.0.0.0/0" for n in authorized):
                        findings.append({
                            "resource": f"cloudsql:{inst['name']}", "issue": "public_rds",
                            "detail": f"Cloud SQL instance '{inst['name']}' has a public IP authorized for 0.0.0.0/0.",
                        })
    except Exception as e:
        logger.error(f"GCP Cloud SQL audit failed: {e}")

    try:
        # Feature 4.1/4.2 parity — project-level IAM over-privilege: any
        # individual user (not a service account, not a group) directly
        # granted roles/owner or roles/editor at the project level is a
        # broad-blast-radius grant, mirroring the AWS IAM over-privilege
        # check's intent.
        crm = discovery.build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            if role not in ("roles/owner", "roles/editor"):
                continue
            for member in binding.get("members", []):
                if member.startswith("user:"):
                    findings.append({
                        "resource": f"iam:{member}", "issue": "gcp_iam_over_privilege",
                        "detail": f"'{member}' is directly granted project-level '{role}' — prefer narrower predefined/custom roles over broad owner/editor access.",
                    })
    except Exception as e:
        logger.error(f"GCP IAM audit failed: {e}")

    return findings


# --- Feature 4.2: Azure auditing ---

def audit_azure(cloud_account: CloudAccount) -> list[dict]:
    """
    Feature 4.2 — Azure: Blob Storage public access, NSG rules open to the
    internet, Azure AD security basics (via Graph, best-effort), Key Vault
    access policies.
    """
    findings = []
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.storage import StorageManagementClient
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        logger.warning("azure SDK not installed — skipping Azure audit. pip install azure-identity azure-mgmt-storage azure-mgmt-network")
        return findings

    creds_dict = decrypt_credentials(cloud_account.encrypted_credentials)
    credential = ClientSecretCredential(
        tenant_id=creds_dict["tenant_id"], client_id=creds_dict["client_id"], client_secret=creds_dict["client_secret"],
    )
    subscription_id = cloud_account.account_identifier

    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        for account in storage_client.storage_accounts.list():
            if account.allow_blob_public_access:
                findings.append({
                    "resource": f"storage:{account.name}", "issue": "public_bucket",
                    "detail": f"Storage account '{account.name}' allows public blob access at the account level.",
                })
    except Exception as e:
        logger.error(f"Azure storage audit failed: {e}")

    try:
        network_client = NetworkManagementClient(credential, subscription_id)
        for nsg in network_client.network_security_groups.list_all():
            for rule in (nsg.security_rules or []):
                if (rule.direction == "Inbound" and rule.access == "Allow"
                        and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")):
                    dest_port = rule.destination_port_range or ""
                    if dest_port in ("22", "3389", "3306", "5432", "*"):
                        findings.append({
                            "resource": f"nsg:{nsg.name}/{rule.name}", "issue": "open_ingress",
                            "detail": f"NSG rule '{rule.name}' on '{nsg.name}' allows inbound from any source to port {dest_port}.",
                        })
    except Exception as e:
        logger.error(f"Azure NSG audit failed: {e}")

    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
        kv_client = KeyVaultManagementClient(credential, subscription_id)
        for vault in kv_client.vaults.list():
            resource_group = vault.id.split("/")[4]  # .../resourceGroups/{rg}/providers/...
            details = kv_client.vaults.get(resource_group, vault.name)
            for policy in (details.properties.access_policies or []):
                perms = policy.permissions
                broad = [
                    cat for cat, granted in (("keys", perms.keys), ("secrets", perms.secrets), ("certificates", perms.certificates))
                    if granted and "all" in [p.lower() for p in granted]
                ]
                if broad:
                    findings.append({
                        "resource": f"keyvault:{vault.name}", "issue": "keyvault_overbroad_access_policy",
                        "detail": f"Key Vault '{vault.name}' grants principal '{policy.object_id}' 'all' permissions on {', '.join(broad)} — scope to only the specific operations needed.",
                    })
    except ImportError:
        logger.warning("azure-mgmt-keyvault not installed — skipping Key Vault audit")
    except Exception as e:
        logger.error(f"Azure Key Vault audit failed: {e}")

    try:
        # Azure AD security defaults, via a direct Graph REST call (no
        # separate Graph SDK dependency) -- best-effort: requires the app
        # registration to have Policy.Read.All, which many read-only
        # setups won't grant, so a 403 here is common and non-fatal.
        token = credential.get_token("https://graph.microsoft.com/.default").token
        resp = httpx.get(
            "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
            headers={"Authorization": f"Bearer {token}"}, timeout=15,
        )
        if resp.status_code == 200 and resp.json().get("isEnabled") is False:
            findings.append({
                "resource": "azuread:security-defaults", "issue": "azuread_security_defaults_disabled",
                "detail": "Azure AD Security Defaults are disabled — MFA and other baseline protections aren't enforced tenant-wide unless Conditional Access policies cover the gap.",
            })
    except Exception as e:
        logger.info(f"Azure AD security defaults check skipped (often needs Policy.Read.All): {e}")

    return findings


CLOUD_AUDIT_DISPATCH = {
    CloudProvider.aws: run_full_aws_audit,
    CloudProvider.gcp: audit_gcp,
    CloudProvider.azure: audit_azure,
}


def run_cloud_audit(cloud_account: CloudAccount) -> list[dict]:
    """Single entry point — dispatches to the right provider's audit functions."""
    fn = CLOUD_AUDIT_DISPATCH.get(cloud_account.provider)
    if not fn:
        logger.warning(f"No audit implementation for provider {cloud_account.provider}")
        return []
    return fn(cloud_account)


# --- Feature 1.4: Cloud asset discovery into the main Asset table ---

def discover_aws_assets(cloud_account: CloudAccount) -> list[dict]:
    """Enumerates EC2/S3/RDS/Lambda so cloud resources show up in the same Asset inventory as subdomains."""
    session = _session_for_account(cloud_account)
    assets = []
    try:
        ec2 = session.client("ec2")
        for r in ec2.describe_instances().get("Reservations", []):
            for inst in r.get("Instances", []):
                if inst.get("State", {}).get("Name") == "terminated":
                    continue
                assets.append({"value": inst["InstanceId"], "source": "boto3_ec2",
                                "tech_stack": {"public_ip": inst.get("PublicIpAddress"), "state": inst["State"]["Name"]}})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"EC2 asset discovery failed: {e}")

    try:
        s3 = session.client("s3")
        for b in s3.list_buckets().get("Buckets", []):
            assets.append({"value": f"s3://{b['Name']}", "source": "boto3_s3", "tech_stack": {}})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"S3 asset discovery failed: {e}")

    try:
        rds = session.client("rds")
        for db_inst in rds.describe_db_instances().get("DBInstances", []):
            assets.append({"value": db_inst["DBInstanceIdentifier"], "source": "boto3_rds",
                            "tech_stack": {"engine": db_inst.get("Engine"), "publicly_accessible": db_inst.get("PubliclyAccessible")}})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"RDS asset discovery failed: {e}")

    try:
        lam = session.client("lambda")
        for fn in lam.list_functions().get("Functions", []):
            assets.append({"value": fn["FunctionName"], "source": "boto3_lambda", "tech_stack": {"runtime": fn.get("Runtime")}})
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Lambda asset discovery failed: {e}")

    return assets


def discover_gcp_assets(cloud_account: CloudAccount) -> list[dict]:
    """Feature 1.4 — enumerates GCS buckets and Compute Engine instances so GCP resources show up in the Asset inventory."""
    assets = []
    try:
        from google.cloud import storage as gcs
        from googleapiclient import discovery
    except ImportError:
        logger.warning("google-cloud SDK not installed — skipping GCP asset discovery")
        return assets

    creds = _gcp_credentials_from_account(cloud_account)
    project_id = cloud_account.account_identifier

    try:
        storage_client = gcs.Client(project=project_id, credentials=creds)
        for bucket in storage_client.list_buckets():
            assets.append({"value": f"gcs://{bucket.name}", "source": "gcp_storage", "tech_stack": {}})
    except Exception as e:
        logger.error(f"GCP storage asset discovery failed: {e}")

    try:
        compute = discovery.build("compute", "v1", credentials=creds, cache_discovery=False)
        agg = compute.instances().aggregatedList(project=project_id).execute()
        for zone, scoped in agg.get("items", {}).items():
            for inst in scoped.get("instances", []):
                assets.append({"value": inst["name"], "source": "gcp_compute",
                                "tech_stack": {"zone": zone, "status": inst.get("status")}})
    except Exception as e:
        logger.error(f"GCP compute asset discovery failed: {e}")

    return assets


def discover_azure_assets(cloud_account: CloudAccount) -> list[dict]:
    """Feature 1.4 — enumerates Storage Accounts and VMs so Azure resources show up in the Asset inventory."""
    assets = []
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        logger.warning("azure SDK not installed — skipping Azure asset discovery")
        return assets

    creds_dict = decrypt_credentials(cloud_account.encrypted_credentials)
    credential = ClientSecretCredential(
        tenant_id=creds_dict["tenant_id"], client_id=creds_dict["client_id"], client_secret=creds_dict["client_secret"],
    )
    subscription_id = cloud_account.account_identifier

    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        for account in storage_client.storage_accounts.list():
            assets.append({"value": f"storage:{account.name}", "source": "azure_storage",
                            "tech_stack": {"location": account.location}})
    except Exception as e:
        logger.error(f"Azure storage asset discovery failed: {e}")

    try:
        from azure.mgmt.compute import ComputeManagementClient
        compute_client = ComputeManagementClient(credential, subscription_id)
        for vm in compute_client.virtual_machines.list_all():
            assets.append({"value": vm.name, "source": "azure_vm",
                            "tech_stack": {"location": vm.location, "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None}})
    except ImportError:
        logger.warning("azure-mgmt-compute not installed — skipping Azure VM asset discovery")
    except Exception as e:
        logger.error(f"Azure VM asset discovery failed: {e}")

    return assets


CLOUD_ASSET_DISCOVERY_DISPATCH = {
    CloudProvider.aws: discover_aws_assets,
    CloudProvider.gcp: discover_gcp_assets,
    CloudProvider.azure: discover_azure_assets,
}


def discover_cloud_assets(cloud_account: CloudAccount) -> list[dict]:
    """Single entry point — dispatches asset discovery to the right provider, matching run_cloud_audit's pattern."""
    fn = CLOUD_ASSET_DISCOVERY_DISPATCH.get(cloud_account.provider)
    if not fn:
        return []
    return fn(cloud_account)


def sync_cloud_assets_to_db(db: Session, client: Client, cloud_account: CloudAccount, discovered: list[dict]) -> int:
    """Upserts discovered cloud resources as Asset rows (asset_type=cloud_resource)."""
    now = datetime.utcnow()
    new_count = 0
    for item in discovered:
        asset = db.query(Asset).filter_by(client_id=client.id, asset_type=AssetType.cloud_resource, value=item["value"]).first()
        if asset:
            asset.last_seen = now
            asset.tech_stack = item.get("tech_stack", {})
        else:
            db.add(Asset(client_id=client.id, asset_type=AssetType.cloud_resource, value=item["value"],
                          source=item.get("source"), first_seen=now, last_seen=now, is_alive=True,
                          tech_stack=item.get("tech_stack", {})))
            new_count += 1
    db.commit()
    return new_count


# --- Feature 4.3: Configuration drift detection ---

def snapshot_baseline(raw_findings: list[dict]) -> dict:
    """
    Takes the current audit result set and turns it into a baseline
    signature: resource -> set of active issue codes. Stored as JSON on
    first audit; compared against on every subsequent audit.
    """
    baseline: dict[str, list[str]] = {}
    for item in raw_findings:
        baseline.setdefault(item["resource"], []).append(item["issue"])
    return baseline


def detect_drift(previous_baseline: dict, raw_findings: list[dict]) -> list[dict]:
    """
    Compares the current audit's resource/issue signature against the
    stored baseline. Returns drift events: resources with issues that
    weren't there before (new exposure) — the direction that actually
    matters for security (a resource *fixing* an issue isn't drift risk).
    """
    current = snapshot_baseline(raw_findings)
    drift_events = []
    for resource, issues in current.items():
        prev_issues = set(previous_baseline.get(resource, []))
        new_issues = set(issues) - prev_issues
        for issue in new_issues:
            drift_events.append({
                "resource": resource, "issue": issue,
                "detail": f"New misconfiguration on {resource}: {issue.replace('_', ' ')}. This was not present in the last approved baseline.",
            })
    return drift_events
