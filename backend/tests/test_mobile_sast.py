import plistlib
import sys
import types
import zipfile
from unittest.mock import MagicMock

import pytest

from app.services import mobile_sast


@pytest.fixture
def fake_androguard():
    """
    Injects a fake androguard.misc module into sys.modules so analyze_apk's
    lazy `from androguard.misc import AnalyzeAPK` resolves to a mock
    without needing the real (heavy) package installed -- same
    sys.modules-injection technique used elsewhere in this suite for
    testing code behind optional heavy SDK imports.
    """
    fake_misc = types.ModuleType("androguard.misc")
    fake_misc.AnalyzeAPK = MagicMock()
    fake_androguard = types.ModuleType("androguard")
    fake_androguard.misc = fake_misc
    sys.modules["androguard"] = fake_androguard
    sys.modules["androguard.misc"] = fake_misc
    yield fake_misc
    del sys.modules["androguard.misc"]
    del sys.modules["androguard"]


def _make_apk_mock(manifest_xml: str):
    apk = MagicMock()
    apk.get_package.return_value = "com.example.app"
    apk.get_min_sdk_version.return_value = "21"
    apk.get_target_sdk_version.return_value = "33"
    apk.get_permissions.return_value = ["android.permission.INTERNET"]
    apk.get_activities.return_value = ["com.example.app.MainActivity", "com.example.app.ExportedActivity"]
    apk.get_services.return_value = []
    apk.get_receivers.return_value = []
    apk.get_providers.return_value = []
    axml = MagicMock()
    axml.get_xml.return_value = manifest_xml.encode()
    apk.get_android_manifest_axml.return_value = axml
    return apk


def test_analyze_apk_extracts_manifest_flags_exported_components_and_secrets(fake_androguard):
    manifest_xml = (
        '<application android:allowBackup="true" android:debuggable="true" android:usesCleartextTraffic="true">'
        '<activity android:name=".MainActivity" android:exported="false"/>'
        '<activity android:name=".ExportedActivity" android:exported="true"/>'
        '</application>'
    )
    apk_mock = _make_apk_mock(manifest_xml)
    dex_mock = MagicMock()
    dex_mock.get_strings.return_value = ["hello world", "AKIAABCDEFGHIJKLMNOP", "using MD5 for hashing"]
    fake_androguard.AnalyzeAPK.return_value = (apk_mock, [dex_mock], MagicMock())

    result = mobile_sast.analyze_apk("/tmp/fake.apk")

    assert result["package_name"] == "com.example.app"
    assert result["allow_backup"] == "true"
    assert result["debuggable"] == "true"
    assert result["uses_cleartext_traffic"] == "true"
    exported_names = {c["name"] for c in result["exported_components"]}
    assert "com.example.app.ExportedActivity" in exported_names
    assert "com.example.app.MainActivity" not in exported_names
    assert any(h["type"] == "aws_access_key" for h in result["secret_hits"])
    assert any(h["algorithm"] == "MD5" for h in result["weak_crypto_hits"])


def test_analyze_apk_clean_app_has_no_findings_from_evaluate(fake_androguard):
    manifest_xml = '<application android:allowBackup="false" android:debuggable="false">' \
                    '<activity android:name=".MainActivity" android:exported="false"/></application>'
    apk_mock = _make_apk_mock(manifest_xml)
    dex_mock = MagicMock()
    dex_mock.get_strings.return_value = ["nothing interesting here"]
    fake_androguard.AnalyzeAPK.return_value = (apk_mock, [dex_mock], MagicMock())

    analysis = mobile_sast.analyze_apk("/tmp/fake.apk")
    findings = mobile_sast.evaluate_masvs_checklist(analysis)
    assert findings == []
    assert mobile_sast.compute_masvs_score(findings) == 100


def test_evaluate_masvs_checklist_flags_every_bad_signal():
    analysis = {
        "allow_backup": "true", "debuggable": "true", "uses_cleartext_traffic": "true",
        "exported_components": [{"type": "activity", "name": "Foo"}],
        "weak_crypto_hits": [{"algorithm": "MD5", "excerpt": "x"}],
        "secret_hits": [{"type": "aws_access_key", "excerpt": "x"}],
    }
    findings = mobile_sast.evaluate_masvs_checklist(analysis)
    controls = {f["masvs_control"] for f in findings}
    assert controls == {"MSTG-STORAGE-1", "MSTG-PLATFORM-1", "MSTG-CRYPTO-1", "MSTG-CODE-2", "MSTG-NETWORK-1", "MSTG-AUTH-1"}
    assert mobile_sast.compute_masvs_score(findings) == 0


def _make_fake_ipa(tmp_path, info: dict, extra_files: dict[str, bytes] | None = None) -> str:
    ipa_path = tmp_path / "app.ipa"
    with zipfile.ZipFile(ipa_path, "w") as z:
        z.writestr("Payload/TestApp.app/Info.plist", plistlib.dumps(info))
        for name, content in (extra_files or {}).items():
            z.writestr(name, content)
    return str(ipa_path)


def test_analyze_ipa_extracts_bundle_id_and_ats_flag(tmp_path):
    info = {
        "CFBundleIdentifier": "com.example.iosapp",
        "MinimumOSVersion": "14.0",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}],
    }
    ipa_path = _make_fake_ipa(tmp_path, info, extra_files={"Payload/TestApp.app/secrets.txt": b"AKIAABCDEFGHIJKLMNOP"})
    result = mobile_sast.analyze_ipa(ipa_path)

    assert result["package_name"] == "com.example.iosapp"
    assert result["uses_cleartext_traffic"] == "true"  # NSAllowsArbitraryLoads=True maps to this iOS analog
    assert "myapp" in result["url_schemes"]
    assert any(h["type"] == "aws_access_key" for h in result["secret_hits"])


def test_analyze_ipa_raises_without_info_plist(tmp_path):
    ipa_path = tmp_path / "bad.ipa"
    with zipfile.ZipFile(ipa_path, "w") as z:
        z.writestr("README.txt", "not an app bundle")
    with pytest.raises(ValueError):
        mobile_sast.analyze_ipa(str(ipa_path))


def test_run_optional_enrichment_degrades_gracefully_when_tool_missing():
    assert mobile_sast.run_optional_enrichment("definitely-not-a-real-binary", []) is None
