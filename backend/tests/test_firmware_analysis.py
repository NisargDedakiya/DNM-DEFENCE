import subprocess
from unittest.mock import MagicMock, patch

from app.services.firmware_analysis import (
    extract_printable_strings, run_binwalk_extraction, scan_extracted_files_for_secrets,
    identify_components, check_library_cves, run_checksec, generate_firmware_summary,
)


def test_extract_printable_strings_pulls_ascii_runs():
    data = b"\x00\x01BusyBox v1.31.1\x00\x02Linux version 4.14.0\x00"
    text = extract_printable_strings(data)
    assert "BusyBox v1.31.1" in text
    assert "Linux version 4.14.0" in text


def test_run_binwalk_extraction_degrades_on_missing_binary(tmp_path):
    fw = tmp_path / "firmware.bin"
    fw.write_bytes(b"dummy firmware bytes")
    with patch("app.services.firmware_analysis.subprocess.run", side_effect=FileNotFoundError):
        result = run_binwalk_extraction(str(fw), str(tmp_path / "out"))
    assert result["extracted"] is False


def test_run_binwalk_extraction_degrades_on_nonzero_exit(tmp_path):
    fw = tmp_path / "firmware.bin"
    fw.write_bytes(b"dummy firmware bytes")
    fake_proc = MagicMock(returncode=1, stdout="", stderr="binwalk.core not found")
    with patch("app.services.firmware_analysis.subprocess.run", return_value=fake_proc):
        result = run_binwalk_extraction(str(fw), str(tmp_path / "out"))
    assert result["extracted"] is False


def test_run_binwalk_extraction_degrades_on_timeout(tmp_path):
    fw = tmp_path / "firmware.bin"
    fw.write_bytes(b"dummy")
    with patch("app.services.firmware_analysis.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="binwalk", timeout=300)):
        result = run_binwalk_extraction(str(fw), str(tmp_path / "out"))
    assert result["extracted"] is False


def test_run_binwalk_extraction_success(tmp_path):
    fw = tmp_path / "firmware.bin"
    fw.write_bytes(b"dummy")
    fake_proc = MagicMock(returncode=0, stdout="Signatures found", stderr="")
    with patch("app.services.firmware_analysis.subprocess.run", return_value=fake_proc):
        result = run_binwalk_extraction(str(fw), str(tmp_path / "out"))
    assert result["extracted"] is True


def test_run_binwalk_extraction_passes_run_as_root_when_running_as_root(tmp_path):
    """binwalk >=2.2 exits 3 and refuses to extract as root without --run-as=root
    -- this container runs as root, so the flag must always be added or every
    extraction silently no-ops in production."""
    fw = tmp_path / "firmware.bin"
    fw.write_bytes(b"dummy")
    fake_proc = MagicMock(returncode=0, stdout="Signatures found", stderr="")
    with patch("app.services.firmware_analysis.os.geteuid", return_value=0, create=True), \
         patch("app.services.firmware_analysis.subprocess.run", return_value=fake_proc) as mock_run:
        run_binwalk_extraction(str(fw), str(tmp_path / "out"))
    assert "--run-as=root" in mock_run.call_args.args[0]


def test_run_binwalk_extraction_omits_run_as_root_for_non_root(tmp_path):
    fw = tmp_path / "firmware.bin"
    fw.write_bytes(b"dummy")
    fake_proc = MagicMock(returncode=0, stdout="Signatures found", stderr="")
    with patch("app.services.firmware_analysis.os.geteuid", return_value=1000, create=True), \
         patch("app.services.firmware_analysis.subprocess.run", return_value=fake_proc) as mock_run:
        run_binwalk_extraction(str(fw), str(tmp_path / "out"))
    assert "--run-as=root" not in mock_run.call_args.args[0]


def test_scan_extracted_files_for_secrets_finds_aws_key(tmp_path):
    secret_file = tmp_path / "config.txt"
    secret_file.write_bytes(b"AWS_KEY=AKIAABCDEFGHIJKLMNOP\n")
    hits = scan_extracted_files_for_secrets(str(tmp_path))
    assert any(h["type"] == "aws_access_key" for h in hits)


def test_scan_extracted_files_for_secrets_empty_dir(tmp_path):
    assert scan_extracted_files_for_secrets(str(tmp_path)) == []


def test_identify_components_matches_known_signatures():
    text = "BusyBox v1.31.1 (2021-01-01) multi-call binary\nLinux version 4.14.0\nOpenSSL 1.1.1k"
    components = identify_components(text)
    assert components["BusyBox"] == "1.31.1"
    assert components["Linux kernel"] == "4.14.0"
    assert components["OpenSSL"] == "1.1.1k"


def test_identify_components_empty_when_no_matches():
    assert identify_components("nothing recognizable here") == {}


def test_check_library_cves_parses_nvd_response():
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"vulnerabilities": [{"cve": {"id": "CVE-2021-1234",
                              "descriptions": [{"lang": "en", "value": "BusyBox vuln"}]}}]}
    with patch("app.services.firmware_analysis.httpx.get", return_value=resp):
        hits = check_library_cves({"BusyBox": "1.31.1"})
    assert hits[0]["cve_id"] == "CVE-2021-1234"


def test_check_library_cves_skips_on_network_failure():
    import httpx as httpx_module
    with patch("app.services.firmware_analysis.httpx.get", side_effect=httpx_module.ConnectError("down")):
        hits = check_library_cves({"BusyBox": "1.31.1"})
    assert hits == []


def test_run_checksec_returns_none_when_missing():
    with patch("app.services.firmware_analysis.subprocess.run", side_effect=FileNotFoundError):
        assert run_checksec("/path/to/binary") is None


def test_run_checksec_parses_json_output():
    fake_proc = MagicMock(returncode=0, stdout='{"relro": "full", "canary": true}')
    with patch("app.services.firmware_analysis.subprocess.run", return_value=fake_proc):
        result = run_checksec("/path/to/binary")
    assert result["relro"] == "full"


def test_run_checksec_uses_equals_joined_flags():
    """checksec.sh's own argument parser only accepts --flag=value, not a
    separate --flag value token -- passing them as two argv entries makes
    every real invocation fail with "Unknown option"."""
    fake_proc = MagicMock(returncode=0, stdout='{"relro": "full"}')
    with patch("app.services.firmware_analysis.subprocess.run", return_value=fake_proc) as mock_run:
        run_checksec("/path/to/binary")
    args = mock_run.call_args.args[0]
    assert "--file=/path/to/binary" in args
    assert "--format=json" in args


def test_generate_firmware_summary_grounded_in_findings():
    findings = {"components": {"BusyBox": "1.31.1"}, "secrets": [{"type": "aws_access_key"}], "cves": [{"cve_id": "CVE-2021-1234"}]}
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="Summary body.")]
    with patch("app.services.firmware_analysis.settings.ANTHROPIC_API_KEY", "test-key"), \
         patch("anthropic.Anthropic") as mock_anthropic:
        mock_anthropic.return_value.messages.create.return_value = fake_response
        summary = generate_firmware_summary(findings)
    assert summary == "Summary body."
    prompt = mock_anthropic.return_value.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "BusyBox 1.31.1" in prompt
    assert "CVE-2021-1234" in prompt
