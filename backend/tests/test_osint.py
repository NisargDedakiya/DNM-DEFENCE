import uuid
from unittest.mock import MagicMock, patch

from app.core.database import SessionLocal
from app.models.models import Client, OSINTProfile
from app.services import osint


def _text_block(text):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _fake_claude_response(text="Mocked narrative."):
    resp = MagicMock()
    resp.content = [_text_block(text)]
    return resp


def _make_client(db):
    c = Client(id=str(uuid.uuid4()), name="OSINT Test Co", root_domain="osint-test.example.com",
               contact_email="a@osint-test.example.com")
    db.add(c)
    db.commit()
    return c


def test_get_whois_parses_key_fields():
    fake_proc = MagicMock()
    fake_proc.stdout = "Registrar: Example Registrar\nCreation Date: 2020-01-01\nName Server: ns1.example.com\nName Server: ns2.example.com\n"
    with patch("app.services.osint.subprocess.run", return_value=fake_proc):
        result = osint.get_whois("osint-test.example.com")
    assert result["registrar"] == "Example Registrar"
    assert result["creation_date"] == "2020-01-01"
    assert set(result["name_servers"]) == {"ns1.example.com", "ns2.example.com"}


def test_get_whois_degrades_gracefully_when_binary_missing():
    with patch("app.services.osint.subprocess.run", side_effect=FileNotFoundError()):
        assert osint.get_whois("osint-test.example.com") is None


def test_guess_email_patterns_generates_common_formats():
    guesses = osint.guess_email_patterns("example.com", ["Jane Doe"])
    emails = {g["guessed_email"] for g in guesses}
    assert "jane.doe@example.com" in emails
    assert "jdoe@example.com" in emails
    assert "jane@example.com" in emails


def test_guess_email_patterns_skips_single_word_names():
    assert osint.guess_email_patterns("example.com", ["Cher"]) == []


def test_run_google_dorks_skips_without_keys():
    with patch("app.services.osint.settings") as mock_settings:
        mock_settings.GOOGLE_CSE_API_KEY = ""
        mock_settings.GOOGLE_CSE_CX = ""
        with patch("app.services.osint.httpx.get") as mock_get:
            hits = osint.run_google_dorks("example.com")
    mock_get.assert_not_called()
    assert hits == []


def test_run_google_dorks_returns_hits_with_keys_set():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"items": [{"title": "t", "link": "https://x.example.com", "snippet": "s"}]}
    with patch("app.services.osint.settings") as mock_settings:
        mock_settings.GOOGLE_CSE_API_KEY = "key"
        mock_settings.GOOGLE_CSE_CX = "cx"
        with patch("app.services.osint.httpx.get", return_value=resp):
            hits = osint.run_google_dorks("example.com")
    assert len(hits) == len(osint.DORK_TEMPLATES)
    assert hits[0]["link"] == "https://x.example.com"


def test_check_github_org_exposure_skips_without_token():
    with patch("app.services.osint.settings") as mock_settings:
        mock_settings.GITHUB_TOKEN = ""
        with patch("app.services.osint.httpx.get") as mock_get:
            hits = osint.check_github_org_exposure("Acme Corp", github_token=None)
    mock_get.assert_not_called()
    assert hits == []


def test_analyze_job_listing_finds_tech_keywords():
    resp = MagicMock()
    resp.text = "We use AWS, Kubernetes, and PostgreSQL extensively."
    resp.raise_for_status = MagicMock()
    with patch("app.services.osint.httpx.get", return_value=resp):
        result = osint.analyze_job_listing("https://example.com/careers")
    assert set(result["tech_mentions"]) == {"AWS", "Kubernetes", "PostgreSQL"}


def test_generate_osint_profile_end_to_end(client):
    db = SessionLocal()
    c = _make_client(db)

    fake_ai = MagicMock()
    fake_ai.messages.create.return_value = _fake_claude_response("Attacker-perspective narrative text.")

    with patch("app.services.osint.subprocess.run", side_effect=FileNotFoundError()), \
         patch("app.services.osint.get_dns_records", return_value=[]), \
         patch.object(osint, "_claude_client", return_value=fake_ai):
        profile = osint.generate_osint_profile(db, c, employee_names=["Jane Doe"], careers_page_url=None)

    assert isinstance(profile, OSINTProfile)
    assert profile.findings["narrative"] == "Attacker-perspective narrative text."
    assert "linkedin_note" in profile.findings
    assert "LinkedIn" in profile.findings["linkedin_note"]

    saved = db.query(OSINTProfile).filter_by(client_id=c.id).first()
    assert saved is not None


def test_generate_osint_profile_handles_missing_anthropic_key_honestly(client):
    db = SessionLocal()
    c = _make_client(db)
    with patch("app.services.osint.subprocess.run", side_effect=FileNotFoundError()), \
         patch("app.services.osint.get_dns_records", return_value=[]), \
         patch("app.services.osint.settings") as mock_settings:
        mock_settings.ANTHROPIC_API_KEY = ""
        mock_settings.GITHUB_TOKEN = ""
        mock_settings.GOOGLE_CSE_API_KEY = ""
        mock_settings.GOOGLE_CSE_CX = ""
        profile = osint.generate_osint_profile(db, c)
    assert "AI synthesis unavailable" in profile.findings["narrative"]


def test_export_osint_profile_pdf_writes_real_pdf(tmp_path, client):
    db = SessionLocal()
    c = _make_client(db)
    profile = OSINTProfile(id=str(uuid.uuid4()), client_id=c.id, findings={"narrative": "n", "linkedin_note": "note"})
    db.add(profile)
    db.commit()

    output_path = str(tmp_path / "profile.pdf")
    osint.export_osint_profile_pdf(profile, c, output_path)

    with open(output_path, "rb") as f:
        assert f.read()[:4] == b"%PDF"
