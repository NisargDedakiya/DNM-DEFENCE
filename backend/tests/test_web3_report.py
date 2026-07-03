from app.services import web3_report

SAMPLE_FINDINGS = [
    {"tool": "slither", "check": "reentrancy-eth", "severity": "critical", "description": "Reentrancy found.", "elements": [{"line": 42}]},
    {"tool": "semgrep", "check": "tx-origin-auth", "severity": "high", "description": "tx.origin used.", "elements": [{"line": 10}]},
]


def test_render_web3_audit_html_includes_findings_and_counts():
    html = web3_report.render_web3_audit_html("Acme Co", "Vault", "ethereum", SAMPLE_FINDINGS)
    assert "Acme Co" in html
    assert "Vault" in html
    assert "reentrancy-eth" in html
    assert "tx-origin-auth" in html


def test_render_web3_audit_html_public_mode_redacts_high_severity_detail():
    html = web3_report.render_web3_audit_html("Acme Co", "Vault", "ethereum", SAMPLE_FINDINGS, public_mode=True)
    assert "Reentrancy found." not in html
    assert "redacted" in html.lower()


def test_export_pdf_writes_real_pdf(tmp_path):
    html = web3_report.render_web3_audit_html("Acme Co", "Vault", "ethereum", SAMPLE_FINDINGS)
    output_path = str(tmp_path / "audit.pdf")
    web3_report.export_pdf(html, output_path)
    with open(output_path, "rb") as f:
        assert f.read()[:4] == b"%PDF"


def test_render_web3_audit_markdown_includes_findings_sorted_by_severity():
    md = web3_report.render_web3_audit_markdown("Acme Co", "Vault", "ethereum", SAMPLE_FINDINGS)
    assert md.index("reentrancy-eth") < md.index("tx-origin-auth")
    assert "CRITICAL" in md


def test_render_web3_audit_markdown_handles_no_findings():
    md = web3_report.render_web3_audit_markdown("Acme Co", "Vault", "ethereum", [])
    assert "No findings" in md
