from unittest.mock import MagicMock, patch

from app.models.models import (
    RedTeamOperation, RedTeamOperationStatus, RedTeamTimelineEntry, RedTeamTimelinePhase, RedTeamDetectionStatus,
)
from app.services.red_team import (
    generate_attck_heatmap, check_c2_infra_exposure, generate_attack_narrative, generate_purple_team_export,
)


def _make_operation():
    return RedTeamOperation(
        id="op-1", client_id="client-1", name="Operation Nightfall", objective="Test EDR detection of lateral movement",
        threat_actor="FIN7", status=RedTeamOperationStatus.active,
    )


def _make_entries():
    return [
        RedTeamTimelineEntry(
            id="e1", operation_id="op-1", timestamp="2026-01-01T10:00:00", phase=RedTeamTimelinePhase.initial_access,
            action="Sent spearphishing email", host="mail-server", tool_used="gophish", outcome="user clicked link",
            detected=RedTeamDetectionStatus.not_detected, attack_technique_id="T1566.001",
        ),
        RedTeamTimelineEntry(
            id="e2", operation_id="op-1", timestamp="2026-01-01T11:00:00", phase=RedTeamTimelinePhase.lateral_movement,
            action="Pass the hash to file server", host="fs01", tool_used="mimikatz", outcome="access gained",
            detected=RedTeamDetectionStatus.detected, attack_technique_id="T1550.002",
        ),
    ]


def test_generate_attck_heatmap_counts_techniques():
    layer = generate_attck_heatmap(_make_entries())
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores == {"T1566.001": 1, "T1550.002": 1}


def test_generate_attck_heatmap_handles_no_technique_tags():
    entries = [RedTeamTimelineEntry(id="e1", operation_id="op-1", timestamp="2026-01-01T10:00:00",
                                     phase=RedTeamTimelinePhase.recon, action="Passive OSINT")]
    layer = generate_attck_heatmap(entries)
    assert layer["techniques"] == []


def test_check_c2_infra_exposure_empty_list_skips_lookup():
    assert check_c2_infra_exposure([]) == []


def test_check_c2_infra_exposure_calls_shodan():
    with patch("app.services.red_team.check_shodan", return_value=[{"ip": "1.2.3.4", "org": "Acme"}]) as mock_shodan:
        result = check_c2_infra_exposure(["1.2.3.4"])
    mock_shodan.assert_called_once_with(["1.2.3.4"])
    assert result == [{"ip": "1.2.3.4", "org": "Acme"}]


def test_generate_attack_narrative_grounded_in_timeline():
    op = _make_operation()
    entries = _make_entries()
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="Narrative body.")]
    with patch("app.services.red_team._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        narrative = generate_attack_narrative(op, entries)

    assert narrative == "Narrative body."
    call_kwargs = mock_client_factory.return_value.messages.create.call_args.kwargs
    prompt = call_kwargs["messages"][0]["content"]
    assert "Pass the hash to file server" in prompt
    assert "FIN7" in prompt


def test_generate_attack_narrative_handles_empty_timeline():
    op = _make_operation()
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="No activity yet.")]
    with patch("app.services.red_team._claude_client") as mock_client_factory:
        mock_client_factory.return_value.messages.create.return_value = fake_response
        narrative = generate_attack_narrative(op, [])
    assert narrative == "No activity yet."


def test_generate_purple_team_export_is_markdown_table():
    op = _make_operation()
    entries = _make_entries()
    md = generate_purple_team_export(op, entries)
    assert "Operation Nightfall" in md
    assert "Pass the hash to file server" in md
    assert "T1566.001" in md
