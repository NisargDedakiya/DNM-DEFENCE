"""
SE-3 — Vishing Call Analyser.

Full vishing execution (dialing an employee with a signed consent form
in hand) is a human process that this codebase does not perform. This
module picks up after that call has already happened: given an audio
recording made under the engagement's own legal/consent process (or a
manually supplied transcript), it transcribes and analyzes it for
technique identification, information disclosure, and risk rating.
"""
import logging
import os

from app.core.config import settings
from app.models.models import VishingEngagement, VishingRiskRating

logger = logging.getLogger(__name__)


def transcribe_recording(file_path: str) -> str:
    """Whisper API transcription. Key-gated -- returns an empty string (never a fabricated transcript) if unset."""
    if not settings.OPENAI_API_KEY:
        logger.info("OPENAI_API_KEY not set — skipping transcription; supply a transcript manually instead")
        return ""

    from openai import OpenAI
    client = OpenAI(api_key=settings.OPENAI_API_KEY)
    try:
        with open(file_path, "rb") as f:
            resp = client.audio.transcriptions.create(model="whisper-1", file=f)
        return resp.text
    except Exception as e:
        logger.error(f"Whisper transcription failed for {file_path}: {e}")
        return ""


def _claude_client():
    import anthropic
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set — cannot analyze vishing transcript.")
    return anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)


def analyze_transcript(transcript: str, scenario: str = "") -> dict:
    """Claude-based technique identification + disclosure extraction + risk rating."""
    if not transcript.strip():
        return {"techniques_identified": [], "disclosures": [], "risk_rating": None,
                "summary": "No transcript available to analyze.", "raw_response": ""}

    ai = _claude_client()
    prompt = f"""You are a social engineering assessor reviewing a transcript of an authorized vishing (voice phishing) test call{f' using the pretext: {scenario}' if scenario else ''}.

Transcript:
{transcript[:6000]}

Analyze this transcript and respond in exactly this format:
TECHNIQUES: comma-separated list of social engineering techniques the caller used (e.g. authority impersonation, urgency, IT helpdesk pretext)
DISCLOSURES: comma-separated list of sensitive information the employee disclosed (e.g. password, employee ID, system name) -- write "none" if nothing was disclosed
RISK: one word -- low, medium, high, or critical
SUMMARY: 2-3 sentence summary of what happened and why that risk rating was assigned"""

    response = ai.messages.create(model=settings.ANTHROPIC_MODEL, max_tokens=500, messages=[{"role": "user", "content": prompt}])
    text = "".join(block.text for block in response.content if block.type == "text").strip()

    techniques: list[str] = []
    disclosures: list[str] = []
    risk = None
    summary = text
    for line in text.splitlines():
        upper = line.upper()
        if upper.startswith("TECHNIQUES:"):
            techniques = [t.strip() for t in line.split(":", 1)[1].split(",") if t.strip()]
        elif upper.startswith("DISCLOSURES:"):
            raw = line.split(":", 1)[1].strip()
            disclosures = [] if raw.lower() == "none" else [d.strip() for d in raw.split(",") if d.strip()]
        elif upper.startswith("RISK:"):
            candidate = line.split(":", 1)[1].strip().lower()
            if candidate in VishingRiskRating.__members__:
                risk = candidate
        elif upper.startswith("SUMMARY:"):
            summary = line.split(":", 1)[1].strip()

    return {"techniques_identified": techniques, "disclosures": disclosures, "risk_rating": risk,
            "summary": summary, "raw_response": text}


def run_vishing_analysis(engagement: VishingEngagement) -> dict:
    """Orchestrates transcription (if a recording exists and no transcript yet) + analysis."""
    transcript = engagement.transcript
    if not transcript and engagement.recording_path and os.path.exists(engagement.recording_path):
        transcript = transcribe_recording(engagement.recording_path)
    return analyze_transcript(transcript or "", engagement.scenario or "")
