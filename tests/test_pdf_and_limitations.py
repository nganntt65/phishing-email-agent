import asyncio

import pytest
from fpdf import FPDF

from app.orchestrator import orchestrator
from app.pdf_parser import UnreadablePdfError, parse_pdf
from app.redis_store import redis_store
from app.schemas import Confidence


def make_pdf(lines, link=None, link_text="portal.westbrook.edu/grades") -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    for line in lines:
        pdf.cell(0, 7, line, new_x="LMARGIN", new_y="NEXT")
    if link:
        pdf.cell(0, 7, link_text, new_x="LMARGIN", new_y="NEXT", link=link)
    return bytes(pdf.output())


PHISH_LINES = [
    "From: Westbrook IT Services <it-help@westbrook-edu.com>",
    "To: student@westbrook.edu",
    "Subject: Action required: verify your student account",
    "",
    "Please sign in to view your grades before Friday or your account will be suspended.",
]


def run(coro):
    async def _wrap():
        await redis_store.initialize()
        return await coro
    return asyncio.run(_wrap())


def test_pdf_recovers_headers_link_target_and_disguised_anchor():
    parsed = parse_pdf(make_pdf(PHISH_LINES, link="https://westbrook-edu.com/login/grades"))
    assert parsed.headers["from"].endswith("<it-help@westbrook-edu.com>")
    assert parsed.headers["subject"] == "Action required: verify your student account"
    assert [l.uri for l in parsed.links] == ["https://westbrook-edu.com/login/grades"]
    assert "portal.westbrook.edu" in parsed.links[0].anchor_text

    r = run(orchestrator.analyze_pdf_bytes(make_pdf(PHISH_LINES, link="https://westbrook-edu.com/login/grades"),
                                           use_llm=False, record_memory=False))
    assert r.input_kind == "pdf"
    assert r.sanitized_email.anchor_mismatches[0].actual_href_domain == "westbrook-edu.com"
    assert r.sender_integrity.impersonated_brand == "westbrook.edu"
    assert r.summary.finding == "This email asks you to sign in to view your grades."
    assert r.sender_integrity.spf_status == "unavailable"
    assert r.risk_score >= 60


def test_pdf_without_link_targets_offers_paste_link():
    r = run(orchestrator.analyze_pdf_bytes(make_pdf(PHISH_LINES + ["Click here to sign in."]),
                                           use_llm=False, record_memory=False))
    assert r.summary.link_unrecovered is True
    assert "paste_link" in [a.kind for a in r.summary.actions]
    assert any("couldn't recover where this email's links really go" in l for l in r.limitations)
    assert r.confidence == Confidence.LOW


@pytest.mark.parametrize("data, fragment", [
    (b"", "empty"),
    (b"this is not a pdf at all", "isn't a PDF"),
])
def test_unreadable_pdf_messages(data, fragment):
    with pytest.raises(UnreadablePdfError) as err:
        parse_pdf(data)
    assert fragment in str(err.value)


def test_image_only_pdf_is_rejected_clearly():
    blank = FPDF()
    blank.add_page()
    with pytest.raises(UnreadablePdfError) as err:
        parse_pdf(bytes(blank.output()))
    assert "picture of the email" in str(err.value)
    assert "Save as PDF" in str(err.value)


def test_microsoft_print_to_pdf_gets_specific_advice():
    # "Microsoft Print to PDF" saves the page as images only (seen with a real Gmail print).
    pdf = FPDF()
    pdf.set_producer("Microsoft: Print To PDF")
    pdf.add_page()
    with pytest.raises(UnreadablePdfError) as err:
        parse_pdf(bytes(pdf.output()))
    assert "Microsoft Print to PDF" in str(err.value)
    assert "Save as PDF" in str(err.value)


def test_gmail_print_layout_uses_sender_not_inbox_owner():
    # Gmail's print view puts the *inbox owner* in the top row; the sender is the line above "To:".
    lines = [
        "Gmail    Student Tester <owner@example.com>",
        "Action required: verify your student account",
        "1 message",
        "Westbrook IT Services <it-help@westbrook-edu.com>    Tue, Nov 10, 2026 at 8:00 AM",
        "To: owner@example.com",
        "",
        "Please sign in to view your grades before Friday.",
    ]
    parsed = parse_pdf(make_pdf(lines))
    assert parsed.headers["from"] == "Westbrook IT Services <it-help@westbrook-edu.com>"
    assert parsed.headers["subject"] == "Action required: verify your student account"

    r = run(orchestrator.analyze_pdf_bytes(make_pdf(lines), use_llm=False, record_memory=False))
    assert r.sender_integrity.is_lookalike_domain is True


def test_pdf_title_metadata_supplies_the_subject():
    pdf = FPDF()
    pdf.set_title("Gmail - Your parcel is waiting")
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    pdf.cell(0, 7, "Some body text without a subject line.")
    assert parse_pdf(bytes(pdf.output())).headers["subject"] == "Your parcel is waiting"


def test_low_risk_notification_does_not_claim_a_request():
    text = "You used Sign in with Google to sign in to ppt.ai. There's nothing you need to do right now."
    r = run(orchestrator.analyze_raw_eml(text, use_llm=False, record_memory=False))
    assert r.risk_level.value == "LOW"
    assert "asks you" not in r.summary.finding


def test_pasted_credential_lure_without_link_is_medium_and_named():
    # Pasted text with no sender and no recoverable link can't be proven a scam, but a suspend-or-verify
    # script is more than "low risk": caution, and the finding must say what the text asks for.
    text = "Your account will be suspended. Click here to verify your account immediately."
    r = run(orchestrator.analyze_raw_eml(text, use_llm=False, record_memory=False))
    assert r.risk_level.value == "MEDIUM" and 30 <= r.risk_score < 60
    assert "suspend" in r.summary.finding
    assert "didn't find" not in r.summary.why_it_matters  # must not contradict the finding


def test_low_score_with_warning_signs_is_not_called_no_red_flags():
    text = "Submit the form immediately. See the attached schedule."
    r = run(orchestrator.analyze_raw_eml(text, use_llm=False, record_memory=False))
    assert r.risk_level.value == "LOW"
    assert r.summary.label == "Low risk"
    assert "warning signs (" in r.summary.finding and "urgency" in r.summary.finding
    assert "didn't find" not in r.summary.why_it_matters


def test_clean_text_says_no_warning_signs():
    r = run(orchestrator.analyze_raw_eml("See you at the library at 3pm for the group project.",
                                         use_llm=False, record_memory=False))
    assert r.summary.label == "No red flags found"
    assert r.summary.finding == "We found no warning signs in this email."


def test_plain_text_is_reported_not_penalised():
    text = "Hello, the group meeting moved to 3pm in the library. See you there."
    r = run(orchestrator.analyze_raw_eml(text, use_llm=False, record_memory=False))
    assert r.input_kind == "plain_text"
    assert r.sender_integrity.dmarc_status == "unavailable"
    assert r.score_breakdown.sender_integrity_score == 0  # previously +15 just for missing headers
    assert r.confidence == Confidence.LOW
    assert any("without email headers" in l for l in r.limitations)


def test_plain_text_link_mention_without_url_flags_unrecovered_link():
    text = "Your account will be suspended. Click here to verify your account immediately."
    r = run(orchestrator.analyze_raw_eml(text, use_llm=False, record_memory=False))
    assert r.summary.link_unrecovered is True


def test_executable_attachment_override():
    eml = (
        "From: Office <office@docs-share-center.com>\nTo: s@westbrook.edu\nSubject: Form\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass header.from=docs-share-center.com\n"
        "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XX\n\n--XX\nContent-Type: text/plain\n\n"
        "Please open the attached form.\n--XX\nContent-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=Form.pdf.exe\n\nMZ\n--XX--\n"
    )
    r = run(orchestrator.analyze_raw_eml(eml, use_llm=False, record_memory=False))
    assert r.risk_score >= 85
    assert "Form.pdf.exe" in r.summary.finding
