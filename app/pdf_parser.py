"""Read an email that was saved with Print -> Save as PDF.

What we can recover: the visible text, header lines printed on the page (From/To/Subject/Date),
and the destinations of clickable links (PDF link annotations) together with the text shown on
top of them, so disguised links are still caught.

What we cannot recover: authentication headers (SPF/DKIM/DMARC are never printed), attachments,
and link targets when the PDF only contains the printed link text. Those gaps are returned as
`limitations` instead of being guessed.

Out of scope: scanned/image-only PDFs (no OCR).
"""

import io
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Dict, List, Optional, Tuple

from app.domains import domains_in_text, normalize_host
from app.evidence import LINK_MENTION_RE
from app.sanitizer import URL_REGEX, _extract_domain, _extract_url_domain
from app.schemas import AnchorMismatch, SanitizedEmailPayload, SanitizedHeaders

try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover - pypdf is in requirements
    PdfReader = None  # type: ignore

MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_PAGES = 20

NO_AUTH_LIMITATION = (
    "Saved PDFs don't keep the email's authentication headers, so we couldn't confirm who really sent it."
)
LINK_UNRECOVERED_LIMITATION = (
    "We couldn't recover where this email's links really go. The PDF only kept the printed text, not the link targets."
)

# URLs that browsers print in the page header/footer when you "Print to PDF" from webmail.
_PRINT_CHROME_URL = re.compile(
    r"^https?://(mail\.google\.com/mail|outlook\.(office|office365|live)\.com/(mail|owa)|mail\.yahoo\.com)",
    re.IGNORECASE,
)
_HEADER_LINE = re.compile(r"^\s*(From|To|Cc|Subject|Date|Sent|Reply-To)\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_ANGLE_EMAIL = re.compile(r"(?P<name>[^<>\n]{0,80}?)\s*<(?P<addr>[\w.+-]+@[\w-]+(?:\.[\w-]+)+)>")
_GMAIL_TITLE = re.compile(r"Gmail\s*-\s*(.+)")

PDF_PRINTER_IMAGE_ONLY = (
    "This PDF was saved with “Microsoft Print to PDF”, which turns the email into a picture we can't read. "
    "Print the email again and set the destination to “Save as PDF” instead."
)
IMAGE_ONLY = (
    "We couldn't find any text in this PDF. It looks like a picture of the email (a scan, a screenshot, or a PDF "
    "printer). Open the email, choose Print, and set the destination to “Save as PDF”."
)


class UnreadablePdfError(ValueError):
    """The upload can't be analysed; the message is shown next to the upload field."""


@dataclass
class PdfLink:
    uri: str
    anchor_text: str
    page: int


@dataclass
class ParsedPdf:
    text: str
    links: List[PdfLink]
    headers: Dict[str, str]
    page_count: int
    notes: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    link_unrecovered: bool = False


def _fragment_position(cm: List[float], tm: List[float]) -> Tuple[float, float]:
    x = tm[4] * cm[0] + tm[5] * cm[2] + cm[4]
    y = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]
    return x, y


def _text_in_rect(fragments: List[Tuple[float, float, str]], rect: List[float]) -> str:
    if len(rect) != 4:
        return ""
    x1, y1, x2, y2 = min(rect[0], rect[2]), min(rect[1], rect[3]), max(rect[0], rect[2]), max(rect[1], rect[3])
    hits = [t for (x, y, t) in fragments if x1 - 3 <= x <= x2 + 3 and y1 - 4 <= y <= y2 + 4]
    return re.sub(r"\s+", " ", "".join(hits)).strip()


def _recover_headers(text: str, document_title: str = "") -> Dict[str, str]:
    lines = text.splitlines()
    head = "\n".join(lines[:60])
    headers: Dict[str, str] = {}
    for match in _HEADER_LINE.finditer(head):
        key = match.group(1).lower()
        key = "date" if key == "sent" else key
        headers.setdefault(key, match.group(2).strip())

    if "from" not in headers:
        # Gmail prints the sender as "Name <addr>   date" followed by a "To:" line, with no "From:" prefix.
        # The first line ("Gmail   Owner <owner@...>") is the *inbox owner*, not the sender, so it is skipped.
        # A printed thread lists messages oldest first; the newest one (the email being asked about) wins.
        candidates = []
        window = lines
        for idx, line in enumerate(window):
            stripped = line.strip()
            lowered = stripped.lower()
            if lowered.startswith(("to", "cc", "bcc", "gmail")):
                continue
            match = _ANGLE_EMAIL.search(stripped)
            if not match:
                continue
            next_line = next((l.strip().lower() for l in window[idx + 1:] if l.strip()), "")
            if idx >= 30 and not next_line.startswith("to"):
                continue  # deep in the body: only trust real sender lines
            candidates.append((next_line.startswith("to"), idx, match))
        if candidates:
            match = max(candidates, key=lambda c: (c[0], c[1]))[2]
            headers["from"] = f"{match.group('name').strip()} <{match.group('addr')}>".strip()

    if "subject" not in headers:
        # Chrome stores the tab title ("Gmail - <subject>") as the PDF title, and prints it in the page header.
        title = _GMAIL_TITLE.match(document_title.strip()) or _GMAIL_TITLE.search(head)
        if title:
            headers["subject"] = title.group(1).strip()
        elif lines and lines[0].strip().lower().startswith("gmail") and len(lines) > 1:
            headers["subject"] = lines[1].strip()  # Gmail print: subject is the line under the header row
    return headers


def parse_pdf(data: bytes) -> ParsedPdf:
    if PdfReader is None:
        raise UnreadablePdfError("PDF support isn't installed on the server (missing pypdf).")
    if not data:
        raise UnreadablePdfError("The file is empty.")
    if len(data) > MAX_PDF_BYTES:
        raise UnreadablePdfError("This PDF is larger than 5 MB. Save just the one email as a PDF and try again.")
    if b"%PDF-" not in data[:1024]:
        raise UnreadablePdfError("This file isn't a PDF. Open the email, choose Print, then Save as PDF.")

    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            try:
                unlocked = reader.decrypt("")
            except Exception:
                unlocked = 0
            if not unlocked:
                raise UnreadablePdfError("This PDF is password-protected. Save the email as a PDF again without a password.")
        pages = list(reader.pages)
    except UnreadablePdfError:
        raise
    except Exception:
        raise UnreadablePdfError("We couldn't read this PDF. It may be damaged. Try saving the email as a PDF again.")

    notes: List[str] = []
    limitations: List[str] = []
    if len(pages) > MAX_PAGES:
        notes.append(f"Only the first {MAX_PAGES} of {len(pages)} pages were read.")
        limitations.append(f"Only the first {MAX_PAGES} pages of this PDF were checked.")
        pages = pages[:MAX_PAGES]

    page_texts: List[str] = []
    links: List[PdfLink] = []
    for index, page in enumerate(pages, 1):
        fragments: List[Tuple[float, float, str]] = []

        def _visitor(text, cm, tm, font_dict, font_size, _frags=fragments):
            if text and text.strip():
                try:
                    x, y = _fragment_position(cm, tm)
                    _frags.append((x, y, text))
                except Exception:
                    pass

        try:
            page_texts.append(page.extract_text(visitor_text=_visitor) or "")
        except Exception:
            notes.append(f"Text on page {index} couldn't be read.")
            continue

        try:
            annotations = page.get("/Annots") or []
            for annot in annotations:
                obj = annot.get_object()
                if obj.get("/Subtype") != "/Link":
                    continue
                action = obj.get("/A")
                action = action.get_object() if action is not None else None
                uri = str(action.get("/URI")) if action is not None and action.get("/URI") else ""
                if not uri:
                    continue
                rect = [float(v) for v in obj.get("/Rect", [])]
                links.append(PdfLink(uri=uri.strip(), anchor_text=_text_in_rect(fragments, rect), page=index))
        except Exception:
            notes.append(f"Links on page {index} couldn't be read.")

    metadata = {}
    try:
        metadata = dict(reader.metadata or {})
    except Exception:
        pass
    producer = str(metadata.get("/Producer", ""))
    document_title = str(metadata.get("/Title", ""))

    text = "\n".join(t for t in page_texts if t).strip()
    if not text:
        if "print to pdf" in producer.lower():
            raise UnreadablePdfError(PDF_PRINTER_IMAGE_ONLY)
        raise UnreadablePdfError(IMAGE_ONLY)

    web_links = [l for l in links if l.uri.lower().startswith(("http://", "https://"))]
    limitations.insert(0, NO_AUTH_LIMITATION)

    text_urls = [u for u in URL_REGEX.findall(text) if not _PRINT_CHROME_URL.match(u)]
    link_unrecovered = False
    if not web_links and (text_urls or LINK_MENTION_RE.search(text)):
        link_unrecovered = True
        limitations.append(LINK_UNRECOVERED_LIMITATION)
    elif web_links:
        notes.append(f"Recovered {len(web_links)} clickable link destination(s) from the PDF.")

    return ParsedPdf(
        text=text,
        links=web_links,
        headers=_recover_headers(text, document_title),
        page_count=len(pages),
        notes=notes,
        limitations=limitations,
        link_unrecovered=link_unrecovered,
    )


def to_payload(parsed: ParsedPdf, request_id: Optional[str] = None) -> SanitizedEmailPayload:
    """Turn a parsed PDF into the same payload the .eml sanitizer produces."""
    hdr = parsed.headers
    from_raw = hdr.get("from", "")
    from_name, from_addr = parseaddr(from_raw)
    from_addr = from_addr.lower().strip()
    _, to_addr = parseaddr(hdr.get("to", ""))
    reply_to_raw = hdr.get("reply-to", "")
    _, reply_to_addr = parseaddr(reply_to_raw)
    reply_to_addr = reply_to_addr.lower().strip()

    headers = SanitizedHeaders(
        from_raw=from_raw,
        from_display_name=from_name.strip(),
        from_address=from_addr,
        from_domain=_extract_domain(from_addr),
        to_raw=hdr.get("to", ""),
        to_address=to_addr.lower().strip(),
        reply_to_raw=reply_to_raw,
        reply_to_address=reply_to_addr,
        reply_to_domain=_extract_domain(reply_to_addr),
        subject=hdr.get("subject", ""),
        date=hdr.get("date", ""),
        auth_headers_present=False,
    )

    urls: List[str] = []
    mismatches: List[AnchorMismatch] = []
    notes = list(parsed.notes)
    for link in parsed.links:
        urls.append(link.uri)
        href_domain = _extract_url_domain(link.uri)
        shown = domains_in_text(link.anchor_text)
        if shown and href_domain and normalize_host(shown[0]) != href_domain:
            mismatches.append(
                AnchorMismatch(visible_text_domain=normalize_host(shown[0]), actual_href_domain=href_domain, full_href=link.uri)
            )
            notes.append(f"Anchor domain mismatch: text shows '{shown[0]}' but links to '{href_domain}'")

    for match in URL_REGEX.findall(parsed.text):
        cleaned = match.rstrip(".,;:!?)")
        if _PRINT_CHROME_URL.match(cleaned):
            notes.append("Ignored the webmail address the browser printed in the page header.")
            continue
        urls.append(cleaned)

    body = re.sub(r"\n{3,}", "\n\n", parsed.text).strip()[:8000]
    return SanitizedEmailPayload(
        request_id=request_id or f"pdf_{uuid.uuid4().hex[:10]}",
        sanitized_at=datetime.now(timezone.utc).isoformat(),
        headers=headers,
        body_text=body,
        extracted_urls=list(dict.fromkeys(urls)),
        anchor_mismatches=mismatches,
        attachments=[],
        sanitization_notes=list(dict.fromkeys(notes)),
    )
