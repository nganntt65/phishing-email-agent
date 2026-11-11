import email
from email import policy
from email.utils import parseaddr
import hashlib
from html.parser import HTMLParser
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
import uuid
from typing import List, Tuple

from app.schemas import (
    AnchorMismatch,
    AttachmentMetadata,
    SanitizedEmailPayload,
    SanitizedHeaders,
)

HIGH_RISK_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".hta", ".iso", ".img", ".lnk", ".jar"
)

URL_REGEX = re.compile(
    r"https?://[^\s<>\"'\)\]]+",
    re.IGNORECASE,
)


class _SafeHTMLStripper(HTMLParser):
    """Strips scripts/styles, extracts visible text, and detects anchor text vs href mismatches."""

    def __init__(self) -> None:
        super().__init__()
        self.text_chunks: List[str] = []
        self.links: List[Tuple[str, str]] = []  # (href, visible_text)
        self.notes: List[str] = []
        self._skip_depth = 0
        self._current_href: str | None = None
        self._current_anchor_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag_lower in ("script", "style", "iframe", "object", "embed"):
            self._skip_depth += 1
            self.notes.append(f"Stripped active/embedded HTML tag: <{tag_lower}>")
            return

        style = attr_dict.get("style", "").lower().replace(" ", "")
        if "display:none" in style or "visibility:hidden" in style or "font-size:0" in style:
            self.notes.append("Detected hidden CSS styling on HTML element (potential evasion/injection)")

        if tag_lower == "a":
            href = attr_dict.get("href", "").strip()
            if href:
                self._current_href = href
                self._current_anchor_text = []

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in ("script", "style", "iframe", "object", "embed") and self._skip_depth > 0:
            self._skip_depth -= 1
            return

        if tag_lower == "a" and self._current_href is not None:
            visible = "".join(self._current_anchor_text).strip()
            self.links.append((self._current_href, visible))
            self._current_href = None
            self._current_anchor_text = []

        if tag_lower in ("p", "div", "br", "li", "tr", "h1", "h2", "h3"):
            self.text_chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self.text_chunks.append(data)
            if self._current_href is not None:
                self._current_anchor_text.append(data)


def _extract_domain(addr: str) -> str:
    if "@" in addr:
        return addr.split("@", 1)[1].strip().lower().rstrip(">")
    return ""


def _extract_url_domain(url: str) -> str:
    try:
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


def preprocess_and_sanitize_eml(raw_eml: str, request_id: str | None = None) -> SanitizedEmailPayload:
    """
    Parses and sanitizes a raw .eml string into a safe structured payload
    suitable for the Agent Orchestrator and tools.
    """
    req_id = request_id or f"eml_{uuid.uuid4().hex[:10]}"
    msg = email.message_from_string(raw_eml, policy=policy.default)

    from_raw = str(msg.get("From", ""))
    from_name, from_addr = parseaddr(from_raw)
    from_addr = from_addr.lower().strip()

    to_raw = str(msg.get("To", ""))
    _, to_addr = parseaddr(to_raw)

    reply_to_raw = str(msg.get("Reply-To", ""))
    _, reply_to_addr = parseaddr(reply_to_raw)
    reply_to_addr = reply_to_addr.lower().strip()

    return_path_raw = str(msg.get("Return-Path", ""))
    _, return_path_addr = parseaddr(return_path_raw)
    return_path_addr = return_path_addr.lower().strip()

    headers = SanitizedHeaders(
        from_raw=from_raw,
        from_display_name=from_name.strip(),
        from_address=from_addr,
        from_domain=_extract_domain(from_addr),
        to_raw=to_raw,
        to_address=to_addr.lower().strip(),
        reply_to_raw=reply_to_raw,
        reply_to_address=reply_to_addr,
        reply_to_domain=_extract_domain(reply_to_addr),
        return_path_raw=return_path_raw,
        return_path_address=return_path_addr,
        return_path_domain=_extract_domain(return_path_addr),
        subject=str(msg.get("Subject", "")).strip(),
        date=str(msg.get("Date", "")).strip(),
        message_id=str(msg.get("Message-ID", "")).strip(),
        authentication_results=str(msg.get("Authentication-Results", "")).strip(),
        received_spf=str(msg.get("Received-SPF", "")).strip(),
        dkim_signature_present=bool(msg.get("DKIM-Signature")),
    )

    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[AttachmentMetadata] = []
    sanitization_notes: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get_content_disposition() or "")
            content_type = part.get_content_type()
            filename = part.get_filename()

            if filename or content_disposition == "attachment":
                payload_bytes = part.get_payload(decode=True) or b""
                fname = filename or "unnamed_attachment"
                fname_lower = fname.lower()
                is_risky = fname_lower.endswith(HIGH_RISK_EXTENSIONS) or bool(
                    re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png)\.(exe|scr|bat|js|hta)$", fname_lower)
                )
                attachments.append(
                    AttachmentMetadata(
                        filename=fname,
                        content_type=content_type,
                        size_bytes=len(payload_bytes),
                        sha256=hashlib.sha256(payload_bytes).hexdigest(),
                        is_high_risk_extension=is_risky,
                    )
                )
                continue

            if content_type == "text/plain":
                try:
                    plain_parts.append(part.get_content())
                except Exception:
                    raw_bytes = part.get_payload(decode=True) or b""
                    plain_parts.append(raw_bytes.decode("utf-8", errors="replace"))
            elif content_type == "text/html":
                try:
                    html_parts.append(part.get_content())
                except Exception:
                    raw_bytes = part.get_payload(decode=True) or b""
                    html_parts.append(raw_bytes.decode("utf-8", errors="replace"))
    else:
        ctype = msg.get_content_type()
        try:
            body_content = msg.get_content()
        except Exception:
            raw_bytes = msg.get_payload(decode=True) or b""
            body_content = raw_bytes.decode("utf-8", errors="replace")

        if ctype == "text/html":
            html_parts.append(body_content)
        else:
            plain_parts.append(body_content)

    extracted_urls: List[str] = []
    anchor_mismatches: List[AnchorMismatch] = []

    # Process HTML parts through the sanitizer
    html_extracted_text: List[str] = []
    for html_doc in html_parts:
        stripper = _SafeHTMLStripper()
        stripper.feed(html_doc)
        html_extracted_text.append("".join(stripper.text_chunks))
        sanitization_notes.extend(stripper.notes)

        for href, visible_text in stripper.links:
            if href.lower().startswith(("http://", "https://")):
                extracted_urls.append(href)
                # Check if visible anchor text looks like a URL/domain that mismatches actual href
                visible_urls = URL_REGEX.findall(visible_text)
                if visible_urls:
                    vis_domain = _extract_url_domain(visible_urls[0])
                    href_domain = _extract_url_domain(href)
                    if vis_domain and href_domain and vis_domain != href_domain:
                        anchor_mismatches.append(
                            AnchorMismatch(
                                visible_text_domain=vis_domain,
                                actual_href_domain=href_domain,
                                full_href=href,
                            )
                        )
                        sanitization_notes.append(
                            f"Anchor domain mismatch: text shows '{vis_domain}' but links to '{href_domain}'"
                        )

    combined_text = "\n".join(plain_parts).strip()
    if not combined_text and html_extracted_text:
        combined_text = "\n".join(html_extracted_text).strip()
        sanitization_notes.append("Derived plain text from sanitized HTML body")
    elif html_extracted_text:
        # Also include any additional text from HTML not in plain text
        html_clean = re.sub(r"\n{3,}", "\n\n", "\n".join(html_extracted_text).strip())
        if html_clean and html_clean not in combined_text:
            combined_text = f"{combined_text}\n\n[Sanitized HTML Text]:\n{html_clean}"

    # Extract URLs from plain/combined text as well
    for match in URL_REGEX.findall(combined_text):
        cleaned_url = match.rstrip(".,;:!?)")
        extracted_urls.append(cleaned_url)

    # Deduplicate URLs preserving order
    deduped_urls: List[str] = list(dict.fromkeys(extracted_urls))

    # Normalize excessive whitespace and cap body size for safe prompt assembly
    combined_text = re.sub(r"\n{3,}", "\n\n", combined_text).strip()[:8000]

    return SanitizedEmailPayload(
        request_id=req_id,
        sanitized_at=datetime.now(timezone.utc).isoformat(),
        headers=headers,
        body_text=combined_text,
        extracted_urls=deduped_urls,
        anchor_mismatches=anchor_mismatches,
        attachments=attachments,
        sanitization_notes=list(dict.fromkeys(sanitization_notes)),
    )

