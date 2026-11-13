"""Evaluation dataset: the generated synthetic items plus items people add from the Evaluation tab.

Generated items live in eval/data/ (rewritten by eval/generate_dataset.py, which wipes eval/data/items).
Added items therefore live in their own folder, eval/added/ by default (EVAL_ADDED_DIR overrides it),
which is git-ignored so that real emails people add are never pushed by accident.
"""

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.link_scan import InvalidUrlError, normalize_url
from app.pdf_parser import MAX_PDF_BYTES, UnreadablePdfError, parse_pdf

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_DIR = os.path.join(BASE_DIR, "eval")
GENERATED_DIR = os.path.join(EVAL_DIR, "data")
GENERATED_INDEX = os.path.join(GENERATED_DIR, "dataset.jsonl")

# What the browser gets for each item: labels and metadata, never the content or file path.
PUBLIC_FIELDS = ("id", "label", "input_kind", "attack_type", "difficulty", "split", "title", "source")
LABELS = ("phishing", "legit")
MAX_ADDED_ITEMS = 5000
MAX_FILES_PER_UPLOAD = 100
MAX_LINKS_PER_UPLOAD = 200

KIND_BY_EXTENSION = {".eml": "eml", ".pdf": "pdf", ".txt": "plain_text"}
EXTENSION_BY_KIND = {"eml": ".eml", "pdf": ".pdf", "plain_text": ".txt"}

_lock = threading.Lock()
_generated_cache: Dict[str, Any] = {"mtime": None, "items": []}


class ItemError(ValueError):
    """An upload that can't become a dataset item. The message is shown to the user."""


def added_dir() -> str:
    return os.getenv("EVAL_ADDED_DIR", "").strip() or os.path.join(EVAL_DIR, "added")


def _added_index() -> str:
    return os.path.join(added_dir(), "added.jsonl")


def load_generated() -> List[Dict[str, Any]]:
    if not os.path.exists(GENERATED_INDEX):
        return []
    mtime = os.path.getmtime(GENERATED_INDEX)
    if _generated_cache["mtime"] != mtime:
        with open(GENERATED_INDEX, "r", encoding="utf-8") as fh:
            items = [json.loads(line) for line in fh if line.strip()]
        for item in items:
            item.setdefault("source", "generated")
        _generated_cache.update(mtime=mtime, items=items)
    return _generated_cache["items"]


def load_added() -> List[Dict[str, Any]]:
    path = _added_index()
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def all_items() -> List[Dict[str, Any]]:
    return load_generated() + load_added()


def find(item_id: str) -> Optional[Dict[str, Any]]:
    return next((i for i in all_items() if i["id"] == item_id), None)


def public(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: item.get(k) for k in PUBLIC_FIELDS}


def file_path(item: Dict[str, Any]) -> str:
    base = added_dir() if item.get("source") == "added" else GENERATED_DIR
    return os.path.join(base, item["path"])


# ----------------------------------------------------------------------------- validation

def _title_from_text(text: str, header: bool) -> str:
    if header:
        match = re.search(r"^Subject:[ \t]*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        if match and match.group(1).strip():
            return match.group(1).strip()[:120]
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:120]
    return ""


def inspect_file(filename: str, data: bytes) -> Tuple[str, str]:
    """Return (input_kind, title) or raise ItemError with a plain explanation."""
    name = (filename or "").lower()
    ext = os.path.splitext(name)[1]
    if data[:5] == b"%PDF-" and ext in ("", ".pdf"):
        ext = ".pdf"
    kind = KIND_BY_EXTENSION.get(ext)
    if kind is None:
        raise ItemError("Only .eml, .pdf and .txt files can be added.")
    if not data.strip():
        raise ItemError("The file is empty.")
    if len(data) > MAX_PDF_BYTES:
        raise ItemError("This file is larger than 5 MB.")
    if kind == "pdf":
        try:
            parsed = parse_pdf(data)
        except UnreadablePdfError as exc:
            raise ItemError(str(exc))
        title = parsed.headers.get("subject") or _title_from_text(parsed.text, header=False)
        return kind, title[:120]
    if b"\x00" in data[:8192]:
        raise ItemError("This doesn't look like a text file. Use a saved .eml file, a .txt file or a PDF.")
    text = data.decode("utf-8", errors="replace")
    return kind, _title_from_text(text, header=(kind == "eml"))


def _next_id(existing: List[Dict[str, Any]], kind: str, label: str) -> str:
    prefix = f"added-{kind}-{label}-"
    numbers = [int(i["id"][len(prefix):]) for i in existing if i["id"].startswith(prefix) and i["id"][len(prefix):].isdigit()]
    return f"{prefix}{max(numbers, default=0) + 1:03d}"


def _record(item_id: str, kind: str, label: str, title: str, digest: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": item_id,
        "label": label,
        "input_kind": kind,
        "attack_type": "added",
        "difficulty": "unrated",
        "split": "added",
        "title": title,
        "source": "added",
        "sha256": digest,
        "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **extra,
    }


def _write_index(items: List[Dict[str, Any]]) -> None:
    os.makedirs(added_dir(), exist_ok=True)
    tmp = _added_index() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for item in items:
            fh.write(json.dumps(item, sort_keys=True) + "\n")
    os.replace(tmp, _added_index())


# ----------------------------------------------------------------------------- add / remove

def add_items(
    label: str, files: List[Tuple[str, bytes]], links: List[str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    """Validate and store new items. Returns (added items, rejected [{name, reason}])."""
    if label not in LABELS:
        raise ItemError("Choose whether these items are phishing or legit.")
    if not files and not links:
        raise ItemError("Choose at least one file or paste at least one link.")
    if len(files) > MAX_FILES_PER_UPLOAD:
        raise ItemError(f"Add at most {MAX_FILES_PER_UPLOAD} files at a time.")
    if len(links) > MAX_LINKS_PER_UPLOAD:
        raise ItemError(f"Add at most {MAX_LINKS_PER_UPLOAD} links at a time.")

    added: List[Dict[str, Any]] = []
    rejected: List[Dict[str, str]] = []
    with _lock:
        existing = load_added()
        if len(existing) + len(files) + len(links) > MAX_ADDED_ITEMS:
            raise ItemError(f"The dataset can hold at most {MAX_ADDED_ITEMS} added items. Remove some first.")
        known = {i.get("sha256") for i in existing}
        os.makedirs(os.path.join(added_dir(), "items"), exist_ok=True)

        for filename, data in files:
            shown = os.path.basename(filename or "file")
            try:
                kind, title = inspect_file(filename, data)
            except ItemError as exc:
                rejected.append({"name": shown, "reason": str(exc)})
                continue
            digest = hashlib.sha256(data).hexdigest()
            if digest in known:
                rejected.append({"name": shown, "reason": "This file is already in the dataset."})
                continue
            item_id = _next_id(existing + added, kind, label)
            rel = f"items/{item_id}{EXTENSION_BY_KIND[kind]}"
            with open(os.path.join(added_dir(), rel), "wb") as fh:
                fh.write(data)
            added.append(_record(item_id, kind, label, title or shown, digest, path=rel))
            known.add(digest)

        for raw in links:
            try:
                url, _host, _ = normalize_url(raw)
            except InvalidUrlError as exc:
                rejected.append({"name": raw[:80], "reason": str(exc)})
                continue
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
            if digest in known:
                rejected.append({"name": raw[:80], "reason": "This link is already in the dataset."})
                continue
            item_id = _next_id(existing + added, "url", label)
            added.append(_record(item_id, "url", label, url[:120], digest, url=url))
            known.add(digest)

        if added:
            _write_index(existing + added)
    return added, rejected


def remove_item(item_id: str) -> None:
    with _lock:
        existing = load_added()
        item = next((i for i in existing if i["id"] == item_id), None)
        if item is None:
            if any(i["id"] == item_id for i in load_generated()):
                raise PermissionError("Only items you added can be removed. The generated dataset is rebuilt by eval/generate_dataset.py.")
            raise KeyError(item_id)
        _write_index([i for i in existing if i["id"] != item_id])
        if item.get("path"):
            try:
                os.remove(os.path.join(added_dir(), item["path"]))
            except FileNotFoundError:
                pass
