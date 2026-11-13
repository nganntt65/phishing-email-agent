"""The Evaluation tab's endpoints: the item list it samples from, adding and removing items, and running one item live."""

import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
import app.orchestrator as orchestrator_module
from app import eval_items, load_env_file
from app.main import app
from app.memory import CampaignHistoryMemory
from app.sample_emails import SAMPLE_EMLS

ROOT = Path(__file__).resolve().parent.parent
GENERATED_PDF = ROOT / "eval" / "data" / "items" / "pdf-phishing-002.pdf"
PHISH_EML = SAMPLE_EMLS["paypal_phish"]["raw_eml"].encode("utf-8")


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def added_dir(tmp_path, monkeypatch):
    """Each test gets its own empty folder for added items."""
    folder = tmp_path / "added"
    monkeypatch.setenv("EVAL_ADDED_DIR", str(folder))
    return folder


@pytest.fixture
def fresh_memory(tmp_path, monkeypatch):
    memory = CampaignHistoryMemory(db_path=str(tmp_path / "memory.db"))
    monkeypatch.setattr(orchestrator_module, "campaign_memory", memory)
    monkeypatch.setattr(main_module, "campaign_memory", memory)
    return memory


def add(client, label, files=(), links=""):
    return client.post("/api/v1/eval/items", data={"label": label, "links": links},
                       files=[("files", f) for f in files])


# ----------------------------------------------------------------------------- listing and sampling

def test_item_list_covers_the_whole_dataset_without_content(client, added_dir):
    data = client.get("/api/v1/eval/items").json()
    items = data["items"]
    assert len(items) == 260 and data["added"] == 0
    assert len({i["id"] for i in items}) == 260
    assert sum(i["label"] == "phishing" for i in items) == 130
    assert data["threshold"] == 60
    # Labels and metadata only: the email text, file path and link stay on the server.
    assert set(items[0]) == {"id", "label", "input_kind", "attack_type", "difficulty", "split", "title", "source"}
    assert {i["source"] for i in items} == {"generated"}


def test_sample_accepts_the_full_dataset_size(client, added_dir):
    items = client.get("/api/v1/eval/sample", params={"n": 260, "seed": 1}).json()["items"]
    assert len(items) == 260
    assert sum(i["label"] == "phishing" for i in items) == 130


# ----------------------------------------------------------------------------- adding items

def test_added_files_and_links_join_the_dataset_and_can_be_run(client, added_dir, fresh_memory):
    r = add(client, "phishing",
            files=[("phish.eml", PHISH_EML, "message/rfc822"),
                   ("saved.pdf", GENERATED_PDF.read_bytes(), "application/pdf"),
                   ("pasted.txt", b"Your account is locked. Verify now at https://paypa1-secure.com/login", "text/plain")],
            links="https://paypa1-secure.com/signin\n").json()
    assert r["rejected"] == []
    kinds = sorted(i["input_kind"] for i in r["added"])
    assert kinds == ["eml", "pdf", "plain_text", "url"]
    assert all(i["source"] == "added" and i["label"] == "phishing" for i in r["added"])
    eml_item = next(i for i in r["added"] if i["input_kind"] == "eml")
    assert eml_item["title"] == "URGENT: Your account will be suspended in 24 hours"  # from the Subject header

    listing = client.get("/api/v1/eval/items").json()
    assert len(listing["items"]) == 264 and listing["added"] == 4

    for item in r["added"]:
        run = client.post(f"/api/v1/eval/run-item/{item['id']}", params={"use_llm": "false"}).json()
        assert run.get("error") is None, run
        assert run["label"] == "phishing" and run["predicted"] in ("phishing", "legit")
    # Files are stored under the added-items folder, never with the user's file name.
    stored = sorted(p.name for p in (added_dir / "items").iterdir())
    assert all(name.startswith("added-") for name in stored) and "phish.eml" not in stored


def test_label_is_required(client, added_dir):
    r = add(client, "", files=[("a.eml", PHISH_EML, "message/rfc822")])
    assert r.status_code == 422
    assert "phishing or legit" in r.json()["detail"]["message"]


def test_nothing_to_add_is_rejected(client, added_dir):
    r = add(client, "legit")
    assert r.status_code == 422
    assert "at least one file" in r.json()["detail"]["message"]


def test_bad_files_are_rejected_one_by_one(client, added_dir):
    r = add(client, "legit", files=[
        ("notes.docx", b"PK\x03\x04 not an email", "application/octet-stream"),
        ("picture.eml", b"\x89PNG\x00\x00binary", "message/rfc822"),
        ("empty.txt", b"   ", "text/plain"),
        ("broken.pdf", b"%PDF-1.4\nthis is not really a pdf", "application/pdf"),
        ("big.txt", b"a" * (5 * 1024 * 1024 + 10), "text/plain"),
        ("ok.txt", b"Hi, are we still meeting at the library at 3?", "text/plain"),
    ], links="javascript:alert(1)\n").json()
    reasons = {x["name"]: x["reason"] for x in r["rejected"]}
    assert "Only .eml, .pdf and .txt" in reasons["notes.docx"]
    assert "doesn't look like a text file" in reasons["picture.eml"]
    assert "empty" in reasons["empty.txt"]
    assert "broken.pdf" in reasons
    assert "larger than 5 MB" in reasons["big.txt"]
    assert "Only web links" in reasons["javascript:alert(1)"]
    assert [i["title"] for i in r["added"]] == ["Hi, are we still meeting at the library at 3?"]


def test_duplicates_are_not_added_twice(client, added_dir):
    first = add(client, "phishing", files=[("a.eml", PHISH_EML, "message/rfc822")], links="https://evil.example/login").json()
    second = add(client, "phishing", files=[("copy.eml", PHISH_EML, "message/rfc822")], links="https://evil.example/login").json()
    assert len(first["added"]) == 2
    assert second["added"] == []
    assert all("already in the dataset" in x["reason"] for x in second["rejected"])


def test_added_item_can_be_removed_but_generated_ones_cannot(client, added_dir):
    item = add(client, "legit", files=[("hi.txt", b"See you at lunch.", "text/plain")]).json()["added"][0]
    stored = list((added_dir / "items").iterdir())
    assert len(stored) == 1
    assert client.delete(f"/api/v1/eval/items/{item['id']}").json() == {"removed": item["id"]}
    assert list((added_dir / "items").iterdir()) == []
    assert client.get("/api/v1/eval/items").json()["added"] == 0
    assert client.delete("/api/v1/eval/items/eml-legit-001").status_code == 403
    assert client.delete("/api/v1/eval/items/added-eml-legit-999").status_code == 404


def test_added_items_are_git_ignored():
    assert "eval/added/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


# ----------------------------------------------------------------------------- running items

@pytest.mark.parametrize("item_id", ["url-phishing-001", "eml-phishing-001", "pdf-phishing-002"])
def test_run_item_returns_a_verdict_and_remembers_nothing(client, added_dir, fresh_memory, item_id):
    r = client.post(f"/api/v1/eval/run-item/{item_id}", params={"use_llm": "false"}).json()
    assert r["id"] == item_id
    assert r["label"] == "phishing"
    assert r["predicted"] in ("phishing", "legit")
    assert r["correct"] == (r["predicted"] == "phishing")
    assert r["predicted"] == ("phishing" if r["risk_score"] >= r["threshold"] else "legit")
    assert "result" in r
    con = sqlite3.connect(fresh_memory.db_path)
    try:
        assert con.execute("SELECT COUNT(*) FROM historical_outputs").fetchone()[0] == 0
    finally:
        con.close()


def test_unknown_item_is_a_404(client, added_dir):
    assert client.post("/api/v1/eval/run-item/does-not-exist").status_code == 404


# ----------------------------------------------------------------------------- .env (plug and play)

def test_env_file_supplies_the_key_but_never_overrides_the_shell(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("﻿# comment\nGEMINI_API_KEY=from-file\nGEMINI_MODEL=\"gemini-2.5-flash\"\n", encoding="utf-8")
    monkeypatch.delenv("SCAMSHIELD_SKIP_DOTENV", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_MODEL", "set-in-shell")
    assert load_env_file(env) is True
    assert os.environ["GEMINI_API_KEY"] == "from-file"
    assert os.environ["GEMINI_MODEL"] == "set-in-shell"


def test_env_file_is_skipped_when_asked(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("GEMINI_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("SCAMSHIELD_SKIP_DOTENV", "1")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert load_env_file(env) is False
    assert "GEMINI_API_KEY" not in os.environ


def test_env_example_is_shipped_and_not_ignored():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "GEMINI_API_KEY=" in example
    assert "!.env.example" in (ROOT / ".gitignore").read_text(encoding="utf-8")
