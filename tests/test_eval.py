import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))

from metrics import average_precision, confusion, evaluate, scores, threshold_sweep  # noqa: E402

from app.domains import campus_lookalike, fake_academic_domain, find_trusted, registrable_domain  # noqa: E402


def test_confusion_and_scores_by_hand():
    labels = [1, 1, 1, 0, 0, 0]
    preds = [1, 1, 0, 1, 0, 0]
    c = confusion(labels, preds)
    assert c == {"tp": 2, "fp": 1, "tn": 2, "fn": 1}
    s = scores(c)
    assert s["precision"] == round(2 / 3, 4)
    assert s["recall"] == round(2 / 3, 4)
    assert s["f1"] == round(2 / 3, 4)
    assert s["accuracy"] == round(4 / 6, 4)


def test_undefined_precision_is_none_not_zero():
    s = scores(confusion([1, 0], [0, 0]))
    assert s["precision"] is None
    assert s["recall"] == 0.0


def test_evaluate_counts_right_and_wrong():
    m = evaluate([1, 0, 1, 0], [90, 10, 20, 70], threshold=60)
    assert (m["correct"], m["wrong"]) == (2, 2)


def test_sweep_and_average_precision():
    labels = [1, 1, 0, 0]
    sc = [90, 80, 30, 10]
    assert threshold_sweep(labels, sc)["best"]["f1"] == 1.0
    assert average_precision(labels, sc) == 1.0


def test_generic_fake_academic_domain():
    assert fake_academic_domain("westbrook.edu-verify.com") == "westbrook.edu"
    assert fake_academic_domain("student.westbrook.ac.uk.account-check.co") == "westbrook.ac.uk"
    assert fake_academic_domain("westbrook-edu.com") == "westbrook.edu"
    assert fake_academic_domain("my-westbrook-edu.net") == "westbrook.edu"
    # real academic domains and unrelated sites are never flagged
    assert fake_academic_domain("portal.westbrook.edu") is None
    assert fake_academic_domain("ui.ac.id") is None
    assert fake_academic_domain("github.com") is None
    assert fake_academic_domain("edu-tools.com") is None
    assert fake_academic_domain("my-edu-portal.com") is None


def test_optional_campus_lookalike_cases():
    assert campus_lookalike("westbr0ok.edu", ["westbrook.edu"]) == "westbrook.edu"
    assert campus_lookalike("wesbtrook.edu", ["westbrook.edu"]) == "westbrook.edu"
    assert campus_lookalike("westbrook-login.com", ["westbrook.edu"]) == "westbrook.edu"
    assert campus_lookalike("portal.westbrook.edu", ["westbrook.edu"]) is None
    assert campus_lookalike("github.com", ["westbrook.edu"]) is None
    assert campus_lookalike("ui-login.com", ["ui.ac.id"]) is None  # too short to compare safely
    assert campus_lookalike("westbr0ok.edu", []) is None  # nothing configured: generic mode


def test_trusted_subdomains_and_multi_part_suffixes():
    assert find_trusted("docs.github.com", {"github.com": "Dev"}) == ("github.com", "Dev")
    assert find_trusted("evilgithub.com", {"github.com": "Dev"}) is None
    assert registrable_domain("portal.ui.ac.id") == "ui.ac.id"
