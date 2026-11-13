"""Evaluation harness.

    .venv\\Scripts\\python.exe eval\\run_eval.py                 # test split, all systems available
    .venv\\Scripts\\python.exe eval\\run_eval.py --split dev     # tune on dev only

Systems compared:
- rules        full pipeline, Gemini off (deterministic rule engine)
- ml_baseline  TF-IDF + Logistic Regression trained on the dev split
- llm_hybrid   full pipeline with Gemini in STRICT mode (a failed call is an error, never a silent fallback)
- llm_only     Gemini's own final score without the deterministic tool totals (derived from llm_hybrid)

Gemini systems are skipped, with the reason recorded, when GEMINI_API_KEY is not set.
Outputs: eval/results/latest/{summary.json, results.jsonl, report.md}
"""

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "eval" / "data"
RESULTS_DIR = ROOT / "eval" / "results" / "latest"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))


def _prepare_environment(manifest: Dict[str, Any]) -> None:
    """Pin everything that would otherwise make results depend on the machine they run on."""
    # Generic CampusGuard AI: no campus configured, so nothing can be tuned to one university's name.
    os.environ["CAMPUS_NAME"] = ""
    os.environ["CAMPUS_DOMAINS"] = ""
    os.environ["CAMPUS_PORTAL_URL"] = ""
    os.environ["REDIS_DISABLED"] = "1"
    os.environ["CAMPAIGN_DB_PATH"] = os.path.join(tempfile.mkdtemp(prefix="scamshield-eval-"), "memory.db")
    os.environ.setdefault("LLM_CACHE_DIR", str(ROOT / "eval" / "cache" / "llm"))
    # Batch runs can afford to wait out a free-tier rate limit; interactive scans keep the 30 s default.
    # Items run one at a time (no concurrency), so this is the only pacing needed.
    os.environ.setdefault("LLM_DEADLINE_SECONDS", "180")
    os.environ.setdefault("LLM_TIMEOUT_SECONDS", "60")


def _load() -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if not (DATA_DIR / "dataset.jsonl").exists():
        raise SystemExit("No dataset. Run: .venv\\Scripts\\python.exe eval\\generate_dataset.py")
    with open(DATA_DIR / "dataset.jsonl", encoding="utf-8") as fh:
        items = [json.loads(l) for l in fh if l.strip()]
    with open(DATA_DIR / "manifest.json", encoding="utf-8") as fh:
        manifest = json.load(fh)
    return items, manifest


async def _run_pipeline(item: Dict[str, Any], use_llm: bool, strict: bool) -> Any:
    from app.link_scan import analyze_url
    from app.orchestrator import orchestrator

    kind = item["input_kind"]
    if kind == "url":
        return await analyze_url(item["url"], use_llm=use_llm, strict_llm=strict)
    path = DATA_DIR / item["path"]
    if kind == "pdf":
        return await orchestrator.analyze_pdf_bytes(path.read_bytes(), use_llm=use_llm, strict_llm=strict, record_memory=False)
    return await orchestrator.analyze_raw_eml(path.read_text(encoding="utf-8"), use_llm=use_llm, strict_llm=strict,
                                              record_memory=False)


def _ml_text(item: Dict[str, Any]) -> str:
    from app.pdf_parser import parse_pdf, to_payload
    from app.sanitizer import preprocess_and_sanitize_eml
    from baseline_ml import email_features_text

    kind = item["input_kind"]
    if kind == "url":
        return item["url"]
    path = DATA_DIR / item["path"]
    payload = to_payload(parse_pdf(path.read_bytes())) if kind == "pdf" else preprocess_and_sanitize_eml(
        path.read_text(encoding="utf-8"))
    return email_features_text(payload.headers.subject, payload.body_text, payload.extracted_urls,
                               payload.headers.from_domain)


def _row(item: Dict[str, Any], system: str, threshold: int, **kw: Any) -> Dict[str, Any]:
    score = kw.get("risk_score")
    row = {
        "id": item["id"], "system": system, "split": item["split"], "label": item["label"],
        "input_kind": item["input_kind"], "attack_type": item["attack_type"], "difficulty": item["difficulty"],
        "title": item.get("title", ""), "risk_score": score, "error": kw.get("error"),
        "latency_ms": kw.get("latency_ms"), "llm_status": kw.get("llm_status"),
        "finding": kw.get("finding"), "reasons": kw.get("reasons", []), "explanation": kw.get("explanation"),
        "groundedness": kw.get("groundedness"),
    }
    if score is not None:
        row["predicted"] = "phishing" if score >= threshold else "legit"
        row["correct"] = row["predicted"] == item["label"]
    return row


def _reasons(result: Any) -> List[str]:
    if hasattr(result, "reasons"):
        return list(result.reasons)[:4]
    out = [f for f in result.sender_integrity.findings[:2]] + [f for f in result.url_scan.findings[:2]]
    return out + [t for t in result.psychological_tactics[:2]]


async def run_pipeline_system(items: List[Dict[str, Any]], system: str, use_llm: bool, threshold: int) -> List[Dict[str, Any]]:
    from app.llm import LLMUnavailableError
    from app.pdf_parser import UnreadablePdfError

    rows = []
    for index, item in enumerate(items, 1):
        started = time.perf_counter()
        try:
            result = await _run_pipeline(item, use_llm=use_llm, strict=use_llm)
        except (LLMUnavailableError, UnreadablePdfError) as exc:
            rows.append(_row(item, system, threshold, error=f"{type(exc).__name__}: {exc}"))
            continue
        latency = (time.perf_counter() - started) * 1000
        rows.append(_row(
            item, system, threshold, risk_score=result.risk_score, latency_ms=round(latency, 1),
            llm_status=result.llm_status.value, finding=result.summary.finding if result.summary else None,
            reasons=_reasons(result), groundedness=getattr(result, "groundedness", None),
        ))
        if system == "llm_hybrid":
            rows[-1]["llm_final_risk_score"] = getattr(result, "llm_final_risk_score", None)
        if index % 25 == 0:
            print(f"  {system}: {index}/{len(items)}", flush=True)
    return rows


def run_ml(items: List[Dict[str, Any]], dev: List[Dict[str, Any]], threshold: int):
    from baseline_ml import BaselineModel

    label = lambda i: 1 if i["label"] == "phishing" else 0  # noqa: E731
    text_rows = [(_ml_text(i), label(i)) for i in dev if i["input_kind"] != "url"]
    url_rows = [(_ml_text(i), label(i)) for i in dev if i["input_kind"] == "url"]
    started = time.perf_counter()
    model = BaselineModel().fit(text_rows, url_rows)
    train_ms = (time.perf_counter() - started) * 1000

    rows = []
    for item in items:
        is_url = item["input_kind"] == "url"
        text = _ml_text(item)
        t0 = time.perf_counter()
        score = model.score(text, is_url)
        latency = (time.perf_counter() - t0) * 1000
        rows.append(_row(item, "ml_baseline", threshold, risk_score=round(score, 1), latency_ms=round(latency, 2),
                         explanation=model.explain(text, is_url)))
    global_features = {"text": model.global_top_features(False), "url": model.global_top_features(True)}
    return rows, global_features, round(train_ms, 1), len(text_rows) + len(url_rows)


def summarize_system(rows: List[Dict[str, Any]], threshold: int) -> Dict[str, Any]:
    from metrics import average_precision, evaluate, latency_stats, threshold_sweep

    scored = [r for r in rows if r.get("risk_score") is not None]
    failures = [r for r in rows if r.get("risk_score") is None]

    def block(subset: List[Dict[str, Any]]) -> Dict[str, Any]:
        y = [1 if r["label"] == "phishing" else 0 for r in subset]
        s = [r["risk_score"] for r in subset]
        return evaluate(y, s, threshold) if subset else {"n": 0}

    main = [r for r in scored if r["input_kind"] != "plain_text"]
    y_main = [1 if r["label"] == "phishing" else 0 for r in main]
    s_main = [r["risk_score"] for r in main]
    groups: Dict[str, Dict[str, Any]] = {}
    for key in ("input_kind", "difficulty", "attack_type"):
        buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in scored:
            buckets[r[key]].append(r)
        groups[key] = {k: block(v) for k, v in sorted(buckets.items())}

    grounded = [r["groundedness"] for r in scored if r.get("groundedness") is not None]
    return {
        "status": "ok",
        "overall": block(main),
        "overall_including_plain_text": block(scored),
        "by_input_kind": groups["input_kind"],
        "by_difficulty": groups["difficulty"],
        "by_attack_type": groups["attack_type"],
        "threshold_sweep": threshold_sweep(y_main, s_main) if main else None,
        "average_precision": average_precision(y_main, s_main) if main else None,
        "latency": latency_stats(r["latency_ms"] for r in scored),
        "failures": len(failures),
        "failure_examples": [{"id": r["id"], "error": r["error"]} for r in failures[:10]],
        "groundedness_mean": round(sum(grounded) / len(grounded), 3) if grounded else None,
    }


def _main_xy(rows: List[Dict[str, Any]]):
    main = [r for r in rows if r.get("risk_score") is not None and r["input_kind"] != "plain_text"]
    return [1 if r["label"] == "phishing" else 0 for r in main], [r["risk_score"] for r in main]


# Thresholds that correspond to real product actions (CAUTION_BANNER / WARN / QUARANTINE).
PRODUCT_THRESHOLDS = (30, 60, 85)


def _secondary_from_dev(dev_rows: List[Dict[str, Any]], test_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Choose among the product's action thresholds on DEV, then apply once to TEST."""
    from metrics import evaluate

    y_dev, s_dev = _main_xy(dev_rows)
    dev_f1 = {t: (evaluate(y_dev, s_dev, t)["f1"] or 0.0) for t in PRODUCT_THRESHOLDS}
    chosen = max(PRODUCT_THRESHOLDS, key=lambda t: (dev_f1[t], t))
    y_test, s_test = _main_xy(test_rows)
    return {"threshold": chosen,
            "selected_on": f"dev split among action thresholds {PRODUCT_THRESHOLDS} (dev F1 {dev_f1[chosen]:.3f})",
            **evaluate(y_test, s_test, chosen)}


def run_ml_unseen_types(items: List[Dict[str, Any]], threshold: int):
    """Harder, fairer ML test: train on some attack types, test on types it has never seen.

    Within each (input_kind, label), attack types are sorted and alternately assigned to group A or B.
    Train on dev items of group A; evaluate on test items of group B. Template wording can no longer
    leak from training to evaluation through a shared scenario.
    """
    from baseline_ml import BaselineModel

    groups: Dict[tuple, List[str]] = defaultdict(list)
    for i in items:
        key = (i["input_kind"], i["label"])
        if i["attack_type"] not in groups[key]:
            groups[key].append(i["attack_type"])
    group_a = {(k, t) for k, types in groups.items() for idx, t in enumerate(sorted(types)) if idx % 2 == 0}

    def in_a(i):
        return ((i["input_kind"], i["label"]), i["attack_type"]) in group_a

    train = [i for i in items if i["split"] == "dev" and in_a(i)]
    test = [i for i in items if i["split"] == "test" and not in_a(i)]
    label = lambda i: 1 if i["label"] == "phishing" else 0  # noqa: E731
    model = BaselineModel().fit(
        [(_ml_text(i), label(i)) for i in train if i["input_kind"] != "url"],
        [(_ml_text(i), label(i)) for i in train if i["input_kind"] == "url"],
    )
    rows = []
    for item in test:
        is_url = item["input_kind"] == "url"
        text = _ml_text(item)
        rows.append(_row(item, "ml_unseen_types", threshold, risk_score=round(model.score(text, is_url), 1),
                         explanation=model.explain(text, is_url)))
    return rows, len(train)


def _secondary_fixed(rows: List[Dict[str, Any]], threshold: int, why: str) -> Dict[str, Any]:
    from metrics import evaluate

    y, s = _main_xy(rows)
    return {"threshold": threshold, "selected_on": why, **evaluate(y, s, threshold)}


def errors_for(rows: List[Dict[str, Any]], limit: int = 40) -> List[Dict[str, Any]]:
    wrong = [r for r in rows if r.get("correct") is False]
    wrong.sort(key=lambda r: (r["label"], r["input_kind"], r["id"]))
    keep = ("id", "label", "predicted", "risk_score", "input_kind", "attack_type", "difficulty", "title", "finding",
            "reasons", "explanation")
    return [{k: r.get(k) for k in keep} for r in wrong[:limit]]


def _fmt(x: Optional[float]) -> str:
    return "—" if x is None else f"{x:.3f}"


def write_report(summary: Dict[str, Any]) -> str:
    lines = [
        "# CampusGuard AI evaluation report",
        "",
        f"- Run: {summary['run_at']}",
        f"- Split: **{summary['split']}** ({summary['n_items']} items; plain-text items reported separately)",
        f"- Phishing threshold: risk score ≥ **{summary['threshold']}**",
        f"- Dataset: synthetic, seed {summary['dataset']['seed']}, {len(summary['dataset']['universities'])} fictional universities",
        "",
        "> Synthetic data. These numbers describe this dataset, not real-world accuracy.",
        "",
        "## Systems",
        "",
        "| System | Status | n | Correct | Wrong | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | AP |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, s in summary["systems"].items():
        if s["status"] != "ok":
            lines.append(f"| {name} | skipped: {s['reason']} | | | | | | | | | | | | |")
            continue
        o = s["overall"]
        lines.append(
            f"| {name} | ok | {o['n']} | {o['correct']} | {o['wrong']} | {o['tp']} | {o['fp']} | {o['tn']} | {o['fn']} | "
            f"{_fmt(o['precision'])} | {_fmt(o['recall'])} | {_fmt(o['f1'])} | {_fmt(o['accuracy'])} | "
            f"{_fmt(s['average_precision'])} |"
        )
    for name, s in summary["systems"].items():
        if s["status"] != "ok":
            continue
        lines += ["", f"## {name}", ""]
        sec = s.get("secondary")
        if sec:
            lines.append(f"Secondary: threshold {sec['threshold']} chosen on {sec['selected_on']} → "
                         f"correct {sec['correct']}, wrong {sec['wrong']}, precision {_fmt(sec['precision'])}, "
                         f"recall {_fmt(sec['recall'])}, F1 {_fmt(sec['f1'])}.")
        best = (s.get("threshold_sweep") or {}).get("best")
        if best:
            lines.append(f"Best F1 if the threshold were picked on this split itself: {_fmt(best['f1'])} at "
                         f"{best['threshold']} (hindsight; not a fair number, shown for insight only).")
        if s.get("trained_on"):
            lines.append(f"Trained on: {s['trained_on']}.")
        same = s.get("rules_on_same_items")
        if same:
            lines.append(f"Rules on the same {same['n']} items: F1 {_fmt(same['f1'])} at {same['threshold']}, "
                         f"F1 {_fmt(same['at_30']['f1'])} at 30 (no training needed).")
        if s.get("failures"):
            lines.append(f"Excluded failures: {s['failures']} (see summary.json).")
        if s.get("groundedness_mean") is not None:
            lines.append(f"LLM evidence groundedness: {s['groundedness_mean']:.1%} of quotes found verbatim in the email.")
        lines += ["", "| Input kind | n | Correct | Wrong | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|"]
        for k, b in s["by_input_kind"].items():
            lines.append(f"| {k} | {b['n']} | {b.get('correct', 0)} | {b.get('wrong', 0)} | {_fmt(b.get('precision'))} | "
                         f"{_fmt(b.get('recall'))} | {_fmt(b.get('f1'))} |")
        lines += ["", "| Difficulty | n | Correct | Wrong | F1 |", "|---|---|---|---|---|"]
        for k, b in s["by_difficulty"].items():
            lines.append(f"| {k} | {b['n']} | {b.get('correct', 0)} | {b.get('wrong', 0)} | {_fmt(b.get('f1'))} |")
        errs = summary["errors"].get(name, [])
        if errs:
            lines += ["", f"### Misclassified ({len(errs)} shown)", "", "| Item | Label | Predicted | Score | Kind | Type |",
                      "|---|---|---|---|---|---|"]
            for e in errs:
                lines.append(f"| {e['id']} | {e['label']} | {e['predicted']} | {e['risk_score']} | {e['input_kind']} | "
                             f"{e['attack_type']} |")
    ml = summary.get("ml_global_features")
    if ml:
        lines += ["", "## ML baseline: strongest features", "",
                  f"- Text → phishing: {', '.join(ml['text']['phishing'][:8])}",
                  f"- Text → legit: {', '.join(ml['text']['legit'][:8])}",
                  f"- URL → phishing: {', '.join(ml['url']['phishing'][:8])}"]
    lines += ["", "## Notes", ""] + [f"- {n}" for n in summary["notes"]]
    return "\n".join(lines) + "\n"


async def main_async(args: argparse.Namespace) -> Dict[str, Any]:
    items, manifest = _load()
    _prepare_environment(manifest)

    from app import config, llm
    from app.redis_store import redis_store

    await redis_store.initialize()
    threshold = args.threshold if args.threshold is not None else config.PHISHING_THRESHOLD
    target = [i for i in items if args.split == "all" or i["split"] == args.split]
    dev = [i for i in items if i["split"] == "dev"]
    requested = [s.strip() for s in args.systems.split(",") if s.strip()]

    all_rows: List[Dict[str, Any]] = []
    systems: Dict[str, Dict[str, Any]] = {}
    errors: Dict[str, List[Dict[str, Any]]] = {}
    ml_global = None
    notes = [
        "The 8 hand-written demo emails (app/sample_emails.py) are excluded: the rules were tuned on them.",
        "Each item is judged independently (campaign memory writes are disabled during evaluation).",
        "Trusted domains come from the built-in list (Redis disabled) so results don't depend on a local server.",
    ]

    if "rules" in requested:
        print("Running rules ...", flush=True)
        rows = await run_pipeline_system(target, "rules", use_llm=False, threshold=threshold)
        all_rows += rows
        systems["rules"] = summarize_system(rows, threshold)
        errors["rules"] = errors_for(rows)
        if args.split == "test":
            # Secondary number: pick the threshold on DEV, apply it once to TEST.
            dev_rows = await run_pipeline_system(dev, "rules", use_llm=False, threshold=threshold)
            systems["rules"]["secondary"] = _secondary_from_dev(dev_rows, rows)

    if "ml_baseline" in requested:
        print("Training + running ml_baseline ...", flush=True)
        rows, ml_global, train_ms, n_train = run_ml(target, dev, threshold)
        all_rows += rows
        systems["ml_baseline"] = summarize_system(rows, threshold)
        systems["ml_baseline"]["trained_on"] = f"dev split ({n_train} items) in {train_ms} ms"
        systems["ml_baseline"]["secondary"] = _secondary_fixed(rows, 50, "probability 0.5 (the model's own decision boundary)")
        errors["ml_baseline"] = errors_for(rows)
        if args.split in ("dev", "all"):
            notes.append("ml_baseline is scored on data that includes its own training split; use --split test for a fair number.")
        else:
            unseen_rows, n_unseen_train = run_ml_unseen_types(items, threshold)
            all_rows += unseen_rows
            systems["ml_unseen_types"] = summarize_system(unseen_rows, threshold)
            systems["ml_unseen_types"]["trained_on"] = (
                f"dev items of half the attack types ({n_unseen_train} items); tested on the other half's test items"
            )
            systems["ml_unseen_types"]["secondary"] = _secondary_fixed(unseen_rows, 50, "probability 0.5")
            errors["ml_unseen_types"] = errors_for(unseen_rows)
            unseen_ids = {r["id"] for r in unseen_rows}
            rules_same = [dict(r, system="rules") for r in all_rows if r["system"] == "rules" and r["id"] in unseen_ids]
            if rules_same:
                y, s = _main_xy(rules_same)
                from metrics import evaluate as _evaluate
                systems["ml_unseen_types"]["rules_on_same_items"] = {
                    "threshold": threshold, **_evaluate(y, s, threshold),
                    "at_30": _evaluate(y, s, 30),
                }
            notes.append(
                "ml_baseline shares scenario templates between dev and test, so it can memorise template wording; "
                "ml_unseen_types tests it on attack types it never saw and is the fairer ML number."
            )

    want_llm = [s for s in ("llm_hybrid", "llm_only") if s in requested]
    if want_llm:
        if not llm.api_key():
            for name in want_llm:
                systems[name] = {"status": "skipped", "reason": "GEMINI_API_KEY is not set"}
            notes.append("Gemini systems were skipped because no API key was configured. Set GEMINI_API_KEY and re-run.")
        else:
            print("Running llm_hybrid (strict, cached) ...", flush=True)
            rows = await run_pipeline_system(target, "llm_hybrid", use_llm=True, threshold=threshold)
            all_rows += rows
            if "llm_hybrid" in requested:
                systems["llm_hybrid"] = summarize_system(rows, threshold)
                systems["llm_hybrid"]["model"] = llm.primary_model()
                errors["llm_hybrid"] = errors_for(rows)
            if "llm_only" in requested:
                only_rows = []
                for r in rows:
                    if r["input_kind"] == "url":
                        continue  # the link scan verdict is deterministic; Gemini only writes the explanation
                    item = next(i for i in target if i["id"] == r["id"])
                    only_rows.append(_row(item, "llm_only", threshold, risk_score=r.get("llm_final_risk_score"),
                                          error=r.get("error"), latency_ms=r.get("latency_ms"), llm_status=r.get("llm_status"),
                                          finding=r.get("finding")))
                all_rows += only_rows
                systems["llm_only"] = summarize_system(only_rows, threshold)
                systems["llm_only"]["note"] = "URL items excluded: link verdicts are deterministic."
                errors["llm_only"] = errors_for(only_rows)

    summary = {
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "split": args.split,
        "threshold": threshold,
        "n_items": len(target),
        "dataset": {k: manifest[k] for k in ("seed", "universities", "total", "by_kind_label", "generator_version", "paraphrased")},
        "systems": systems,
        "errors": errors,
        "ml_global_features": ml_global,
        "notes": notes,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_DIR / "results.jsonl", "w", encoding="utf-8") as fh:
        for row in all_rows:
            fh.write(json.dumps(row) + "\n")
    with open(RESULTS_DIR / "summary.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    (RESULTS_DIR / "report.md").write_text(write_report(summary), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--split", choices=["test", "dev", "all"], default="test")
    parser.add_argument("--systems", default="rules,ml_baseline,llm_hybrid,llm_only")
    parser.add_argument("--threshold", type=int, default=None, help="default: PHISHING_THRESHOLD (60)")
    args = parser.parse_args()
    summary = asyncio.run(main_async(args))
    print()
    for name, s in summary["systems"].items():
        if s["status"] != "ok":
            print(f"{name:12} skipped: {s['reason']}")
            continue
        o = s["overall"]
        print(f"{name:12} n={o['n']:3}  correct={o['correct']:3}  wrong={o['wrong']:3}  "
              f"P={_fmt(o['precision'])}  R={_fmt(o['recall'])}  F1={_fmt(o['f1'])}  failures={s['failures']}")
    print(f"\nReport: {RESULTS_DIR / 'report.md'}")


if __name__ == "__main__":
    main()
