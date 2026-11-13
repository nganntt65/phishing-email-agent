"""Plain-Python classification metrics (no sklearn needed, so they are easy to audit)."""

import math
from typing import Any, Dict, Iterable, List, Optional, Sequence


def confusion(labels: Sequence[int], preds: Sequence[int]) -> Dict[str, int]:
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _safe_div(a: float, b: float) -> Optional[float]:
    return None if b == 0 else a / b


def scores(c: Dict[str, int]) -> Dict[str, Optional[float]]:
    """Precision/recall/F1/accuracy. None when undefined (e.g. no positive predictions)."""
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None if (precision is None or recall is None) else 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    accuracy = _safe_div(tp + tn, tp + fp + tn + fn)
    specificity = _safe_div(tn, tn + fp)

    def r(x: Optional[float]) -> Optional[float]:
        return None if x is None else round(x, 4)

    return {"precision": r(precision), "recall": r(recall), "f1": r(f1), "accuracy": r(accuracy),
            "specificity": r(specificity)}


def evaluate(labels: Sequence[int], risk_scores: Sequence[float], threshold: float) -> Dict[str, Any]:
    preds = [1 if s >= threshold else 0 for s in risk_scores]
    c = confusion(labels, preds)
    return {
        "n": len(labels),
        **c,
        "correct": c["tp"] + c["tn"],
        "wrong": c["fp"] + c["fn"],
        **scores(c),
    }


def threshold_sweep(labels: Sequence[int], risk_scores: Sequence[float], step: int = 5) -> Dict[str, Any]:
    points: List[Dict[str, Any]] = []
    for t in range(0, 101, step):
        m = evaluate(labels, risk_scores, t)
        points.append({"threshold": t, "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
                       "fp": m["fp"], "fn": m["fn"]})
    valid = [p for p in points if p["f1"] is not None]
    best = max(valid, key=lambda p: (p["f1"], -abs(p["threshold"] - 60))) if valid else None
    return {"points": points, "best": best}


def average_precision(labels: Sequence[int], risk_scores: Sequence[float]) -> Optional[float]:
    """Area under the precision-recall curve (step interpolation over unique scores)."""
    positives = sum(labels)
    if positives == 0:
        return None
    ranked = sorted(zip(risk_scores, labels), key=lambda x: -x[0])
    ap, tp, fp, last_recall = 0.0, 0, 0, 0.0
    i = 0
    while i < len(ranked):
        score = ranked[i][0]
        while i < len(ranked) and ranked[i][0] == score:
            tp += ranked[i][1]
            fp += 1 - ranked[i][1]
            i += 1
        recall = tp / positives
        precision = tp / (tp + fp)
        ap += (recall - last_recall) * precision
        last_recall = recall
    return round(ap, 4)


def latency_stats(values: Iterable[float]) -> Dict[str, Optional[float]]:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return {"mean_ms": None, "p95_ms": None}
    p95 = vals[min(len(vals) - 1, math.ceil(0.95 * len(vals)) - 1)]
    return {"mean_ms": round(sum(vals) / len(vals), 1), "p95_ms": round(p95, 1)}
