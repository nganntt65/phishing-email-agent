"""Classic ML baseline: TF-IDF + Logistic Regression.

Two small models, both trained on the DEV split only:
- text model for emails (.eml, PDF, plain text): word 1-2 grams + character 3-5 grams over
  subject, body and link hosts;
- URL model for links: character 2-5 grams over the URL.

The point of this baseline is comparison: if the agent can't beat it, the agent isn't adding value.
Explanations come for free: the per-token contribution (tf-idf value x coefficient).
"""

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline


def _text_pipeline() -> Pipeline:
    return Pipeline([
        ("features", FeatureUnion([
            ("words", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)),
            ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
        ])),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=3000, C=4.0)),
    ])


def _url_pipeline() -> Pipeline:
    return Pipeline([
        ("features", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), sublinear_tf=True, lowercase=True)),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=3000, C=4.0)),
    ])


def email_features_text(subject: str, body: str, urls: List[str], sender_domain: str) -> str:
    hosts = " ".join((urlparse(u).hostname or "") + (urlparse(u).path or "") for u in urls)
    return f"{subject}\n{body}\nsender {sender_domain}\nlinks {hosts}"


class BaselineModel:
    def __init__(self) -> None:
        self.text_model = _text_pipeline()
        self.url_model = _url_pipeline()

    def fit(self, text_rows: List[Tuple[str, int]], url_rows: List[Tuple[str, int]]) -> "BaselineModel":
        self.text_model.fit([t for t, _ in text_rows], [y for _, y in text_rows])
        self.url_model.fit([u for u, _ in url_rows], [y for _, y in url_rows])
        return self

    def score(self, text: str, is_url: bool) -> float:
        model = self.url_model if is_url else self.text_model
        return float(model.predict_proba([text])[0][1] * 100.0)

    def explain(self, text: str, is_url: bool, top_k: int = 5) -> List[Dict[str, Any]]:
        """Tokens that pushed this prediction most (positive = towards phishing)."""
        model = self.url_model if is_url else self.text_model
        features = model.named_steps["features"]
        coef = model.named_steps["clf"].coef_[0]
        row = features.transform([text]).tocoo()
        names = features.get_feature_names_out()
        contributions = [(names[j], float(v * coef[j])) for j, v in zip(row.col, row.data)]
        contributions.sort(key=lambda x: -abs(x[1]))
        return [{"feature": n.split("__", 1)[-1], "weight": round(w, 3)} for n, w in contributions[:top_k]]

    def global_top_features(self, is_url: bool, top_k: int = 10) -> Dict[str, List[str]]:
        model = self.url_model if is_url else self.text_model
        names = model.named_steps["features"].get_feature_names_out()
        coef = model.named_steps["clf"].coef_[0]
        order = coef.argsort()
        clean = [n.split("__", 1)[-1] for n in names]
        return {
            "phishing": [clean[i] for i in order[::-1][:top_k]],
            "legit": [clean[i] for i in order[:top_k]],
        }
