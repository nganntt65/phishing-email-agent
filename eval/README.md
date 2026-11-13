# Evaluation

## Dataset (`generate_dataset.py`)

260 synthetic items, reproducible byte-for-byte from `--seed 42`:

| Kind | Phishing | Legit |
|---|---|---|
| `.eml` | 75 | 75 |
| PDF (Print to PDF; 2 of 3 keep link targets) | 15 | 15 |
| Plain text, no headers (reported separately) | 10 | 10 |
| URL | 30 | 30 |

- Five fictional universities (westbrook.edu, lakesidetech.edu, harrowgate.ac.uk, meridian.ac.id, carrickstate.edu). CampusGuard AI itself knows none of them; the evaluation runs with no campus configured.
- 12 phishing scenario types (university login lure, brand lookalike, mailbox quota, BEC wire, invoice/ACH change, gift cards, executable attachment, prompt injection, polite phish, no-link pretext, scholarship fee, short-link delivery) and 12 legitimate types.
- Deliberate **hard cases**: attacker-owned domains that pass SPF/DKIM/DMARC with polite wording; BEC from Gmail with no link; real bank alerts and password resets with urgent wording; student clubs and a credit union whose domains contain the university's name; typo domains on a real academic TLD (westbr0ok.edu), which no generic rule can catch.
- Stratified 50/50 **dev/test** split per (kind, label).
- The 8 hand-written demo emails in `app/sample_emails.py` are **excluded** (the rules were tuned on them).
- `--paraphrase` rewrites bodies with Gemini (cached) to reduce template overlap.

## Protocol (`run_eval.py`)

1. Change rules, prompts and thresholds while looking at **dev** only.
2. Freeze. Run **test** once and report it.
3. Headline threshold: risk score **≥ 60** (fixed before looking at data).
4. Secondary threshold: chosen on dev among the product's action thresholds (30 / 60 / 85), then applied once to test.

Systems:

| System | What it is |
|---|---|
| `rules` | full pipeline, Gemini off |
| `ml_baseline` | TF-IDF + logistic regression trained on dev |
| `ml_unseen_types` | same model, trained on half the attack types, tested on the other half |
| `llm_hybrid` | full pipeline with Gemini in **strict** mode (failures are counted, never silently replaced) |
| `llm_only` | Gemini's own score without the deterministic tool totals |

Gemini systems are skipped (with the reason recorded) when `GEMINI_API_KEY` isn't set. Responses are cached in `eval/cache/llm/`, so re-runs are free.

## Reading the numbers honestly

- **Synthetic data.** Say "on this dataset", never "detects X% of phishing".
- **Template leakage.** `ml_baseline` scores near 1.0 on emails because dev and test share scenario templates, so it learns template wording. `ml_unseen_types` is the fair ML number. Compare it with `rules_on_same_items` in the report.
- **Circularity.** The same person wrote the generator templates and the rule engine. Only general, documented rubric rules were added after looking at dev errors (money/credential requests; executable-attachment override). See `agent_framework/skills/`.
- **The 13 November 2026 rules (scam scripts, sender verification, first-party links, new link checks) were designed after reviewing the misses on the whole dataset, dev and test.** The test-split number is therefore no longer a clean held-out result for those rules. The rules are written around scam mechanics (gift cards, release fees, bank-detail changes, lookalike domains), not around dataset sentences, and the only held-out check is a 16-email hand-written set (8 scams, 8 genuine; 16/16) kept outside the repository. Treat the test number as an upper bound until new items are generated or real data is added.
- **Plain text** has no headers or link targets. It's reported separately and is expected to be weak for the rules.
