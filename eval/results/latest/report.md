# CampusGuard AI evaluation report

- Run: 2026-11-13T00:02:09+00:00
- Split: **test** (132 items; plain-text items reported separately)
- Phishing threshold: risk score ≥ **60**
- Dataset: synthetic, seed 42, 5 fictional universities

> Synthetic data. These numbers describe this dataset, not real-world accuracy.

## Systems

| System | Status | n | Correct | Wrong | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| rules | ok | 122 | 118 | 4 | 57 | 0 | 61 | 4 | 1.000 | 0.934 | 0.966 | 0.967 | 0.967 |
| ml_baseline | ok | 122 | 116 | 6 | 55 | 0 | 61 | 6 | 1.000 | 0.902 | 0.948 | 0.951 | 0.998 |
| ml_unseen_types | ok | 58 | 35 | 23 | 20 | 17 | 15 | 6 | 0.540 | 0.769 | 0.635 | 0.603 | 0.607 |
| llm_hybrid | skipped: GEMINI_API_KEY is not set | | | | | | | | | | | | |
| llm_only | skipped: GEMINI_API_KEY is not set | | | | | | | | | | | | |

## rules

Secondary: threshold 60 chosen on dev split among action thresholds (30, 60, 85) (dev F1 0.974) → correct 118, wrong 4, precision 1.000, recall 0.934, F1 0.966.
Best F1 if the threshold were picked on this split itself: 0.966 at 60 (hindsight; not a fair number, shown for insight only).

| Input kind | n | Correct | Wrong | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| eml | 76 | 73 | 3 | 1.000 | 0.921 | 0.959 |
| pdf | 16 | 15 | 1 | 1.000 | 0.875 | 0.933 |
| plain_text | 10 | 9 | 1 | 1.000 | 0.800 | 0.889 |
| url | 30 | 30 | 0 | 1.000 | 1.000 | 1.000 |

| Difficulty | n | Correct | Wrong | F1 |
|---|---|---|---|---|
| easy | 39 | 38 | 1 | 0.979 |
| hard | 41 | 37 | 4 | 0.882 |
| medium | 52 | 52 | 0 | 1.000 |

### Misclassified (5 shown)

| Item | Label | Predicted | Score | Kind | Type |
|---|---|---|---|---|---|
| eml-phishing-009 | phishing | legit | 0 | eml | polite_phish |
| eml-phishing-021 | phishing | legit | 0 | eml | polite_phish |
| eml-phishing-069 | phishing | legit | 0 | eml | polite_phish |
| pdf-phishing-008 | phishing | legit | 0 | pdf | polite_phish |
| plain_text-phishing-007 | phishing | legit | 0 | plain_text | malware_attachment |

## ml_baseline

Secondary: threshold 50 chosen on probability 0.5 (the model's own decision boundary) → correct 118, wrong 4, precision 0.983, recall 0.951, F1 0.967.
Best F1 if the threshold were picked on this split itself: 0.968 at 40 (hindsight; not a fair number, shown for insight only).
Trained on: dev split (128 items) in 166.0 ms.

| Input kind | n | Correct | Wrong | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| eml | 76 | 76 | 0 | 1.000 | 1.000 | 1.000 |
| pdf | 16 | 16 | 0 | 1.000 | 1.000 | 1.000 |
| plain_text | 10 | 10 | 0 | 1.000 | 1.000 | 1.000 |
| url | 30 | 24 | 6 | 1.000 | 0.600 | 0.750 |

| Difficulty | n | Correct | Wrong | F1 |
|---|---|---|---|---|
| easy | 39 | 37 | 2 | 0.957 |
| hard | 41 | 38 | 3 | 0.914 |
| medium | 52 | 51 | 1 | 0.978 |

### Misclassified (6 shown)

| Item | Label | Predicted | Score | Kind | Type |
|---|---|---|---|---|---|
| url-phishing-002 | phishing | legit | 46.5 | url | university_typo |
| url-phishing-006 | phishing | legit | 56.9 | url | university_lookalike |
| url-phishing-014 | phishing | legit | 59.4 | url | university_lookalike |
| url-phishing-020 | phishing | legit | 45.4 | url | risky_tld_login |
| url-phishing-021 | phishing | legit | 53.0 | url | shortlink |
| url-phishing-027 | phishing | legit | 43.8 | url | university_typo |

## ml_unseen_types

Secondary: threshold 50 chosen on probability 0.5 → correct 36, wrong 22, precision 0.548, recall 0.885, F1 0.676.
Best F1 if the threshold were picked on this split itself: 0.687 at 55 (hindsight; not a fair number, shown for insight only).
Trained on: dev items of half the attack types (59 items); tested on the other half's test items.
Rules on the same 58 items: F1 0.980 at 60, F1 0.943 at 30 (no training needed).

| Input kind | n | Correct | Wrong | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| eml | 38 | 24 | 14 | 0.600 | 0.667 | 0.632 |
| pdf | 6 | 5 | 1 | 0.750 | 1.000 | 0.857 |
| plain_text | 6 | 3 | 3 | 0.500 | 0.333 | 0.400 |
| url | 14 | 6 | 8 | 0.385 | 1.000 | 0.556 |

| Difficulty | n | Correct | Wrong | F1 |
|---|---|---|---|---|
| easy | 22 | 16 | 6 | 0.700 |
| hard | 18 | 17 | 1 | 0.952 |
| medium | 24 | 5 | 19 | 0.296 |

### Misclassified (26 shown)

| Item | Label | Predicted | Score | Kind | Type |
|---|---|---|---|---|---|
| eml-legit-007 | legit | phishing | 66.5 | eml | shipping_notice |
| eml-legit-012 | legit | phishing | 74.7 | eml | personal |
| eml-legit-031 | legit | phishing | 66.5 | eml | shipping_notice |
| eml-legit-048 | legit | phishing | 74.8 | eml | personal |
| eml-legit-049 | legit | phishing | 61.5 | eml | campus_announcement |
| eml-legit-055 | legit | phishing | 66.5 | eml | shipping_notice |
| eml-legit-067 | legit | phishing | 66.5 | eml | shipping_notice |
| eml-legit-072 | legit | phishing | 74.5 | eml | personal |
| pdf-legit-002 | legit | phishing | 75.6 | pdf | course_reminder |
| plain_text-legit-007 | legit | phishing | 65.8 | plain_text | shipping_notice |
| url-legit-003 | legit | phishing | 73.8 | url | university_official |
| url-legit-008 | legit | phishing | 70.1 | url | university_official |
| url-legit-010 | legit | phishing | 68.5 | url | trusted_brand |
| url-legit-014 | legit | phishing | 68.3 | url | university_official |
| url-legit-015 | legit | phishing | 74.2 | url | trusted_brand |
| url-legit-016 | legit | phishing | 61.3 | url | university_official |
| url-legit-020 | legit | phishing | 69.0 | url | university_official |
| url-legit-028 | legit | phishing | 63.5 | url | university_official |
| eml-phishing-001 | phishing | legit | 55.3 | eml | campus_credential |
| eml-phishing-029 | phishing | legit | 44.1 | eml | invoice_ach |
| eml-phishing-041 | phishing | legit | 44.0 | eml | invoice_ach |
| eml-phishing-049 | phishing | legit | 55.9 | eml | campus_credential |
| eml-phishing-053 | phishing | legit | 44.5 | eml | invoice_ach |
| eml-phishing-073 | phishing | legit | 57.4 | eml | campus_credential |
| plain_text-phishing-001 | phishing | legit | 39.8 | plain_text | campus_credential |
| plain_text-phishing-005 | phishing | legit | 52.3 | plain_text | invoice_ach |

## ML baseline: strongest features

- Text → phishing: verify, please, are you, account, office, need, open the, today
- Text → legit: week, if, this, from, password, edu, hey, no
- URL → phishing: re, e-, u., edu., du., de, ni, are

## Notes

- The 8 hand-written demo emails (app/sample_emails.py) are excluded: the rules were tuned on them.
- Each item is judged independently (campaign memory writes are disabled during evaluation).
- Trusted domains come from the built-in list (Redis disabled) so results don't depend on a local server.
- ml_baseline shares scenario templates between dev and test, so it can memorise template wording; ml_unseen_types tests it on attack types it never saw and is the fairer ML number.
- Gemini systems were skipped because no API key was configured. Set GEMINI_API_KEY and re-run.
