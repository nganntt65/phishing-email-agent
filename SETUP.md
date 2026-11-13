# Setting up CampusGuard AI with your Gemini key

This guide takes you from a fresh clone to CampusGuard AI running with Gemini reasoning switched on. It takes about 10 minutes. You don't need Redis, Docker or any other service.

The app reads the key from a file called `.env` in the project folder. There is no key field in the web page: the key stays on the server, never in the browser. The Scan, Analyst and Evaluation tabs all use that same key.


## 1. What you need

- Python 3.12 or newer (tested on 3.14)
- Git
- A Gemini API key from Google AI Studio: https://aistudio.google.com/apikey


## 2. Get the code and install

Windows (PowerShell):

```powershell
git clone https://github.com/yardannaufal/Campus-Guard-AI.git
cd Campus-Guard-AI
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

macOS / Linux:

```bash
git clone https://github.com/yardannaufal/Campus-Guard-AI.git
cd Campus-Guard-AI
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```


## 3. Paste your key

Make your own `.env` from the template:

```powershell
Copy-Item .env.example .env        # Windows
```

```bash
cp .env.example .env               # macOS / Linux
```

Open `.env` in any editor and put your key right after the equals sign, with no spaces or quotes:

```
GEMINI_API_KEY=AIza...your key...
```

Save the file. That's the only required setting. Everything else in `.env` is optional and explained in the file.

`.env` is listed in `.gitignore`, so it is never committed. Don't paste the key into any other file.

Optional: to protect one specific university, also uncomment the three `CAMPUS_*` lines in `.env` and fill them in (the file has an NTPU example). Skip them for a general demo: the app then works for any university. What they change is explained in "Penjelasan Sistem.md" and "System Explanation.md", section 4.


## 4. Start the app

Windows:

```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

macOS / Linux:

```bash
.venv/bin/python -m uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000.

The app reads `.env` when the server starts. If you change `.env` later, stop the server (Ctrl+C) and start it again. `--reload` only watches the code, not `.env`.


## 5. Check that Gemini is really being used

1. Look at the chip in the top-right corner of the page.
   - "AI reasoning: on" means the key was found.
   - "AI reasoning: off" means no key was found. See section 7.
   - "AI reasoning: error" means the key was found but the last Gemini call failed. Hover over the chip to see why.
2. On the Scan tab, choose "Email file", pick a sample under "Try an example", and scan it. The result should start with a green note: "Checked with AI reasoning (model name)". If you see an amber note instead, it says in plain words why Gemini wasn't used.
3. For details, open http://localhost:8000/api/v1/health:
   - `gemini_api_key_configured: true` means the key was found.
   - `llm_last_status: "USED"` and `llm_last_model` show the last successful call and which model answered.
   - `llm_last_error` explains the last failure, if there was one.

In the Analyst tab, keep "Use Gemini reasoning" ticked, pick a sample and run it. The "Reasoning engine (Gemini)" step should finish without a "fallback" event.


## 6. What the key is used for

- Scan tab, emails and PDFs: one Gemini call per scan. Gemini reads the wording of the message (pressure, threats, requests for money or logins) and quotes the sentences that worried it. Each quote is checked against the email. The sender, link and campaign checks are still done by code.
- Scan tab, links: one call per scan, only to write the explanation. The label and score come from the URL scanner either way.
- Analyst tab: the same email pipeline, shown step by step.
- Evaluation tab: tick "Use Gemini if available" to run dataset items with Gemini. Every item is one call, so on a free key keep live runs small (10 to 50 items).
- `eval/run_eval.py`: a command-line comparison that fills in the `llm_hybrid` and `llm_only` rows of `eval/results/latest/report.md` (see section 8).

If Gemini fails for any reason (wrong key, rate limit, timeout, an answer in the wrong format), the scan still finishes using the rule engine and says so. Nothing fails silently.

Privacy: on Google's free tier, Google may use what you send to improve its products. Use the example emails, the synthetic dataset or your own test emails, not real students' emails. Check Google's current terms.


## 7. Troubleshooting

The chip still says "AI reasoning: off":
- The file must be called exactly `.env` and sit in the project folder, next to `requirements.txt`. On Windows, Notepad may save it as `.env.txt`. Turn on "File name extensions" in Explorer to check.
- The line must start with `GEMINI_API_KEY=`, with no `#` in front.
- Restart the server after editing `.env`.

"The API key was rejected", or a note that mentions `400 INVALID_ARGUMENT` and "API key not valid":
- The key is wrong (often a character missing when copying), was deleted, or has restrictions that block the Gemini API. Copy the key again from AI Studio, or make a new one, paste it into `.env` and restart the server. A mistyped key currently shows the longer `400 INVALID_ARGUMENT` message rather than the short one. Either way the scan still finishes using the rules.

"The model isn't available for this key":
- The app first tries `gemini-3-flash-preview`, then falls back to `gemini-2.5-flash` automatically. To skip the first attempt, add `GEMINI_MODEL=gemini-2.5-flash` to `.env` and restart.

"Rate limit reached":
- The free tier allows only a few requests per minute and per day. The app waits and retries briefly, then falls back to the rules. Wait a minute, or run smaller batches.

"Gemini didn't answer in time":
- Each scan waits at most 30 seconds for Gemini, then uses the rules. On a slow connection you can raise the limits in `.env` with `LLM_TIMEOUT_SECONDS=40` and `LLM_DEADLINE_SECONDS=60`.

A scan scores higher the second time:
- That's campaign memory. A scam scored HIGH or CRITICAL is remembered, and the same pattern gets +15 next time (for example the scholarship example PDF goes from "Suspicious email" 75 to "Likely scam" 90). To start a demo fresh, stop the server, delete `campaign_memory.db` and start it again.

A variable set in the terminal (for example `$env:GEMINI_API_KEY = "..."`) takes priority over `.env`. If the app keeps using an old key, close that terminal or clear the variable.


## 8. Compare rules, ML yardstick and Gemini from the command line (optional)

```powershell
.venv\Scripts\python.exe eval\run_eval.py
```

This runs the rules, the machine-learning yardstick and Gemini on the 132 test items of the synthetic dataset, which comes to roughly 132 or more Gemini calls. Answers are cached in `eval/cache/llm/`, so if you hit the daily limit you can run it again the next day and it continues where it stopped. Running it again after that costs nothing. Results are written to `eval/results/latest/report.md` (and `summary.json`, `results.jsonl`). The Evaluation tab does not show them: it runs the live app on the dataset instead.


## 9. Adding your own dataset items (optional)

On the Evaluation tab, open "Add items to the dataset", choose Phishing or Legit, and add `.eml`, `.pdf` or `.txt` files, or links (one per line). The items then join the runs on that tab.

They are stored in `eval/added/`, which is git-ignored on purpose, because added items may be real emails. To share a set of synthetic or demo items with the team, remove the `eval/added/` line from `.gitignore` for that commit.


## 10. Run the tests (optional)

```powershell
.venv\Scripts\python.exe -m pytest -q
```

The tests never call Gemini and ignore your `.env`, so they pass with or without a key.
