# Phishing Email Agentic AI System

End-to-end prototype implementing the **Phishing Email Agentic AI System** with **FastAPI**, **google-genai (Gemini 3.x Flash)**, **redis-py (Trusted Domains Redis DB)**, **Git-backed Skill Playbooks (`.md`)**, **Campaign History Memory**, and an interactive **WebSocket + HTTPS Contextual Web UI**.

## Quick Start

```bash
cd /Users/mac/.gemini/antigravity/scratch/phishing-email-agent
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Optional: Configure live Gemini 3.x Flash & Redis
export GEMINI_API_KEY="your-gemini-api-key"
export GEMINI_MODEL="gemini-3-flash-preview"
export REDIS_URL="redis://localhost:6379/0"

# Start the FastAPI + WebSocket server
.venv/bin/uvicorn app.main:app --reload --port 8000
```

Then open `http://localhost:8000` in your browser to interact with the **Contextual UI Demo**.

