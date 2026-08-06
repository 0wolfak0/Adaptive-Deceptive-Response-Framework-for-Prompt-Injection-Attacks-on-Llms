#  LLM Security Middleware

A FastAPI-based security layer that wraps a locally hosted LLaMA3 model via Ollama with prompt injection detection, deception honeypotting, rate limiting, and a real-time monitoring dashboard.

## Features

|  **Keyword Detection** | Matches injection, illegal-activity, and harm phrases (with l33t-speak normalisation) |
|  **LLM Semantic Classifier** | Uses LLaMA3 itself to semantically classify risk — catches paraphrased attacks |
|  **Honeypot / Deception Mode** | High-risk prompts receive dynamically generated fake API keys & DB schemas |
|  **Rate Limiting** | 15 requests/minute per IP via `slowapi` |
|  **Live Dashboard** | Dark-mode web dashboard with charts, stat cards, and event log |
|  **Structured Logging** | Every request logged with IP, risk scores, categories, and LLM reasoning |

## Project Structure
```

llm_security_project/
├── app.py                          # Main FastAPI app
├── requirements.txt
├── attack_log.csv                  # Auto-created event log
├── security/
│   ├── analyzer.py                 # Keyword + LLM semantic classifier
│   └── deception.py                # Honeypot response generator
├── event_log/
│   └── logger.py                   # CSV logger with auto-migration
└── dashboard/
    ├── routes.py                   # /dashboard and /stats endpoints
    └── templates/
        └── dashboard.html          # Dark-mode dashboard UI
```
```

## Requirements

- Python 3.10+
- Ollama running locally with `llama3` pulled


## Setup

in bash
# 1. Clone the repo
git clone https://github.com/0wolfak0/llm.git
cd llm

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Pull the LLaMA3 model (first time only)
ollama pull llama3
(you dont have to pull it everytime)


## Running

```bash
# Terminal 1 — Start Ollama
ollama serve

# Terminal 2 — Start the API server
uvicorn app:app --host 0.0.0.0 --port 8000 --reload

---

## Usage

| URL | Description |
|---|---|
| `http://localhost:8000/docs` | Swagger UI — test prompts interactively |
| `http://localhost:8000/dashboard` | Live security monitoring dashboard |
| `http://localhost:8000/stats` | Raw JSON analytics |
| `http://localhost:8000/health` | Health check |

### Example: Send a prompt

```bash
curl -X POST "http://localhost:8000/chat?prompt=explain+machine+learning"
```

### Risk Levels

| Score | Mode | Action |
|---|---|---|
| 0 | **SAFE** | Forwarded to LLaMA3 |
| 1–3 | **MONITOR** | Blocked with a policy warning |
| ≥ 4 | **DECEPTION** | Returns fake credentials/schema |

---

## Security Note

This project is for **research and educational purposes**. The deception responses contain entirely fake credentials — never use real API keys or secrets anywhere in this codebase.
