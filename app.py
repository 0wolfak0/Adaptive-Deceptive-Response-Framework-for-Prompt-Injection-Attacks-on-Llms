"""
app.py  —  LLM Security Middleware (refactored)
============================================================
Endpoints:
  POST /chat         — main chat endpoint (protected)
  GET  /stats        — JSON analytics
  GET  /dashboard    — HTML security dashboard
  GET  /health       — simple health check
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import requests as http_requests

# ── Internal modules ─────────────────────────
from security.analyzer  import analyze_prompt
from security.deception import dynamic_deceptive_response, static_deceptive_response
from event_log.logger   import log_event
from dashboard.routes   import router as dashboard_router

# ── LLM config ───────────────────────────────
OLLAMA_URL  = "http://localhost:11434/api/generate"
MODEL_NAME  = "llama3"

# ── Rate limiter ─────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="LLM Security Middleware",
    description="Prompt-injection detection, deception honeypot, and security analytics.",
    version="2.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Register dashboard routes
app.include_router(dashboard_router)


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
def call_llm(prompt: str) -> str:
    """Forward a safe prompt to the local Ollama LLM."""
    try:
        response = http_requests.post(
            OLLAMA_URL,
            json={"model": MODEL_NAME, "prompt": prompt, "stream": False},
            timeout=180,
        )
        response.raise_for_status()
        return response.json().get("response", "No response returned by LLM.")
    except Exception as e:
        return f"Error communicating with LLM: {str(e)}"


# ──────────────────────────────────────────────
# HEALTH CHECK
# ──────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


# ──────────────────────────────────────────────
# MAIN CHAT ENDPOINT
# ──────────────────────────────────────────────
@app.post("/chat")
@limiter.limit("15/minute")        # max 15 requests per minute per IP
def chat(prompt: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"

    # ── Analyze the prompt (keyword + LLM semantic) ──
    analysis = analyze_prompt(prompt, use_llm_classifier=True)

    score       = analysis["score"]
    categories  = analysis["categories"]
    mode        = analysis["mode"]
    kw_score    = analysis["kw_score"]
    sem_score   = analysis["sem_score"]
    reasoning   = analysis["llm_reasoning"]

    # ── Log every request ──
    log_event(
        prompt=prompt,
        score=score,
        kw_score=kw_score,
        sem_score=sem_score,
        mode=mode,
        categories=categories,
        llm_reasoning=reasoning,
        ip_address=client_ip,
    )

    # ── HIGH RISK → Honeypot deception ──
    if mode == "DECEPTION":
        return JSONResponse(content={
            "response": dynamic_deceptive_response(prompt),
            "mode": "DECEPTION",
        })

    # ── MEDIUM RISK → Block & warn ──
    if mode == "MONITOR":
        return JSONResponse(content={
            "response": "⚠️ This request violates usage policies and has been logged.",
            "mode": "MONITOR",
        })

    # ── SAFE → Forward to LLM ──
    return JSONResponse(content={
        "response": call_llm(prompt),
        "mode": "SAFE",
    })