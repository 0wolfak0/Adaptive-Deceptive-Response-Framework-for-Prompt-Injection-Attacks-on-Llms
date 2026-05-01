from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import requests as http_requests

from security.analyzer  import analyze_prompt
from security.deception import dynamic_deceptive_response
from security.auth      import get_api_key
from security.dlp       import redact_text, detect_pii
from event_log.logger   import log_event
from dashboard.routes   import router as dashboard_router

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"

class ChatRequest(BaseModel):
    prompt: str

def rate_limit_key(request: Request):
    auth = request.headers.get("Authorization")
    return auth if auth else get_remote_address(request)

limiter = Limiter(key_func=rate_limit_key)

app = FastAPI(title="LLM Security Middleware", version="3.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.include_router(dashboard_router)

def call_llm(prompt: str) -> str:
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

@app.get("/health")
def health():
    return {"status": "ok", "version": "3.1.0"}

@app.post("/chat")
@limiter.limit("50/minute")
def chat(body: ChatRequest, request: Request, api_key: str = Depends(get_api_key)):
    prompt    = body.prompt
    client_ip = request.client.host if request.client else "unknown"

    analysis   = analyze_prompt(prompt, api_key=api_key, use_llm_classifier=True)
    score      = analysis["score"]
    categories = analysis["categories"]
    mode       = analysis["mode"]
    kw_score   = analysis["kw_score"]
    sem_score  = analysis["sem_score"]
    reasoning  = analysis["llm_reasoning"]

    if mode == "DECEPTION":
        log_event(prompt=prompt, score=score, kw_score=kw_score, sem_score=sem_score,
                  mode=mode, categories=categories, llm_reasoning=reasoning,
                  ip_address=client_ip, api_key=api_key, tokens=len(prompt) // 4)
        return JSONResponse(content={"response": dynamic_deceptive_response(prompt), "mode": "DECEPTION"})

    if mode == "MONITOR":
        log_event(prompt=prompt, score=score, kw_score=kw_score, sem_score=sem_score,
                  mode=mode, categories=categories, llm_reasoning=reasoning,
                  ip_address=client_ip, api_key=api_key, tokens=len(prompt) // 4)
        return JSONResponse(content={
            "response": "⚠️ This request violates usage policies and has been logged.",
            "mode": "MONITOR",
        })

    raw_response = call_llm(prompt)
    est_tokens   = (len(prompt) + len(raw_response)) // 4
    log_event(prompt=prompt, score=score, kw_score=kw_score, sem_score=sem_score,
              mode=mode, categories=categories, llm_reasoning=reasoning,
              ip_address=client_ip, api_key=api_key, tokens=est_tokens)

    dlp_violations = detect_pii(raw_response)
    if dlp_violations:
        return JSONResponse(content={
            "response": redact_text(raw_response),
            "mode": "SAFE_REDACTED",
            "message": f"DLP removed: {', '.join(dlp_violations)}"
        })

    return JSONResponse(content={"response": raw_response, "mode": "SAFE"})