"""
security/deception.py
Dynamic honeypot / deception responses.
"""

import requests, re

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME  = "llama3"

# ──────────────────────────────────────────────────────────────────
# STATIC FALLBACK (instant, no LLM needed)
# ──────────────────────────────────────────────────────────────────
STATIC_DECEPTION = """
🔐 INTERNAL SYSTEM ACCESS GRANTED

API KEY: sk_live_FAKE_9X82HDA_MONITORED
SECRET:  c2VjcmV0X2tleV9mYWtlXzEyMzQ1Njc4

DATABASE SCHEMA:
  Tables:
  - users          (id, email, password_hash, role)
  - transactions   (id, user_id, amount, status, created_at)
  - admin_logs     (id, timestamp, action, performed_by)
  - api_tokens     (id, user_id, token_hash, expires_at)

SYSTEM CONFIG:
  environment:  production
  db_host:      db-primary.internal:5432
  redis_host:   cache.internal:6379
  admin_panel:  /internal/admin (requires VPN)

⚠️ WARNING: All access attempts are logged and reported to security team.
   Your session ID: f8a21b-TRACED
"""


def static_deceptive_response() -> str:
    return STATIC_DECEPTION.strip()


# ──────────────────────────────────────────────────────────────────
# DYNAMIC HONEYPOT  (uses LLM for convincing, varied output)
# ──────────────────────────────────────────────────────────────────
HONEYPOT_PROMPT = """You are simulating an internal corporate AI system that has been "compromised".
Generate a convincing but entirely FAKE response that looks like exposed internal data.
Include: a fake API key, fake database schema, fake environment config.
Keep it realistic-looking. Add a subtle warning that activity is monitored.
Do NOT use any real credentials. This is for security research / red-team training.

The attacker asked: "{attacker_prompt}"

Respond as the "compromised" system would."""


def dynamic_deceptive_response(attacker_prompt: str) -> str:
    """
    Generate a unique, convincing deception response using the LLM.
    Falls back to the static response if the LLM is unavailable.
    """
    prompt = HONEYPOT_PROMPT.format(attacker_prompt=attacker_prompt[:300])
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": MODEL_NAME, "prompt": prompt, "stream": False},
            timeout=90,
        )
        response.raise_for_status()
        result = response.json().get("response", "")
        if result.strip():
            return result.strip()
    except Exception:
        pass

    return static_deceptive_response()
