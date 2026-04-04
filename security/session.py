"""
security/session.py
Multi-turn session track.
"""
from datetime import datetime, timedelta

# In-memory session store: api_key -> list of prompts
SESSION_STORE = {}

def add_to_session(api_key: str, prompt: str):
    if api_key not in SESSION_STORE:
        SESSION_STORE[api_key] = []
    
    SESSION_STORE[api_key].append({
        "timestamp": datetime.now(),
        "prompt": prompt
    })
    
    # Sliding window of last 5
    if len(SESSION_STORE[api_key]) > 5:
        SESSION_STORE[api_key].pop(0)

def get_session_context(api_key: str) -> str:
    """Returns concatenated string of user's recent prompts for context."""
    if api_key not in SESSION_STORE:
        return ""
    
    cutoff = datetime.now() - timedelta(minutes=15)
    recent = [s["prompt"] for s in SESSION_STORE[api_key] if s["timestamp"] > cutoff]
    
    return " \n".join(recent)
