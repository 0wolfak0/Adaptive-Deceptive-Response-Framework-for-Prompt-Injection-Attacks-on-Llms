from datetime import datetime, timedelta

SESSION_STORE: dict = {}
_WINDOW_MINUTES = 15
_MAX_TURNS = 5

def _cleanup_store():
    cutoff = datetime.now() - timedelta(minutes=_WINDOW_MINUTES)
    stale = [k for k, v in SESSION_STORE.items() if all(e["timestamp"] < cutoff for e in v)]
    for k in stale:
        del SESSION_STORE[k]

def add_to_session(api_key: str, prompt: str):
    if api_key not in SESSION_STORE:
        SESSION_STORE[api_key] = []
    SESSION_STORE[api_key].append({"timestamp": datetime.now(), "prompt": prompt})
    if len(SESSION_STORE[api_key]) > _MAX_TURNS:
        SESSION_STORE[api_key].pop(0)
    _cleanup_store()

def get_session_context(api_key: str) -> str:
    if api_key not in SESSION_STORE:
        return ""
    cutoff = datetime.now() - timedelta(minutes=_WINDOW_MINUTES)
    recent = [s["prompt"] for s in SESSION_STORE[api_key] if s["timestamp"] > cutoff]
    return "\n".join(recent)