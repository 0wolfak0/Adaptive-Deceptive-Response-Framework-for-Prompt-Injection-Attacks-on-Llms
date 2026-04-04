"""
event_log/logger.py
Refactored to write logs to SQLAlchemy.
"""

from .database import SessionLocal, EventLog, Rule
from datetime import datetime

def log_event(
    prompt: str,
    score: int,
    kw_score: int,
    sem_score: int,
    mode: str,
    categories: list[str],
    llm_reasoning: str = "",
    ip_address: str = "unknown",
    api_key: str = "anonymous",
    tokens: int = 0
):
    """Save an event row to the SQLite DB."""
    db = SessionLocal()
    try:
        new_event = EventLog(
            timestamp=datetime.now(),
            api_key=api_key,
            ip_address=ip_address,
            prompt=prompt,
            risk_score=score,
            kw_score=kw_score,
            sem_score=sem_score,
            risk_mode=mode,
            categories="|".join(categories) if categories else "none",
            llm_reasoning=llm_reasoning,
            tokens=tokens,
        )
        db.add(new_event)
        db.commit()
    finally:
        db.close()


def read_all_events() -> list[dict]:
    """Return all log rows as a list of dicts for the dashboard."""
    db = SessionLocal()
    try:
        events = db.query(EventLog).all()
        result = []
        for e in events:
            result.append({
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "api_key": e.api_key,
                "ip_address": e.ip_address,
                "prompt": e.prompt,
                "risk_score": e.risk_score,
                "kw_score": e.kw_score,
                "sem_score": e.sem_score,
                "risk_mode": e.risk_mode,
                "categories": e.categories,
                "llm_reasoning": e.llm_reasoning,
                "tokens": e.tokens,
            })
        return result
    finally:
        db.close()
