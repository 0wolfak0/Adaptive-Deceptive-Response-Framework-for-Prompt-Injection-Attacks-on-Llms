"""
dashboard/routes.py
FastAPI routes for the security dashboard and tools.
"""

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from collections import Counter
from datetime import datetime
import os

from event_log.logger import read_all_events
from event_log.database import SessionLocal, Rule

router = APIRouter()
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# ──────────────────────────────────────────────
# /stats  — JSON stats API
# ──────────────────────────────────────────────
@router.get("/stats")
def get_stats():
    events = read_all_events()

    modes = Counter(e.get("risk_mode", "") for e in events)
    all_cats = []
    for e in events:
        cats = e.get("categories", "")
        if cats and cats != "none":
            all_cats.extend(cats.split("|"))
    cat_counts = Counter(all_cats)

    days: Counter = Counter()
    for e in events:
        ts = e.get("timestamp", "")
        if ts:
            try:
                day = datetime.fromisoformat(ts).strftime("%Y-%m-%d")
                days[day] += 1
            except ValueError:
                pass

    user_counts = Counter(e.get("api_key", "") for e in events if e.get("api_key"))

    return {
        "total_requests": len(events),
        "safe_count": modes.get("SAFE", 0),
        "monitor_count": modes.get("MONITOR", 0),
        "deception_count": modes.get("DECEPTION", 0),
        "top_categories": dict(cat_counts.most_common(10)),
        "events_per_day": dict(sorted(days.items())),
        "top_users": dict(user_counts.most_common(10)),
        "recent_events": events[-20:][::-1],
    }

@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

# ──────────────────────────────────────────────
# NEW: Rules Engine
# ──────────────────────────────────────────────
@router.get("/rules", response_class=HTMLResponse)
def get_rules_page(request: Request):
    db = SessionLocal()
    try:
        rules = db.query(Rule).all()
        return templates.TemplateResponse("rules.html", {"request": request, "rules": rules})
    finally:
        db.close()

@router.post("/rules/add")
def add_rule(phrase: str = Form(...), category: str = Form(...), weight: int = Form(...)):
    db = SessionLocal()
    try:
        if not db.query(Rule).filter_by(phrase=phrase).first():
            db.add(Rule(phrase=phrase, category=category, weight=weight))
            db.commit()
    finally:
        db.close()
    return RedirectResponse(url="/rules", status_code=303)

@router.post("/rules/delete/{rule_id}")
def delete_rule(rule_id: int):
    db = SessionLocal()
    try:
        rule = db.query(Rule).filter_by(id=rule_id).first()
        if rule:
            db.delete(rule)
            db.commit()
    finally:
        db.close()
    return RedirectResponse(url="/rules", status_code=303)

# ──────────────────────────────────────────────
# NEW: Tokens & Cost DoW tracking
# ──────────────────────────────────────────────
@router.get("/tokens", response_class=HTMLResponse)
def get_tokens_page(request: Request):
    events = read_all_events()
    user_tokens = Counter()
    for e in events:
        ak = e.get("api_key", "unknown")
        user_tokens[ak] += e.get("tokens", 0)
    
    # Estimate Cost: roughly $0.002 per 1k tokens
    costs = {k: v * 0.000002 for k, v in user_tokens.items()}
    
    return templates.TemplateResponse("tokens.html", {
        "request": request, 
        "user_tokens": dict(user_tokens.most_common()),
        "costs": costs
    })

# ──────────────────────────────────────────────
# NEW: Prompt Playground
# ──────────────────────────────────────────────
@router.get("/playground", response_class=HTMLResponse)
def get_playground(request: Request):
    return templates.TemplateResponse("playground.html", {"request": request})
