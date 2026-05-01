import os
from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from collections import Counter
from datetime import datetime

from event_log.logger   import read_all_events
from event_log.database import SessionLocal, Rule
from security.auth      import get_api_key

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

_DOW_LIMIT = float(os.environ.get("DOW_COST_LIMIT_USD", "1.00"))


# /stats is open so the dashboard page can fetch it from the browser
@router.get("/stats")
def get_stats():
    events = read_all_events()
    modes  = Counter(e.get("risk_mode", "") for e in events)
    cats   = Counter(
        c for e in events
        for c in (e.get("categories") or "").split("|")
        if c and c != "none"
    )
    days: Counter = Counter()
    for e in events:
        try:
            days[datetime.fromisoformat(e["timestamp"]).strftime("%Y-%m-%d")] += 1
        except Exception:
            pass
    users = Counter(e.get("api_key", "") for e in events if e.get("api_key"))
    return {
        "total_requests":  len(events),
        "safe_count":      modes.get("SAFE", 0),
        "monitor_count":   modes.get("MONITOR", 0),
        "deception_count": modes.get("DECEPTION", 0),
        "top_categories":  dict(cats.most_common(10)),
        "events_per_day":  dict(sorted(days.items())),
        "top_users":       dict(users.most_common(10)),
        "recent_events":   events[-20:][::-1],
    }


# Dashboard and playground pages are open (they're just HTML)
@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@router.get("/playground", response_class=HTMLResponse)
def get_playground(request: Request):
    return templates.TemplateResponse("playground.html", {"request": request})


# Rules page — open for viewing, but add/delete require a valid API key
@router.get("/rules", response_class=HTMLResponse)
def get_rules_page(request: Request):
    db = SessionLocal()
    try:
        rules = db.query(Rule).all()
        return templates.TemplateResponse("rules.html", {"request": request, "rules": rules})
    finally:
        db.close()

@router.post("/rules/add", )
def add_rule(phrase: str = Form(...), category: str = Form(...), weight: int = Form(...)):
    db = SessionLocal()
    try:
        if not db.query(Rule).filter_by(phrase=phrase).first():
            db.add(Rule(phrase=phrase, category=category, weight=weight))
            db.commit()
    finally:
        db.close()
    return RedirectResponse(url="/rules", status_code=303)

@router.post("/rules/delete/{rule_id}", )
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


# Tokens page — open for viewing
@router.get("/tokens", response_class=HTMLResponse)
def get_tokens_page(request: Request):
    events = read_all_events()
    user_tokens: Counter = Counter()
    for e in events:
        user_tokens[e.get("api_key", "unknown")] += e.get("tokens", 0)
    costs = {k: v * 0.000002 for k, v in user_tokens.items()}
    return templates.TemplateResponse("tokens.html", {
        "request":     request,
        "user_tokens": dict(user_tokens.most_common()),
        "costs":       costs,
        "cost_limit":  _DOW_LIMIT,
    })