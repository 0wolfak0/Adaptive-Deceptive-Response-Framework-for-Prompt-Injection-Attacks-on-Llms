"""
dashboard/routes.py
FastAPI routes for the security dashboard and stats API.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from collections import Counter
import os, json
from datetime import datetime

from event_log.logger import read_all_events

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

    # Events per day
    days: Counter = Counter()
    for e in events:
        ts = e.get("timestamp", "")
        if ts:
            try:
                day = datetime.fromisoformat(ts).strftime("%Y-%m-%d")
                days[day] += 1
            except ValueError:
                pass

    # Top attacking IPs
    ip_counts = Counter(e.get("ip_address", "") for e in events if e.get("ip_address"))

    return {
        "total_requests": len(events),
        "safe_count": modes.get("SAFE", 0),
        "monitor_count": modes.get("MONITOR", 0),
        "deception_count": modes.get("DECEPTION", 0),
        "top_categories": dict(cat_counts.most_common(10)),
        "events_per_day": dict(sorted(days.items())),
        "top_ips": dict(ip_counts.most_common(10)),
        "recent_events": events[-20:][::-1],  # last 20, newest first
    }


# ──────────────────────────────────────────────
# /dashboard  — HTML dashboard
# ──────────────────────────────────────────────
@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})
