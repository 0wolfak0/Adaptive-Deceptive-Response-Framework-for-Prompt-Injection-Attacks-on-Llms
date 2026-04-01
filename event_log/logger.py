"""
event_log/logger.py
Structured CSV logger for all prompt events.
"""

import csv
import os
import shutil
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "attack_log.csv")
LOG_FILE = os.path.abspath(LOG_FILE)

HEADERS = [
    "timestamp",
    "ip_address",
    "prompt",
    "risk_score",
    "kw_score",
    "sem_score",
    "risk_mode",
    "categories",
    "llm_reasoning",
]


# ──────────────────────────────────────────────
# ONE-TIME MIGRATION
# ──────────────────────────────────────────────
def _looks_like_score(val: str) -> bool:
    """Return True if val is a small integer (i.e. a risk score, not a prompt)."""
    try:
        int(str(val).strip())
        return True
    except (ValueError, AttributeError):
        return False


def _migrate_csv_if_needed():
    """
    If the on-disk CSV has wrong/old headers, rewrite it with the correct
    HEADERS while preserving all historical data. Runs once at import time.

    Root cause this fixes:
      - Old CSV header: timestamp, prompt, risk_score, risk_mode, categories  (5 cols)
      - New row written: timestamp, ip_address, prompt, score, kw, sem, mode, cats, reasoning (9 cols)
      When DictReader reads new rows under old headers every column is shifted right by one,
      causing prompt to appear in the score column, score in the mode column, etc.
    """
    if not os.path.exists(LOG_FILE):
        return  # nothing to migrate yet

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()

    on_disk_headers = [h.strip() for h in first_line.split(",")]

    # File already has the correct schema — nothing to do
    if on_disk_headers == HEADERS:
        return

    # ── Read every row positionally ───────────────────────────────
    migrated: list[list] = []
    has_ip_col = "ip_address" in on_disk_headers

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # skip the old header line

        for raw in reader:
            # Skip entirely blank rows
            if not any(cell.strip() for cell in raw):
                continue

            ts = raw[0].strip() if raw else ""
            if not ts:
                continue

            if has_ip_col:
                # File already had ip_address column — rows are aligned correctly
                # but some other header mismatch exists; just re-map positionally
                ip        = raw[1] if len(raw) > 1 else "—"
                prompt    = raw[2] if len(raw) > 2 else ""
                score     = raw[3] if len(raw) > 3 else "0"
                kw_score  = raw[4] if len(raw) > 4 else score
                sem_score = raw[5] if len(raw) > 5 else "0"
                mode      = raw[6] if len(raw) > 6 else "SAFE"
                cats      = raw[7] if len(raw) > 7 else "none"
                reasoning = raw[8] if len(raw) > 8 else ""
            else:
                # Old-format file: ts | prompt | risk_score | risk_mode | categories
                # But some rows may be NEW-format rows accidentally saved under old headers:
                #   ts | ip_address | prompt | score | kw | sem | mode | cats | reasoning
                # We detect this by checking if position [2] (old "risk_score") looks like a score.
                # If it does NOT (it's text), the row has been shifted → treat as new-format.
                old_risk_score_col = raw[2] if len(raw) > 2 else ""

                if not _looks_like_score(old_risk_score_col):
                    # New-format row saved under old headers → read positionally as new layout
                    ip        = raw[1] if len(raw) > 1 else "—"
                    prompt    = raw[2] if len(raw) > 2 else ""
                    score     = raw[3] if len(raw) > 3 else "0"
                    kw_score  = raw[4] if len(raw) > 4 else score
                    sem_score = raw[5] if len(raw) > 5 else "0"
                    mode      = raw[6] if len(raw) > 6 else "SAFE"
                    cats      = raw[7] if len(raw) > 7 else "none"
                    reasoning = raw[8] if len(raw) > 8 else ""
                else:
                    # Genuine old-format row → positions: ts | prompt | score | mode | cats
                    ip        = "—"
                    prompt    = raw[1] if len(raw) > 1 else ""
                    score     = raw[2] if len(raw) > 2 else "0"
                    kw_score  = score
                    sem_score = "0"
                    mode      = raw[3] if len(raw) > 3 else "SAFE"
                    cats      = raw[4] if len(raw) > 4 else "none"
                    reasoning = ""

            # Normalise categories separator and defaults
            cats = (cats or "none").replace(",", "|").strip("|") or "none"
            mode = mode.strip() or "SAFE"

            migrated.append([ts, ip, prompt, score, kw_score, sem_score, mode, cats, reasoning])

    # ── Back up old file, then rewrite with correct headers ───────
    backup = LOG_FILE.replace(".csv", "_backup.csv")
    shutil.copy2(LOG_FILE, backup)

    with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        writer.writerows(migrated)


# Run once at import time
_migrate_csv_if_needed()


# ──────────────────────────────────────────────
# ENSURE FILE EXISTS
# ──────────────────────────────────────────────
def _ensure_log_file():
    """Create the CSV with correct headers if it doesn't exist yet."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(HEADERS)


# ──────────────────────────────────────────────
# WRITE
# ──────────────────────────────────────────────
def log_event(
    prompt: str,
    score: int,
    kw_score: int,
    sem_score: int,
    mode: str,
    categories: list[str],
    llm_reasoning: str = "",
    ip_address: str = "unknown",
):
    """Append a single event row to the CSV log."""
    _ensure_log_file()
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            ip_address,
            prompt,
            score,
            kw_score,
            sem_score,
            mode,
            "|".join(categories) if categories else "none",
            llm_reasoning,
        ])


# ──────────────────────────────────────────────
# READ
# ──────────────────────────────────────────────
def read_all_events() -> list[dict]:
    """Return all log rows as a list of dicts. Headers are always correct after migration."""
    _ensure_log_file()
    rows = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("timestamp", "").strip():
                continue
            rows.append(row)
    return rows
