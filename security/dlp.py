"""
security/dlp.py
Regex baseline Data Loss Prevention (PII check & output Guardrails).
"""
import re

PII_PATTERNS = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[ -]?){3}\d{4}\b", 
}

def detect_pii(text: str) -> list[str]:
    """Returns a list of PII types found in the text."""
    found = []
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, text):
            found.append(pii_type)
    return found

def redact_text(text: str) -> str:
    """Masks PII out of the text."""
    redacted = text
    for pii_type, pattern in PII_PATTERNS.items():
        redacted = re.sub(pattern, f"[REDACTED {pii_type.upper()}]", redacted)
    return redacted
