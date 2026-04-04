"""
security/cache.py
Semantic caching for fast analysis skipping.
"""
import hashlib
import re

SEMANTIC_CACHE = {}

def _normalize(prompt: str) -> str:
    # Lowercase, collapse spaces, remove punctuation
    p = prompt.lower().strip()
    p = re.sub(r"[^\w\s]", "", p)
    return re.sub(r"\s+", " ", p)

def get_cache_key(prompt: str) -> str:
    normalized = _normalize(prompt)
    return hashlib.md5(normalized.encode("utf-8")).hexdigest()

def check_cache(prompt: str):
    key = get_cache_key(prompt)
    return SEMANTIC_CACHE.get(key)

def set_cache(prompt: str, analysis: dict):
    key = get_cache_key(prompt)
    SEMANTIC_CACHE[key] = analysis
