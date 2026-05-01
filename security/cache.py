import hashlib
import re
from cachetools import TTLCache

# Expires after 5 minutes, max 1000 entries — so stale SAFE results don't persist forever
SEMANTIC_CACHE = TTLCache(maxsize=1000, ttl=300)

def _normalize(prompt: str) -> str:
    p = prompt.lower().strip()
    p = re.sub(r"[^\w\s]", "", p)
    return re.sub(r"\s+", " ", p)

def get_cache_key(prompt: str) -> str:
    return hashlib.md5(_normalize(prompt).encode("utf-8")).hexdigest()

def check_cache(prompt: str):
    return SEMANTIC_CACHE.get(get_cache_key(prompt))

def set_cache(prompt: str, analysis: dict):
    SEMANTIC_CACHE[get_cache_key(prompt)] = analysis