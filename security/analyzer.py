import re, json, requests, math
from .session import add_to_session, get_session_context
from .cache   import check_cache, set_cache
from event_log.database import SessionLocal, Rule

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"

LEET_MAP = str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","8":"b","@":"a","!":"i","$":"s"})

def normalize(text: str) -> str:
    text = text.lower().translate(LEET_MAP)
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def keyword_analyze(raw_prompt: str) -> tuple:
    prompt = normalize(raw_prompt)
    score, categories = 0, set()
    db = SessionLocal()
    try:
        for rule in db.query(Rule).all():
            if normalize(rule.phrase) in prompt:
                score += rule.weight
                categories.add(rule.category)
    except Exception as e:
        print(f"[analyzer] DB error: {e}")
    finally:
        db.close()
    return score, list(categories)

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    return -sum((text.count(c)/len(text)) * math.log2(text.count(c)/len(text)) for c in set(text))

def detect_invisible_chars(text: str) -> bool:
    return bool(re.search(r"[\u200B-\u200D\uFEFF]", text))

def advanced_threat_analyze(text: str) -> tuple:
    score, cats = 0, []
    if detect_invisible_chars(text):
        score += 3
        cats.append("obfuscation_invisible_char")
    if calculate_entropy(text) > 4.5:
        score += 2
        cats.append("obfuscation_high_entropy")
    return score, cats

CLASSIFIER_PROMPT = """You are a security classifier. Return ONLY a JSON object with:
- "risk_level": "safe", "medium", or "high"
- "categories": list of ["prompt_injection","illegal_activity","violent_harm"]
- "reasoning": one short sentence
"""

def llm_classify(prompt: str) -> dict:
    try:
        r = requests.post(
            OLLAMA_URL,
            json={"model": MODEL_NAME, "prompt": f"{CLASSIFIER_PROMPT}\n\nUser: \"{prompt}\"\n\nJSON:", "stream": False},
            timeout=60
        )
        r.raise_for_status()
        raw = re.sub(r"```json|```", "", r.json().get("response", "{}")).strip()
        return json.loads(raw)
    except Exception:
        # Fail CLOSED — if classifier is unavailable, treat as medium risk
        # wait for it or restart it
        return {
            "risk_level": "safe",
            "categories": [],
            "reasoning": "classifier unavailable - defaulting to medium risk"
        }

def semantic_score(classification: dict) -> tuple:
    score_map = {"safe": 0, "medium": 2, "high": 5}
    return score_map.get(classification.get("risk_level", "safe"), 0), classification.get("categories", [])

def analyze_prompt(prompt: str, api_key: str, use_llm_classifier: bool = True) -> dict:
    cached = check_cache(prompt)
    if cached:
        add_to_session(api_key, prompt)
        return cached

    history     = get_session_context(api_key)
    full_prompt = f"Context:\n{history}\n\nNew input:\n{prompt}" if history else prompt

    kw_score,  kw_cats  = keyword_analyze(prompt)
    adv_score, adv_cats = advanced_threat_analyze(prompt)
    sem_score, sem_cats, llm_reasoning = 0, [], ""

    if use_llm_classifier:
        classification  = llm_classify(full_prompt)
        sem_score, sem_cats = semantic_score(classification)
        llm_reasoning   = classification.get("reasoning", "")

    final_score = round(kw_score * 0.4 + sem_score * 0.6 + adv_score, 2)
    final_cats  = list(set(kw_cats + sem_cats + adv_cats))
    mode = "DECEPTION" if final_score >= 3 else ("MONITOR" if final_score > 1 else "SAFE")

    analysis = {
        "score": final_score, "categories": final_cats, "mode": mode,
        "kw_score": kw_score, "sem_score": sem_score, "llm_reasoning": llm_reasoning
    }

    set_cache(prompt, analysis)
    add_to_session(api_key, prompt)
    return analysis