import os
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

def _build_key_map() -> dict:
    key_map = {}
    key_a = os.environ.get("API_KEY_TENANT_A")
    key_b = os.environ.get("API_KEY_TENANT_B")
    if key_a:
        key_map[f"Bearer {key_a}"] = "tenant_a_user"
    if key_b:
        key_map[f"Bearer {key_b}"] = "tenant_b_dev"
    return key_map

def get_api_key(api_key: str = Security(api_key_header)) -> str:
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header.",
        )
    valid_keys = _build_key_map()
    if api_key in valid_keys:
        return valid_keys[api_key]
    if api_key.startswith("Bearer "):
        token = api_key.split(" ", 1)[1]
        if token:
            return token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key.",
    )