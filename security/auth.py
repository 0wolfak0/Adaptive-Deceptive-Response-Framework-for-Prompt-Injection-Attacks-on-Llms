"""
security/auth.py
Simple API key authentication dependency for FastAPI.
"""
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

# Simple static demo keys. In production, these should be in a DB.
VALID_API_KEYS = {
    "Bearer super-secret-key-1": "tenant_a_user",
    "Bearer dev-key-xyz": "tenant_b_dev",
}

def get_api_key(api_key: str = Security(api_key_header)) -> str:
    """Extracts tenant ID or API key from Auth header."""
    if not api_key:
        return "anonymous"
    
    if api_key in VALID_API_KEYS:
        return VALID_API_KEYS[api_key]
    
    if api_key.startswith("Bearer "):
        return api_key.split(" ")[1]
        
    return api_key
