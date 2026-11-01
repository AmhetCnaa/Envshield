def mask_secret(secret: str) -> str:
    """Mask a secret string to prevent leakage in logs.

    Format:
    - If length <= 8, returns '***'
    - Otherwise, returns first 3 chars + '...' + last 3 chars
    """
    if not secret:
        return ""
    if len(secret) <= 8:
        return "***"
    return f"{secret[:3]}...{secret[-3:]}"
