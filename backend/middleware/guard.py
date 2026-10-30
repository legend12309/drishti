"""
DRISHTI — Phase 5 LLM Guard & Input Sanitization Middleware
Protects the AI engine from prompt injection, token bloat, delimiter evasion,
and cross-boundary command execution while ensuring all scanner evidence is
treated as untrusted input.
"""

import re
from fastapi import HTTPException

# Explicit adversarial injection patterns
SUSPICIOUS_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior)\s+instructions",
    r"system\s+prompt",
    r"<script.*?>",
    r"dump\s+(all\s+)?(secrets|credentials|passwords|tokens|keys)",
    r"override\s+authorization",
    r"exec\s*\(",
    r"__import__",
]

# Max input prompt length (bounded token safety: 16,000 characters ~ 4,000 tokens)
MAX_PROMPT_LENGTH = 16000


def sanitize_llm_input(prompt: str) -> str:
    """
    Sanitizes LLM prompt input against prompt injection, unbounded length,
    and command execution instructions.
    """
    if not prompt or not isinstance(prompt, str):
        return ""

    if len(prompt) > MAX_PROMPT_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Prompt exceeds maximum allowable length of {MAX_PROMPT_LENGTH} characters."
        )

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            raise HTTPException(
                status_code=400,
                detail="Disallowed input detected by LLM Guard: potential prompt injection."
            )

    return prompt.strip()

