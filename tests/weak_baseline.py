"""Inert test-only example of a dangerous, signature-free claims check.

Never import this helper into the installed package or expose it as a service.
It represents a deliberately weak self-owned fixture, not a PyJWT defect.
"""

import jwt


def weak_claim_only_accept(token: str, issuer: str, audience: str) -> bool:
    try:
        claims = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False},
            algorithms=["RS256"],
        )
    except jwt.PyJWTError:
        return False
    return claims.get("iss") == issuer and claims.get("aud") == audience

