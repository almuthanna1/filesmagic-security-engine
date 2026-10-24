"""Scan authorization: short-lived, single-use, file-bound tokens.

The Security Lab (Vercel) signs a token server-side, after the admin has logged in, for
one specific file (its SHA-256 and size). The browser then uploads that file directly to
this API with `Authorization: Bearer <token>`. Tokens are Ed25519-signed, so this service
only holds the PUBLIC key: nothing stored here (or readable by a compromised scan
worker) can mint new tokens.

Token format: base64url(JSON claims) "." base64url(Ed25519 signature over the JSON bytes)
Claims: aud, iat, exp, jti, sha256, size.
"""

import base64
import binascii
import json
import os
import secrets
import time
from collections import defaultdict, deque

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

AUDIENCE = "filesmagic-security-engine/scan"
MAX_TOKEN_LIFETIME = 300  # seconds; the Lab issues 120 s tokens
CLOCK_SKEW = 30  # seconds tolerated between Vercel and Render clocks
MAX_TOKEN_CHARS = 2048

# Unauthorized-request throttling, per client address.
MAX_FAILURES_PER_MINUTE = 20


class AuthError(Exception):
    """The request carries no valid scan token. The message is safe to return."""


def load_public_key(value: str) -> Ed25519PublicKey | None:
    """SECURITY_ENGINE_TOKEN_PUBLIC_KEY: base64 DER (SubjectPublicKeyInfo) of an Ed25519 key."""
    if not value:
        return None
    key = load_der_public_key(base64.b64decode(value))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("SECURITY_ENGINE_TOKEN_PUBLIC_KEY must be an Ed25519 public key.")
    return key


# None = not configured: every scan is refused (fail closed).
PUBLIC_KEY = load_public_key(os.environ.get("SECURITY_ENGINE_TOKEN_PUBLIC_KEY", ""))

# ponytail: in-memory state, correct for a single API instance. With several instances,
# a token could be replayed once per instance and failure counts are per instance; move
# both to a shared store (e.g. Redis) before scaling out.
_used_tokens: dict[str, float] = {}  # jti -> exp
_failures: dict[str, deque] = defaultdict(deque)


def _b64decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def verify(authorization: str, now: float | None = None) -> dict:
    """Validate the Authorization header and consume the token. Returns its claims."""
    if PUBLIC_KEY is None:
        raise AuthError("Scanning is disabled: the engine has no token verification key configured.")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > MAX_TOKEN_CHARS:
        raise AuthError("Missing or malformed scan token.")
    try:
        payload_b64, sig_b64 = token.strip().split(".")
        payload = _b64decode(payload_b64)
        PUBLIC_KEY.verify(_b64decode(sig_b64), payload)
        claims = json.loads(payload)
    except (ValueError, binascii.Error, InvalidSignature):
        raise AuthError("Invalid scan token.") from None

    now = time.time() if now is None else now
    try:
        valid = (
            claims["aud"] == AUDIENCE
            and claims["iat"] - CLOCK_SKEW <= now < claims["exp"]
            and claims["exp"] - claims["iat"] <= MAX_TOKEN_LIFETIME
            and isinstance(claims["jti"], str) and 16 <= len(claims["jti"]) <= 64
            and isinstance(claims["sha256"], str) and len(claims["sha256"]) == 64
            and isinstance(claims["size"], int) and claims["size"] >= 0
        )
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise AuthError("Scan token is expired or not valid for this service.")

    for jti, exp in list(_used_tokens.items()):
        if exp <= now:
            del _used_tokens[jti]
    if claims["jti"] in _used_tokens:
        raise AuthError("Scan token has already been used.")
    _used_tokens[claims["jti"]] = claims["exp"]
    return claims


def mint_token(key: Ed25519PrivateKey, sha256: str, size: int, lifetime: int = 120, now: float | None = None) -> str:
    """Python counterpart of the Lab's token issuer (frontend/lib/auth.ts). Used by tests and the
    offline evaluation harness; the deployed engine never holds a private key."""
    now = int(time.time() if now is None else now)
    claims = {"aud": AUDIENCE, "iat": now, "exp": now + lifetime, "jti": secrets.token_hex(16),
              "sha256": sha256, "size": size}
    payload = json.dumps(claims, separators=(",", ":")).encode()
    return f"{_b64encode(payload)}.{_b64encode(key.sign(payload))}"


def too_many_failures(client: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    q = _failures.get(client)
    while q and q[0] <= now - 60:
        q.popleft()
    return bool(q) and len(q) >= MAX_FAILURES_PER_MINUTE


def record_failure(client: str, now: float | None = None) -> None:
    if len(_failures) > 10_000:  # bound memory if many addresses fail
        _failures.clear()
    _failures[client].append(time.time() if now is None else now)


def reset() -> None:
    _used_tokens.clear()
    _failures.clear()
