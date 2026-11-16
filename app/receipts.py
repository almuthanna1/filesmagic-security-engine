"""Ed25519-signed scan receipts: the only part of a scan answer that can authorize conversion.

Format (same encoding as scan tokens): base64url(JSON claims) "." base64url(Ed25519 signature
over exactly those JSON bytes). Claims are listed in docs/security-integration-v1.md, "Receipt".

The private key lives only in this process, read once from SECURITY_ENGINE_RECEIPT_PRIVATE_KEY
(base64 DER PKCS#8) and removed from the environment, so no child process ever sees it. The key
ID ("kid") is the first 16 hex digits of the SHA-256 of the public key's DER SubjectPublicKeyInfo,
the same ID filesmagic-engine's scripts/scan_keys.py prints. One key signs at a time; rotation is
done by the verifier trusting the old and new public keys while the switch happens.

`verify` is the reference verifier the Conversion Engine mirrors; this service never calls it.
"""

import base64
import binascii
import hashlib
import json
import os
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_private_key

TYPE = "filesmagic-scan-receipt/v1"
ISSUER = "filesmagic-security-engine"
AUDIENCE = "filesmagic-conversion-engine"
LIFETIME_SECONDS = 300
CLOCK_SKEW = 30
MAX_RECEIPT_CHARS = 8192
KEY_ENV = "SECURITY_ENGINE_RECEIPT_PRIVATE_KEY"


class ReceiptError(Exception):
    """The receipt does not authorize anything. `code` is stable."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def key_id(public_key: Ed25519PublicKey) -> str:
    return hashlib.sha256(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]


def load_private_key(value: str) -> Ed25519PrivateKey | None:
    if not value:
        return None
    key = load_der_private_key(base64.b64decode(value, validate=True), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{KEY_ENV} must be an Ed25519 private key.")
    return key


# None = not configured: no receipts, so the Conversion Engine authorizes nothing (fail closed).
PRIVATE_KEY = load_private_key(os.environ.pop(KEY_ENV, "").strip())


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def current_key_id() -> str | None:
    return key_id(PRIVATE_KEY.public_key()) if PRIVATE_KEY else None


def sign(outcome: dict, key: Ed25519PrivateKey | None = None, now: float | None = None) -> str | None:
    """Sign a validated scan outcome. Returns None when no receipt key is configured."""
    key = key or PRIVATE_KEY
    if key is None:
        return None
    iat = int(time.time() if now is None else now)
    # Reserved claims last: an outcome can never override them.
    claims = {**outcome, "typ": TYPE, "iss": ISSUER, "aud": AUDIENCE, "kid": key_id(key.public_key()),
              "rid": uuid.uuid4().hex, "iat": iat, "exp": iat + LIFETIME_SECONDS}
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    return f"{_b64(payload)}.{_b64(key.sign(payload))}"


def verify(receipt: str, trusted: dict[str, Ed25519PublicKey], *, sha256: str, size: int,
           token_jti: str | None = None, now: float | None = None) -> dict:
    """Reference verifier. Returns the claims of a valid receipt for exactly these bytes, or raises
    ReceiptError. The caller must still act on claims["authorization"] and record claims["rid"] as
    used, and must never treat anything outside the claims as authoritative."""
    if not isinstance(receipt, str) or not receipt or len(receipt) > MAX_RECEIPT_CHARS:
        raise ReceiptError("RECEIPT_MISSING")
    try:
        payload_b64, sig_b64 = receipt.split(".")
        payload, signature = _unb64(payload_b64), _unb64(sig_b64)
        claims = json.loads(payload)
        key = trusted.get(claims.get("kid")) if isinstance(claims, dict) else None
        if key is None:
            raise ReceiptError("RECEIPT_UNKNOWN_KEY")
        key.verify(signature, payload)
    except ReceiptError:
        raise
    except (ValueError, binascii.Error, InvalidSignature, AttributeError, TypeError):
        raise ReceiptError("RECEIPT_INVALID_SIGNATURE") from None

    now = time.time() if now is None else now
    try:
        if not (claims["typ"] == TYPE and claims["iss"] == ISSUER and claims["aud"] == AUDIENCE):
            raise ReceiptError("RECEIPT_WRONG_TYPE")
        if not (claims["iat"] - CLOCK_SKEW <= now < claims["exp"]
                and 0 < claims["exp"] - claims["iat"] <= LIFETIME_SECONDS):
            raise ReceiptError("RECEIPT_EXPIRED")
        if claims["sha256"] != sha256 or claims["size"] != size:
            raise ReceiptError("RECEIPT_FILE_MISMATCH")
        if token_jti is not None and claims["token_jti"] != token_jti:
            raise ReceiptError("RECEIPT_REQUEST_MISMATCH")
        if claims["authorization"] not in ("allow", "consent_required", "deny") or claims["isolation_verified"] is not True:
            raise ReceiptError("RECEIPT_WRONG_TYPE")
        if claims["verdict"] == "MALICIOUS" and claims["authorization"] != "deny":
            raise ReceiptError("RECEIPT_WRONG_TYPE")  # never possible from this engine; refuse anyway
    except (KeyError, TypeError):
        raise ReceiptError("RECEIPT_WRONG_TYPE") from None
    return claims
