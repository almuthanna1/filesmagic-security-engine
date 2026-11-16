"""Authorized /scan requests for tests: a test-only signing key and a helper that mints a
file-bound token the way the Security Lab does."""

import hashlib
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import auth

KEY = Ed25519PrivateKey.generate()


def auth_headers(data: bytes, filename: str = "upload", **token_kw) -> dict[str, str]:
    token = auth.mint_token(KEY, hashlib.sha256(data).hexdigest(), len(data), **token_kw)
    return {"Authorization": f"Bearer {token}", "X-Filename": quote(filename)}


def post_scan(client, data: bytes, filename: str = "upload", **kw):
    return client.post("/scan", content=data, headers=auth_headers(data, filename), **kw)
