from __future__ import annotations

import base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def _b64url_uint(n: int) -> str:
    # big-endian, minimal length
    if n == 0:
        raw = b"\x00"
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def rsa_public_jwk(kid: str, pub: RSAPublicKey) -> dict:
    nums = pub.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(nums.n),
        "e": _b64url_uint(nums.e),
    }