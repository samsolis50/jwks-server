from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from .jwks import rsa_public_jwk


UTC = timezone.utc


@dataclass(frozen=True)
class KeyPair:
    kid: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    expires_at: datetime  # UTC


def _new_kid() -> str:
    return secrets.token_hex(16)  # 32 hex chars


def generate_rsa_keypair(expires_at: datetime) -> KeyPair:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return KeyPair(kid=_new_kid(), private_key=priv, public_key=pub, expires_at=expires_at)


class KeyStore:
    """
    Holds exactly two keys for the assignment:
      - active (unexpired)
      - expired (already expired)
    """

    def __init__(self, now: datetime) -> None:
        now = now.astimezone(UTC)

        self.active = generate_rsa_keypair(now + timedelta(hours=1))
        self.expired = generate_rsa_keypair(now - timedelta(hours=1))

    def jwks(self, now: datetime) -> Dict:
        now = now.astimezone(UTC)
        keys = []
        if self.active.expires_at > now:
            keys.append(rsa_public_jwk(self.active.kid, self.active.public_key))
        # DO NOT serve expired keys
        return {"keys": keys}

    def issue_jwt(self, now: datetime, use_expired: bool) -> str:
        now = now.astimezone(UTC)

        kp = self.expired if use_expired else self.active

        # exp must match the key expiry (per assignment)
        exp = kp.expires_at

        payload = {
            "sub": "mock-user",
            "iss": "jwks-server",
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        }

        # include kid in header
        token = jwt.encode(
            payload,
            kp.private_key,
            algorithm="RS256",
            headers={"kid": kp.kid},
        )

        # Ensure we don't accidentally issue with an expired "active" key
        if not use_expired and kp.expires_at <= now:
            raise RuntimeError("active key is expired")

        return token