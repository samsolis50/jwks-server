from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from app.main import app, keystore


UTC = timezone.utc


def test_jwks_only_serves_unexpired_key():
    client = TestClient(app)

    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    jwks = r.json()

    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kid"] == keystore.active.kid


def test_auth_issues_valid_jwt_active_key():
    client = TestClient(app)

    r = client.post("/auth")
    assert r.status_code == 200
    token = r.json()["token"]
    assert token

    header = jwt.get_unverified_header(token)
    assert header["kid"] == keystore.active.kid

    payload = jwt.decode(
        token,
        keystore.active.public_key,
        algorithms=["RS256"],
        options={"verify_aud": False},
    )

    assert payload["sub"] == "mock-user"
    assert payload["iss"] == "jwks-server"
    assert payload["exp"] == int(keystore.active.expires_at.timestamp())


def test_auth_expired_query_uses_expired_key_and_expired_exp():
    client = TestClient(app)

    r = client.post("/auth?expired=1")
    assert r.status_code == 200
    token = r.json()["token"]
    assert token

    header = jwt.get_unverified_header(token)
    assert header["kid"] == keystore.expired.kid

    payload = jwt.decode(
        token,
        keystore.expired.public_key,
        algorithms=["RS256"],
        options={"verify_aud": False, "verify_exp": False},
    )

    assert payload["exp"] == int(keystore.expired.expires_at.timestamp())
    assert payload["exp"] < int(datetime.now(tz=UTC).timestamp())

    # JWKS should not include expired kid
    jwks = client.get("/.well-known/jwks.json").json()
    kids = [k["kid"] for k in jwks["keys"]]
    assert keystore.expired.kid not in kids