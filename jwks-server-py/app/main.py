from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .keystore import KeyStore


UTC = timezone.utc


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


app = FastAPI(title="JWKS Server", version="1.0.0")
keystore = KeyStore(utcnow())


@app.get("/.well-known/jwks.json")
def get_jwks() -> dict:
    return keystore.jwks(utcnow())


@app.post("/auth")
def post_auth(request: Request) -> Response:
    # If “expired” query parameter exists (any value), issue expired token
    use_expired = "expired" in request.query_params
    token = keystore.issue_jwt(utcnow(), use_expired=use_expired)
    return JSONResponse({"token": token})