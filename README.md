# Python JWKS Server (FastAPI)

## Endpoints

- `GET /.well-known/jwks.json`  
  Returns JWKS containing ONLY unexpired public keys.

- `POST /auth`  
  Returns `{ "token": "<jwt>" }` (no body required).

- `POST /auth?expired=1`  
  Returns a JWT signed with an expired key, and the JWT `exp` is in the past.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
