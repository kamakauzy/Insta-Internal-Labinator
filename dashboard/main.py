"""Insta-Internal-Labinator Dashboard — Main Application."""

import secrets
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, WebSocket, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware

DASHBOARD_DIR = Path(__file__).parent
STATIC_DIR = DASHBOARD_DIR / "static"
TOKEN_FILE = DASHBOARD_DIR / ".auth_token"


def _get_or_create_token() -> str:
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip()
    token = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(token)
    return token


AUTH_TOKEN = _get_or_create_token()

app = FastAPI(title="Labinator Dashboard", docs_url="/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not secrets.compare_digest(credentials.credentials, AUTH_TOKEN):
        raise HTTPException(401, "Invalid token")
    return True


# Static files and SPA
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    return FileResponse(str(STATIC_DIR / "index.html"))


# Auth check endpoint (no bearer required — token in body)
@app.post("/api/auth")
async def auth_check(body: dict):
    if secrets.compare_digest(body.get("token", ""), AUTH_TOKEN):
        return {"ok": True}
    raise HTTPException(401, "Invalid token")


# Include API routes with auth
from .api import router as api_router, ws_build, ws_logs, ws_ad_expansion, ws_lx01_provision, ws_scenario_deploy  # noqa: E402
app.include_router(api_router, dependencies=[Depends(verify_token)])


# WebSocket routes (auth via query param)
@app.websocket("/ws/build")
async def websocket_build(websocket: WebSocket, token: str = Query("")):
    await ws_build(websocket, token)


@app.websocket("/ws/logs/{name}")
async def websocket_logs(websocket: WebSocket, name: str, token: str = Query("")):
    await ws_logs(websocket, name, token)


@app.websocket("/ws/ad-expansion")
async def websocket_ad_expansion(websocket: WebSocket, token: str = Query("")):
    await ws_ad_expansion(websocket, token)


@app.websocket("/ws/lx01-provision")
async def websocket_lx01_provision(websocket: WebSocket, token: str = Query("")):
    await ws_lx01_provision(websocket, token)


@app.websocket("/ws/scenario-deploy")
async def websocket_scenario_deploy(websocket: WebSocket, token: str = Query("")):
    await ws_scenario_deploy(websocket, token)


@app.on_event("startup")
async def startup():
    print()
    print("=" * 62)
    print("  INSTA-INTERNAL-LABINATOR — DASHBOARD v1.0")
    print("=" * 62)
    print()
    print(f"  URL:     http://0.0.0.0:8888")
    print(f"  Token:   {AUTH_TOKEN}")
    print()
    print("  Open the URL in your browser and enter the token.")
    print("=" * 62)
    print()
