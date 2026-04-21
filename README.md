# conectmw

SMB share browser as FastAPI web service + installable PWA. Deployable on Coolify. No credentials in env — users add connections via the web UI; credentials are encrypted at rest in SQLite.

## Features

- Web UI for browsing SMB shares and downloading files
- Installable PWA (Chrome, Edge, Android home-screen, iOS Add to Home)
- Multiple saved connection profiles (name, host, user, pass, share, domain)
- Passwords encrypted with Fernet (key persisted in data volume)
- Optional login password (`APP_PASSWORD`) protects the UI
- Port fallback: 445 (direct TCP) ↔ 139 (NetBIOS)
- Test connection button
- Works on LAN for Android phones pointed at the same URL

## Environment

Only the app itself needs env vars. **No SMB credentials in env.**

| Var | Required | Purpose |
|-----|----------|---------|
| `APP_PASSWORD` | recommended | Protects the UI. Empty = open (do not use in public) |
| `SECRET_KEY` | optional | Fernet key (base64, 44 chars). Auto-generated and persisted to `/data/secret.key` if missing |
| `CORS_ORIGINS` | optional | Comma list, default `*` |
| `PORT` | optional | Default `8000` |
| `DATA_DIR` | optional | Default `/data` — must be a persistent volume |
| `SMB_CONNECT_TIMEOUT` | optional | Seconds, default `10` |

Generate `APP_PASSWORD` / `SECRET_KEY`:

```bash
openssl rand -hex 32                         # APP_PASSWORD
python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"   # SECRET_KEY
```

## Local Dev

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATA_DIR=./data APP_PASSWORD=test
python app.py
```

Open http://localhost:8000 → login → add connection.

## Docker

```bash
docker compose up -d --build
```

Data persists in the `conectmw_data` volume (SQLite + Fernet key).

## Coolify Deploy

1. New Resource → Public Repository → `https://github.com/afstudy20-gif/conectmw`
2. Build Pack: **Dockerfile**
3. Port: `8000`
4. Persistent Storage: mount `/data` (volume) — required, stores profiles + encryption key
5. Env: set `APP_PASSWORD` (long random). Optionally set `SECRET_KEY` to pin encryption key across redeploys (otherwise it lives on the volume)
6. Enable HTTPS (required for PWA install from non-localhost)
7. Deploy, open domain, login, add connection

### Network

SMB target must be reachable from the Coolify host. For on-prem SMB from a cloud Coolify, use WireGuard/Tailscale into the LAN, or run Coolify on the same LAN.

## Install as App

- **Chrome/Edge desktop**: address bar install icon → Install
- **Android Chrome**: menu → Install app
- **iOS Safari**: Share → Add to Home Screen

Requires HTTPS (or `localhost`).

## Security

- Always set `APP_PASSWORD` when exposed publicly
- Serve over HTTPS
- SMB passwords encrypted with Fernet — key stored outside DB (`/data/secret.key`) or in `SECRET_KEY` env
- Sessions in SQLite, HttpOnly cookie
- Restrict `CORS_ORIGINS` to your domain in production

## API

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/auth/status` | GET | - | Session state |
| `/auth/login` | POST | - | Login with `APP_PASSWORD` |
| `/auth/logout` | POST | session | Drop session |
| `/profiles` | GET | session | List connections |
| `/profiles` | POST | session | Create connection |
| `/profiles/{id}` | PUT | session | Update |
| `/profiles/{id}` | DELETE | session | Remove |
| `/profiles/{id}/test` | POST | session | Test SMB connect |
| `/fs/shares?profile_id=` | GET | session | List shares |
| `/fs/list?profile_id=&path=` | GET | session | List dir |
| `/fs/download?profile_id=&path=` | GET | session | Download file |
| `/healthz` | GET | - | Liveness |
