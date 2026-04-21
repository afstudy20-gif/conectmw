# conectmw

SMB share browser as FastAPI web service + installable PWA. Deployable on Coolify. Accessible from desktop browsers and Android phones on the same network.

## Features

- Browse SMB shares over HTTP
- Download files
- Installable PWA (Chrome, Edge, Android "Add to Home screen")
- Mobile-friendly dark UI
- Optional API key auth
- Port fallback (445 → 139) if primary SMB port blocked
- Healthcheck endpoint

## Endpoints

| Path | Method | Auth | Purpose |
|------|--------|------|---------|
| `/` | GET | no | Web UI (PWA) |
| `/healthz` | GET | no | Liveness |
| `/ready` | GET | no | SMB connectivity probe |
| `/shares` | GET | key | List shares on server |
| `/list?path=/&share=X` | GET | key | List files in path |
| `/download?path=/file.ext&share=X` | GET | key | Stream file |
| `/manifest.webmanifest`, `/sw.js`, `/icon.svg` | GET | no | PWA assets |

API key via `X-API-Key` header or `?key=...` query.

## Local Dev

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit
python app.py
```

Open http://localhost:8000

## Docker

```bash
docker compose up -d --build
```

## Coolify Deploy

1. New Resource → Public Repository → `https://github.com/afstudy20-gif/conectmw`
2. Build Pack: **Dockerfile**
3. Port: `8000`
4. Set env vars (see `.env.example`): at minimum `SMB_USER`, `SMB_PASS`, `SMB_IP`, `SMB_SHARE`
5. Set `API_KEY` to a long random string (recommended)
6. Enable HTTPS (required for PWA install on remote hosts)
7. Deploy

### Network notes

SMB target must be reachable from the Coolify host. For on-prem SMB from remote Coolify, use a VPN (WireGuard/Tailscale) into the LAN, or run Coolify on the same LAN.

## Install as App

- **Chrome/Edge desktop**: Visit URL → address bar install icon → Install
- **Android Chrome**: Menu → Install app / Add to Home screen
- **iOS Safari**: Share → Add to Home Screen

PWA install requires HTTPS (or `localhost`).

## Security

- Always set `API_KEY` when exposed publicly
- Run behind HTTPS
- Restrict `CORS_ORIGINS` to your domain(s) in production
- SMB creds live in env only, never in repo

## Port Fallback

Default: tries `SMB_PORT` (445, direct TCP), then 139 (NetBIOS). Disable with `SMB_PORT_FALLBACK=false`.
