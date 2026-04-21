import io
import os
from contextlib import contextmanager
from typing import Iterator

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from smb.SMBConnection import SMBConnection

SMB_USER = os.getenv("SMB_USER", "")
SMB_PASS = os.getenv("SMB_PASS", "")
SMB_CLIENT = os.getenv("SMB_CLIENT", "coolify-client")
SMB_SERVER = os.getenv("SMB_SERVER", "smb-server")
SMB_IP = os.getenv("SMB_IP", "")
SMB_SHARE = os.getenv("SMB_SHARE", "")
SMB_PORT = int(os.getenv("SMB_PORT", "445"))
SMB_DOMAIN = os.getenv("SMB_DOMAIN", "")
USE_NTLM_V2 = os.getenv("SMB_USE_NTLM_V2", "true").lower() == "true"
IS_DIRECT_TCP = os.getenv("SMB_DIRECT_TCP", "true").lower() == "true"
PORT_FALLBACK = os.getenv("SMB_PORT_FALLBACK", "true").lower() == "true"
CONNECT_TIMEOUT = int(os.getenv("SMB_CONNECT_TIMEOUT", "10"))

API_KEY = os.getenv("API_KEY", "")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]

app = FastAPI(title="conectmw", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


def require_api_key(x_api_key: str = Header(default=""), key: str = Query(default="")) -> None:
    if not API_KEY:
        return
    provided = x_api_key or key
    if provided != API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")


def _candidate_ports() -> list[tuple[int, bool]]:
    primary = (SMB_PORT, IS_DIRECT_TCP)
    if not PORT_FALLBACK:
        return [primary]
    alt = (139, False) if SMB_PORT == 445 else (445, True)
    seen: list[tuple[int, bool]] = []
    for c in (primary, alt):
        if c not in seen:
            seen.append(c)
    return seen


def _try_connect() -> SMBConnection:
    errors: list[str] = []
    for port, direct in _candidate_ports():
        conn = SMBConnection(
            SMB_USER, SMB_PASS, SMB_CLIENT, SMB_SERVER,
            domain=SMB_DOMAIN, use_ntlm_v2=USE_NTLM_V2, is_direct_tcp=direct,
        )
        try:
            if conn.connect(SMB_IP, port, timeout=CONNECT_TIMEOUT):
                return conn
            errors.append(f"port {port} direct_tcp={direct}: refused")
        except Exception as e:
            errors.append(f"port {port} direct_tcp={direct}: {e}")
        finally:
            if not conn.sock:
                try:
                    conn.close()
                except Exception:
                    pass
    raise HTTPException(status_code=502, detail="smb connect failed: " + "; ".join(errors))


@contextmanager
def smb_conn() -> Iterator[SMBConnection]:
    if not all([SMB_USER, SMB_PASS, SMB_IP, SMB_SHARE]):
        raise HTTPException(status_code=500, detail="smb env vars missing")
    conn = _try_connect()
    try:
        yield conn
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"smb error: {e}") from e
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/ready")
def ready() -> dict:
    with smb_conn() as c:
        c.listShares(timeout=10)
    return {"ok": True, "smb": "up"}


@app.get("/shares", dependencies=[Depends(require_api_key)])
def shares() -> list[dict]:
    with smb_conn() as c:
        return [
            {"name": s.name, "comments": s.comments}
            for s in c.listShares(timeout=15)
            if not s.isSpecial
        ]


@app.get("/list", dependencies=[Depends(require_api_key)])
def list_path(path: str = Query("/"), share: str | None = None) -> list[dict]:
    target_share = share or SMB_SHARE
    with smb_conn() as c:
        items = c.listPath(target_share, path)
    return [
        {
            "name": i.filename,
            "is_dir": i.isDirectory,
            "size": i.file_size,
            "mtime": i.last_write_time,
        }
        for i in items
        if i.filename not in (".", "..")
    ]


@app.get("/download", dependencies=[Depends(require_api_key)])
def download(path: str, share: str | None = None) -> StreamingResponse:
    target_share = share or SMB_SHARE
    buf = io.BytesIO()
    with smb_conn() as c:
        c.retrieveFile(target_share, path, buf)
    buf.seek(0)
    fname = path.rsplit("/", 1)[-1] or "download.bin"
    return StreamingResponse(
        buf,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<meta name="theme-color" content="#0b0f14"/>
<title>conectmw</title>
<link rel="manifest" href="/manifest.webmanifest"/>
<link rel="icon" type="image/svg+xml" href="/icon.svg"/>
<link rel="apple-touch-icon" href="/icon-192.png"/>
<meta name="apple-mobile-web-app-capable" content="yes"/>
<meta name="apple-mobile-web-app-title" content="conectmw"/>
<meta name="mobile-web-app-capable" content="yes"/>
<style>
:root{--bg:#0b0f14;--fg:#e6edf3;--mut:#7d8590;--acc:#2f81f7;--card:#151b23;--bd:#30363d}
*{box-sizing:border-box}
body{margin:0;font:16px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--bd);padding:12px 14px;display:flex;gap:8px;align-items:center}
header h1{font-size:17px;margin:0;flex:1}
header input{flex:0 0 auto;width:130px;padding:8px;border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:8px}
main{padding:12px 14px;padding-bottom:env(safe-area-inset-bottom)}
.crumbs{color:var(--mut);font-size:14px;margin:6px 0 10px;word-break:break-all}
.crumbs a{color:var(--acc);text-decoration:none}
ul{list-style:none;padding:0;margin:0}
li{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:8px;display:flex;align-items:center;gap:10px}
li .n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
li .s{color:var(--mut);font-size:13px;flex:0 0 auto}
li a{color:var(--fg);text-decoration:none}
.icon{width:22px;text-align:center}
.err{color:#f85149;padding:10px;border:1px solid #f85149;border-radius:8px;margin:10px 0}
.empty{color:var(--mut);padding:20px;text-align:center}
</style>
</head>
<body>
<header>
  <h1>conectmw</h1>
  <input id="k" placeholder="API key" autocomplete="off"/>
</header>
<main>
  <div class="crumbs" id="crumbs"></div>
  <ul id="list"></ul>
</main>
<script>
const $=s=>document.querySelector(s);
const kInp=$("#k"); kInp.value=localStorage.getItem("conectmw_key")||"";
kInp.addEventListener("change",()=>{localStorage.setItem("conectmw_key",kInp.value);load();});
function fmt(b){if(!b&&b!==0)return"";const u=["B","KB","MB","GB","TB"];let i=0,n=b;while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(n<10&&i>0?1:0)+u[i]}
function enc(p){return encodeURIComponent(p)}
function qk(){const k=kInp.value.trim();return k?`&key=${enc(k)}`:""}
function pathOf(){return new URLSearchParams(location.search).get("p")||"/"}
function go(p){location.search="?p="+enc(p)}
function crumbs(p){const parts=p.split("/").filter(Boolean);let acc="";const links=['<a href="?p=%2F">/</a>'];for(const seg of parts){acc+="/"+seg;links.push(`<a href="?p=${enc(acc)}">${seg}</a>`)}$("#crumbs").innerHTML=links.join(" / ")}
async function load(){
  const p=pathOf();crumbs(p);
  const list=$("#list");list.innerHTML='<div class="empty">Loading…</div>';
  try{
    const r=await fetch(`/list?path=${enc(p)}${qk()}`,{headers:kInp.value?{'X-API-Key':kInp.value}:{}});
    if(!r.ok){throw new Error(await r.text()||r.status)}
    const items=await r.json();
    if(!items.length){list.innerHTML='<div class="empty">Empty</div>';return}
    items.sort((a,b)=>(b.is_dir-a.is_dir)||a.name.localeCompare(b.name));
    list.innerHTML=items.map(i=>{
      const np=(p.endsWith("/")?p:p+"/")+i.name;
      if(i.is_dir){return `<li><span class="icon">📁</span><a class="n" href="?p=${enc(np)}">${i.name}</a></li>`}
      const dl=`/download?path=${enc(np)}${qk()}`;
      return `<li><span class="icon">📄</span><a class="n" href="${dl}" download>${i.name}</a><span class="s">${fmt(i.size)}</span></li>`;
    }).join("");
  }catch(e){list.innerHTML=`<div class="err">${e.message||e}</div>`}
}
load();
if("serviceWorker" in navigator){navigator.serviceWorker.register("/sw.js").catch(()=>{})}
</script>
</body>
</html>
"""

ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192">
<rect width="192" height="192" rx="36" fill="#0b0f14"/>
<path d="M40 64h48l12 12h52v52H40z" fill="#2f81f7"/>
<path d="M40 64h48l12 12h52v8H40z" fill="#1f6feb"/>
<circle cx="96" cy="128" r="10" fill="#0b0f14"/>
</svg>"""

MANIFEST = {
    "name": "conectmw",
    "short_name": "conectmw",
    "description": "SMB paylasim tarayici",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "orientation": "portrait",
    "background_color": "#0b0f14",
    "theme_color": "#0b0f14",
    "icons": [
        {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"},
        {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
    ],
}

SW_JS = """const CACHE="conectmw-v1";
const ASSETS=["/","/icon.svg","/manifest.webmanifest"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting()))});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=="GET"){return}
  if(u.pathname.startsWith("/list")||u.pathname.startsWith("/download")||u.pathname.startsWith("/shares")||u.pathname.startsWith("/ready")){return}
  e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request).then(resp=>{const c=resp.clone();caches.open(CACHE).then(ca=>ca.put(e.request,c));return resp}).catch(()=>caches.match("/"))))
});
"""

PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000d49444154789c6300010000000500010d0a2db40000000049454e44"
    "ae426082"
)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


@app.get("/manifest.webmanifest")
def manifest() -> JSONResponse:
    return JSONResponse(MANIFEST, media_type="application/manifest+json")


@app.get("/sw.js")
def sw() -> Response:
    return Response(SW_JS, media_type="application/javascript")


@app.get("/icon.svg")
def icon_svg() -> Response:
    return Response(ICON_SVG, media_type="image/svg+xml")


@app.get("/icon-192.png")
@app.get("/icon-512.png")
def icon_png() -> Response:
    return Response(PNG_1X1, media_type="image/png")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
