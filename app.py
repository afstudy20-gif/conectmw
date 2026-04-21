import io
import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from cryptography.fernet import Fernet
from fastapi import Body, Cookie, Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from smb.SMBConnection import SMBConnection

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "conectmw.db"
KEY_PATH = DATA_DIR / "secret.key"

APP_PASSWORD = os.getenv("APP_PASSWORD", "")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
CONNECT_TIMEOUT = int(os.getenv("SMB_CONNECT_TIMEOUT", "10"))
SESSION_COOKIE = "conectmw_session"


def _load_or_create_key() -> bytes:
    env_key = os.getenv("SECRET_KEY", "").strip()
    if env_key:
        return env_key.encode() if len(env_key) >= 44 else Fernet.generate_key()
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    k = Fernet.generate_key()
    KEY_PATH.write_bytes(k)
    try:
        os.chmod(KEY_PATH, 0o600)
    except Exception:
        pass
    return k


FERNET = Fernet(_load_or_create_key())


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with db() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS profiles(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 445,
                username TEXT NOT NULL,
                password_enc BLOB NOT NULL,
                share TEXT NOT NULL,
                domain TEXT NOT NULL DEFAULT '',
                direct_tcp INTEGER NOT NULL DEFAULT 1,
                port_fallback INTEGER NOT NULL DEFAULT 1,
                client_name TEXT NOT NULL DEFAULT 'conectmw',
                server_name TEXT NOT NULL DEFAULT 'smb-server',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions(
                token TEXT PRIMARY KEY,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()

app = FastAPI(title="conectmw", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_session(session: str = Cookie(default="", alias=SESSION_COOKIE)) -> None:
    if not APP_PASSWORD:
        return
    if not session:
        raise HTTPException(status_code=401, detail="login required")
    with db() as c:
        r = c.execute("SELECT 1 FROM sessions WHERE token=?", (session,)).fetchone()
    if not r:
        raise HTTPException(status_code=401, detail="invalid session")


class LoginBody(BaseModel):
    password: str


class ProfileIn(BaseModel):
    name: str = Field(default="", max_length=64)
    host: str = Field(min_length=1)
    port: int = 445
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    share: str = Field(min_length=1)
    domain: str = ""
    direct_tcp: bool = True
    port_fallback: bool = True
    client_name: str = "conectmw"
    server_name: str = "smb-server"


class ProfileUpdate(BaseModel):
    name: str | None = None
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    share: str | None = None
    domain: str | None = None
    direct_tcp: bool | None = None
    port_fallback: bool | None = None
    client_name: str | None = None
    server_name: str | None = None


def _profile_row_to_dict(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "name": r["name"],
        "host": r["host"],
        "port": r["port"],
        "username": r["username"],
        "share": r["share"],
        "domain": r["domain"],
        "direct_tcp": bool(r["direct_tcp"]),
        "port_fallback": bool(r["port_fallback"]),
        "client_name": r["client_name"],
        "server_name": r["server_name"],
    }


def _get_profile(profile_id: int) -> dict:
    with db() as c:
        r = c.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="profile not found")
    d = _profile_row_to_dict(r)
    d["password"] = FERNET.decrypt(r["password_enc"]).decode()
    return d


def _candidate_ports(port: int, direct: bool, fallback: bool) -> list[tuple[int, bool]]:
    primary = (port, direct)
    if not fallback:
        return [primary]
    alt = (139, False) if port == 445 else (445, True)
    return [primary] + ([alt] if alt != primary else [])


def _connect_profile(p: dict) -> SMBConnection:
    errors: list[str] = []
    for port, direct in _candidate_ports(p["port"], p["direct_tcp"], p["port_fallback"]):
        conn = SMBConnection(
            p["username"], p["password"], p["client_name"], p["server_name"],
            domain=p["domain"], use_ntlm_v2=True, is_direct_tcp=direct,
        )
        try:
            if conn.connect(p["host"], port, timeout=CONNECT_TIMEOUT):
                return conn
            errors.append(f"port {port} direct_tcp={direct}: refused")
        except Exception as e:
            errors.append(f"port {port} direct_tcp={direct}: {e}")
        try:
            conn.close()
        except Exception:
            pass
    raise HTTPException(status_code=502, detail="connect failed: " + "; ".join(errors))


@contextmanager
def smb_conn(profile_id: int) -> Iterator[tuple[SMBConnection, dict]]:
    p = _get_profile(profile_id)
    conn = _connect_profile(p)
    try:
        yield conn, p
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


@app.get("/auth/status")
def auth_status(session: str = Cookie(default="", alias=SESSION_COOKIE)) -> dict:
    if not APP_PASSWORD:
        return {"auth_required": False, "logged_in": True}
    with db() as c:
        r = c.execute("SELECT 1 FROM sessions WHERE token=?", (session,)).fetchone() if session else None
    return {"auth_required": True, "logged_in": bool(r)}


@app.post("/auth/login")
def login(body: LoginBody, response: Response) -> dict:
    if not APP_PASSWORD:
        return {"ok": True}
    if not secrets.compare_digest(body.password, APP_PASSWORD):
        raise HTTPException(status_code=401, detail="invalid password")
    tok = secrets.token_urlsafe(32)
    with db() as c:
        c.execute("INSERT INTO sessions(token) VALUES(?)", (tok,))
    response.set_cookie(
        SESSION_COOKIE, tok,
        httponly=True, samesite="lax", secure=False, max_age=60 * 60 * 24 * 30, path="/",
    )
    return {"ok": True}


@app.post("/auth/logout")
def logout(response: Response, session: str = Cookie(default="", alias=SESSION_COOKIE)) -> dict:
    if session:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (session,))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/profiles", dependencies=[Depends(require_session)])
def list_profiles() -> list[dict]:
    with db() as c:
        rows = c.execute("SELECT * FROM profiles ORDER BY name").fetchall()
    return [_profile_row_to_dict(r) for r in rows]


def _unique_name(base: str) -> str:
    with db() as c:
        existing = {r["name"] for r in c.execute("SELECT name FROM profiles").fetchall()}
    if base not in existing:
        return base
    i = 2
    while f"{base} ({i})" in existing:
        i += 1
    return f"{base} ({i})"


@app.post("/profiles", dependencies=[Depends(require_session)])
def create_profile(p: ProfileIn) -> dict:
    enc = FERNET.encrypt(p.password.encode())
    name = p.name.strip() or _unique_name(f"{p.username}@{p.host}")
    try:
        with db() as c:
            cur = c.execute(
                """INSERT INTO profiles(name,host,port,username,password_enc,share,domain,direct_tcp,port_fallback,client_name,server_name)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (name, p.host, p.port, p.username, enc, p.share, p.domain,
                 int(p.direct_tcp), int(p.port_fallback), p.client_name, p.server_name),
            )
            pid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="name exists")
    return {"id": pid, "name": name}


@app.put("/profiles/{pid}", dependencies=[Depends(require_session)])
def update_profile(pid: int, body: ProfileUpdate = Body(...)) -> dict:
    fields = body.model_dump(exclude_unset=True)
    if "password" in fields:
        fields["password_enc"] = FERNET.encrypt(fields.pop("password").encode())
    if "direct_tcp" in fields:
        fields["direct_tcp"] = int(fields["direct_tcp"])
    if "port_fallback" in fields:
        fields["port_fallback"] = int(fields["port_fallback"])
    if not fields:
        return {"ok": True}
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [pid]
    with db() as c:
        cur = c.execute(f"UPDATE profiles SET {cols} WHERE id=?", vals)
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="not found")
    return {"ok": True}


@app.delete("/profiles/{pid}", dependencies=[Depends(require_session)])
def delete_profile(pid: int) -> dict:
    with db() as c:
        c.execute("DELETE FROM profiles WHERE id=?", (pid,))
    return {"ok": True}


@app.post("/profiles/{pid}/test", dependencies=[Depends(require_session)])
def test_profile(pid: int) -> dict:
    with smb_conn(pid) as (c, _):
        c.listShares(timeout=10)
    return {"ok": True}


@app.get("/fs/list", dependencies=[Depends(require_session)])
def fs_list(profile_id: int, path: str = "/", share: str | None = Query(default=None)) -> list[dict]:
    with smb_conn(profile_id) as (c, p):
        items = c.listPath(share or p["share"], path)
    return [
        {"name": i.filename, "is_dir": i.isDirectory, "size": i.file_size, "mtime": i.last_write_time}
        for i in items if i.filename not in (".", "..")
    ]


@app.get("/fs/shares", dependencies=[Depends(require_session)])
def fs_shares(profile_id: int) -> list[dict]:
    with smb_conn(profile_id) as (c, _):
        return [{"name": s.name, "comments": s.comments} for s in c.listShares(timeout=15) if not s.isSpecial]


@app.get("/fs/download", dependencies=[Depends(require_session)])
def fs_download(profile_id: int, path: str, share: str | None = None) -> StreamingResponse:
    buf = io.BytesIO()
    with smb_conn(profile_id) as (c, p):
        c.retrieveFile(share or p["share"], path, buf)
    buf.seek(0)
    fname = path.rsplit("/", 1)[-1] or "download.bin"
    return StreamingResponse(
        buf, media_type="application/octet-stream",
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
:root{--bg:#0b0f14;--fg:#e6edf3;--mut:#7d8590;--acc:#2f81f7;--card:#151b23;--bd:#30363d;--ok:#3fb950;--err:#f85149}
*{box-sizing:border-box}
body{margin:0;font:15px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:1px solid var(--bd);padding:12px 14px;display:flex;gap:8px;align-items:center}
header h1{font-size:17px;margin:0;flex:1;cursor:pointer}
button,.btn{background:var(--acc);color:#fff;border:none;border-radius:8px;padding:9px 14px;font-size:14px;cursor:pointer}
button.sec{background:transparent;border:1px solid var(--bd);color:var(--fg)}
button.danger{background:var(--err)}
main{padding:14px;padding-bottom:calc(env(safe-area-inset-bottom) + 80px);max-width:720px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-bottom:10px}
input,select{width:100%;padding:10px;border:1px solid var(--bd);background:var(--bg);color:var(--fg);border-radius:8px;font-size:15px;margin-top:4px}
label{display:block;font-size:13px;color:var(--mut);margin-top:10px}
.row{display:flex;gap:8px}.row>*{flex:1}
.crumbs{color:var(--mut);font-size:13px;margin:6px 0 10px;word-break:break-all}
.crumbs a{color:var(--acc);text-decoration:none}
ul.ls{list-style:none;padding:0;margin:0}
ul.ls li{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:11px 14px;margin-bottom:6px;display:flex;align-items:center;gap:10px}
ul.ls li .n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
ul.ls li .s{color:var(--mut);font-size:12px;flex:0 0 auto}
ul.ls li a{color:var(--fg);text-decoration:none}
.icon{width:22px;text-align:center}
.err{color:var(--err);padding:10px;border:1px solid var(--err);border-radius:8px;margin:10px 0;font-size:13px}
.empty{color:var(--mut);padding:24px;text-align:center}
.chk{display:flex;align-items:center;gap:8px;margin-top:10px}.chk input{width:auto;margin:0}
.actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.profile h3{margin:0 0 4px;font-size:16px}
.profile .meta{color:var(--mut);font-size:12px}
.hide{display:none}
</style>
</head>
<body>
<header>
  <h1 id="home">conectmw</h1>
  <button id="logoutBtn" class="sec hide">Logout</button>
</header>
<main id="app"></main>
<script>
const app=document.getElementById("app"),logoutBtn=document.getElementById("logoutBtn");
document.getElementById("home").onclick=()=>{location.hash=""};
let AUTH={auth_required:false,logged_in:true};
const esc=s=>(s??"").toString().replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function fmt(b){if(b==null)return"";const u=["B","KB","MB","GB","TB"];let i=0,n=b;while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(n<10&&i>0?1:0)+u[i]}
async function api(p,opts={}){
  const r=await fetch(p,{credentials:"same-origin",headers:{"Content-Type":"application/json"},...opts});
  if(r.status===401){AUTH.logged_in=false;renderLogin();throw new Error("unauthorized")}
  if(!r.ok){const t=await r.text();throw new Error(t||r.status)}
  const ct=r.headers.get("content-type")||"";return ct.includes("json")?r.json():r.text();
}
async function boot(){
  AUTH=await api("/auth/status");
  logoutBtn.classList.toggle("hide",!(AUTH.auth_required&&AUTH.logged_in));
  if(AUTH.auth_required&&!AUTH.logged_in){renderLogin();return}
  route();
}
logoutBtn.onclick=async()=>{await api("/auth/logout",{method:"POST"});AUTH.logged_in=false;logoutBtn.classList.add("hide");renderLogin()};
window.addEventListener("hashchange",route);
function route(){
  const h=location.hash.slice(1);
  if(!h||h==="/"){return renderProfiles()}
  const m=h.match(/^\\/p\\/(\\d+)(?:\\/(.*))?$/);
  if(m){return renderBrowser(Number(m[1]),"/"+(m[2]||""))}
  if(h==="/new"){return renderProfileForm()}
  const em=h.match(/^\\/edit\\/(\\d+)$/);
  if(em){return renderProfileForm(Number(em[1]))}
  renderProfiles();
}
function renderLogin(){
  app.innerHTML=`<div class="card"><h2 style="margin-top:0">Login</h2>
    <label>Password<input id="pw" type="password" autocomplete="current-password"/></label>
    <div id="loginErr" class="err hide"></div>
    <div class="actions"><button id="loginBtn">Sign in</button></div></div>`;
  document.getElementById("loginBtn").onclick=async()=>{
    const pw=document.getElementById("pw").value;
    try{await api("/auth/login",{method:"POST",body:JSON.stringify({password:pw})});AUTH.logged_in=true;logoutBtn.classList.remove("hide");location.hash="";route()}
    catch(e){const el=document.getElementById("loginErr");el.textContent=e.message;el.classList.remove("hide")}
  };
  document.getElementById("pw").addEventListener("keydown",e=>{if(e.key==="Enter")document.getElementById("loginBtn").click()});
}
async function renderProfiles(){
  app.innerHTML='<div class="empty">Loading…</div>';
  try{
    const profs=await api("/profiles");
    const items=profs.map(p=>`<div class="card profile">
      <h3>${esc(p.name)}</h3>
      <div class="meta">${esc(p.username)}@${esc(p.host)}:${p.port} · share: ${esc(p.share)}</div>
      <div class="actions">
        <button onclick="location.hash='/p/${p.id}'">Open</button>
        <button class="sec" onclick="testProfile(${p.id},this)">Test</button>
        <button class="sec" onclick="location.hash='/edit/${p.id}'">Edit</button>
        <button class="danger" onclick="delProfile(${p.id})">Delete</button>
      </div></div>`).join("");
    app.innerHTML=(items||'<div class="empty">No profiles yet</div>')+
      `<div class="actions"><button onclick="location.hash='/new'">+ New connection</button></div>`;
  }catch(e){app.innerHTML=`<div class="err">${esc(e.message)}</div>`}
}
async function testProfile(id,btn){btn.disabled=true;btn.textContent="Testing…";try{await api(`/profiles/${id}/test`,{method:"POST"});btn.textContent="OK";btn.style.background="var(--ok)";btn.style.color="#fff";btn.style.borderColor="var(--ok)"}catch(e){btn.textContent="Fail";btn.style.background="var(--err)";btn.style.color="#fff";btn.style.borderColor="var(--err)";alert(e.message)}finally{setTimeout(()=>{btn.disabled=false;btn.textContent="Test";btn.style.cssText=""},2500)}}
async function delProfile(id){if(!confirm("Delete profile?"))return;await api(`/profiles/${id}`,{method:"DELETE"});renderProfiles()}
async function renderProfileForm(id){
  let p={name:"",host:"",port:445,username:"",password:"",share:"",domain:"",direct_tcp:true,port_fallback:true,client_name:"conectmw",server_name:"smb-server"};
  if(id){const all=await api("/profiles");const f=all.find(x=>x.id===id);if(f){Object.assign(p,f);p.password=""}}
  app.innerHTML=`<div class="card"><h2 style="margin-top:0">${id?"Edit":"New"} connection</h2>
    <label>Name <span style="color:var(--mut)">(optional)</span><input id="f_name" placeholder="auto: user@host" value="${esc(p.name)}"/></label>
    <label>Host / IP<input id="f_host" placeholder="192.168.1.15" value="${esc(p.host)}"/></label>
    <div class="row"><label>Port<input id="f_port" type="number" value="${p.port}"/></label><label>Share<input id="f_share" placeholder="SharedFolder" value="${esc(p.share)}"/></label></div>
    <label>Username<input id="f_user" value="${esc(p.username)}" autocomplete="off"/></label>
    <label>Password${id?" <span style=\\"color:var(--mut)\\">(leave blank to keep)</span>":""}<input id="f_pass" type="password" autocomplete="new-password"/></label>
    <label>Domain (optional)<input id="f_domain" value="${esc(p.domain)}"/></label>
    <div class="chk"><input id="f_direct" type="checkbox" ${p.direct_tcp?"checked":""}/><label for="f_direct" style="margin:0">Direct TCP (port 445)</label></div>
    <div class="chk"><input id="f_fb" type="checkbox" ${p.port_fallback?"checked":""}/><label for="f_fb" style="margin:0">Port fallback (445 ↔ 139)</label></div>
    <div id="formErr" class="err hide"></div>
    <div class="actions">
      <button id="saveBtn">${id?"Save":"Create"}</button>
      <button class="sec" onclick="location.hash=''">Cancel</button>
    </div></div>`;
  document.getElementById("saveBtn").onclick=async()=>{
    const body={
      name:document.getElementById("f_name").value.trim(),
      host:document.getElementById("f_host").value.trim(),
      port:Number(document.getElementById("f_port").value)||445,
      username:document.getElementById("f_user").value,
      password:document.getElementById("f_pass").value,
      share:document.getElementById("f_share").value.trim(),
      domain:document.getElementById("f_domain").value.trim(),
      direct_tcp:document.getElementById("f_direct").checked,
      port_fallback:document.getElementById("f_fb").checked,
    };
    try{
      if(id){const payload={...body};if(!payload.password)delete payload.password;await api(`/profiles/${id}`,{method:"PUT",body:JSON.stringify(payload)})}
      else{if(!body.password){throw new Error("password required")}await api("/profiles",{method:"POST",body:JSON.stringify(body)})}
      location.hash="";
    }catch(e){const el=document.getElementById("formErr");el.textContent=e.message;el.classList.remove("hide")}
  };
}
async function renderBrowser(pid,path){
  app.innerHTML='<div class="empty">Loading…</div>';
  const parts=path.split("/").filter(Boolean);let acc="";
  const crumbs=[`<a href="#/p/${pid}">root</a>`];
  for(const s of parts){acc+="/"+s;crumbs.push(`<a href="#/p/${pid}${acc}">${esc(s)}</a>`)}
  try{
    const items=await api(`/fs/list?profile_id=${pid}&path=${encodeURIComponent(path)}`);
    items.sort((a,b)=>(b.is_dir-a.is_dir)||a.name.localeCompare(b.name));
    const list=items.map(i=>{
      const np=(path.endsWith("/")?path:path+"/")+i.name;
      if(i.is_dir)return `<li><span class="icon">📁</span><a class="n" href="#/p/${pid}${np}">${esc(i.name)}</a></li>`;
      const dl=`/fs/download?profile_id=${pid}&path=${encodeURIComponent(np)}`;
      return `<li><span class="icon">📄</span><a class="n" href="${dl}" download>${esc(i.name)}</a><span class="s">${fmt(i.size)}</span></li>`;
    }).join("");
    app.innerHTML=`<div class="crumbs">${crumbs.join(" / ")}</div>`+
      (list?`<ul class="ls">${list}</ul>`:'<div class="empty">Empty</div>')+
      `<div class="actions"><button class="sec" onclick="location.hash=''">← Profiles</button></div>`;
  }catch(e){app.innerHTML=`<div class="err">${esc(e.message)}</div><div class="actions"><button class="sec" onclick="location.hash=''">← Profiles</button></div>`}
}
boot();
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
    "description": "SMB share browser",
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

SW_JS = """const CACHE="conectmw-v2";
const ASSETS=["/","/icon.svg","/manifest.webmanifest"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting()))});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=="GET"){return}
  if(u.pathname.startsWith("/fs/")||u.pathname.startsWith("/profiles")||u.pathname.startsWith("/auth/")){return}
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
