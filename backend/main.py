"""
FTO Gestionale Noleggio — FastAPI Backend v3.2
Tutti i campi del gestionale desktop, sicurezza completa.
"""
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
import io
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime, timedelta
from typing import Optional
import os, hashlib, platform, time
from collections import defaultdict
from jose import JWTError, jwt
from pydantic import BaseModel
import psycopg2, psycopg2.extras
from contextlib import contextmanager

SECRET_KEY         = os.getenv("SECRET_KEY", "fto-secret-2025")
ALGORITHM          = "HS256"
TOKEN_EXPIRE_HOURS = 12
DATABASE_URL       = os.getenv("DATABASE_URL", "")

ALLOWED_ORIGINS = [
    "https://web-production-eb644.up.railway.app",
    "https://gestionale.ftorent.it",
    "https://ftorent.it",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

MAX_ATTEMPTS   = 5
LOCKOUT_SECS   = 900
RATE_LIMIT_RPM = 60

def _h(pw): return hashlib.sha256(pw.encode()).hexdigest()

USERS = {
    "ak":       {"hash": _h("ak47ven"),   "role": "admin",    "display": "Ak"},
    "toad":     {"hash": _h("caramello"), "role": "admin",    "display": "Toad"},
    "fuma":     {"hash": _h("Alex2001$"), "role": "admin",    "display": "Fuma"},
    "utente 1": {"hash": _h("ftorent$"),  "role": "employee", "display": "Utente 1"},
}

_login_attempts: dict = defaultdict(lambda: {"attempts": 0, "locked_until": 0.0})
_request_log:    dict = defaultdict(list)

def get_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd: return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def rate_limit(ip: str):
    now = time.time()
    _request_log[ip] = [t for t in _request_log[ip] if t > now - 60]
    if len(_request_log[ip]) >= RATE_LIMIT_RPM:
        raise HTTPException(429, "Troppe richieste.")
    _request_log[ip].append(now)

def check_brute(ip: str):
    s = _login_attempts[ip]
    if time.time() < s["locked_until"]:
        raise HTTPException(429, f"Bloccato per {int(s['locked_until']-time.time())}s.")

def fail_login(ip: str):
    s = _login_attempts[ip]; s["attempts"] += 1
    if s["attempts"] >= MAX_ATTEMPTS:
        s["locked_until"] = time.time() + LOCKOUT_SECS; s["attempts"] = 0

def ok_login(ip: str):
    _login_attempts[ip] = {"attempts": 0, "locked_until": 0.0}

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        r = await call_next(request)
        r.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        return r

@contextmanager
def db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()

def init_db():
    with db() as conn:
        conn.cursor().execute("""
        CREATE TABLE IF NOT EXISTS noleggi (
            id SERIAL PRIMARY KEY,
            -- contratto
            data_contratto TEXT DEFAULT '',
            -- cliente
            cl_nome TEXT DEFAULT '', cl_cognome TEXT DEFAULT '',
            cl_luogo TEXT DEFAULT '', cl_data_nascita TEXT DEFAULT '',
            cl_indirizzo TEXT DEFAULT '', cl_cf TEXT DEFAULT '',
            cl_doc TEXT DEFAULT '', cl_doc_da TEXT DEFAULT '',
            cl_doc_dt TEXT DEFAULT '', cl_pat TEXT DEFAULT '',
            cl_cat TEXT DEFAULT '', cl_pat_r TEXT DEFAULT '',
            cl_pat_s TEXT DEFAULT '',
            -- società
            soc_nome TEXT DEFAULT '', soc_sede TEXT DEFAULT '',
            soc_cf TEXT DEFAULT '', soc_piva TEXT DEFAULT '',
            -- guidatore
            gu_nome TEXT DEFAULT '', gu_cognome TEXT DEFAULT '',
            gu_luogo TEXT DEFAULT '', gu_data_nascita TEXT DEFAULT '',
            gu_indirizzo TEXT DEFAULT '', gu_cf TEXT DEFAULT '',
            gu_doc TEXT DEFAULT '', gu_doc_da TEXT DEFAULT '',
            gu_doc_dt TEXT DEFAULT '', gu_pat TEXT DEFAULT '',
            gu_cat TEXT DEFAULT '', gu_pat_r TEXT DEFAULT '',
            gu_pat_s TEXT DEFAULT '',
            -- conducente aggiuntivo
            ex_nome TEXT DEFAULT '', ex_cognome TEXT DEFAULT '',
            ex_luogo TEXT DEFAULT '', ex_data_nascita TEXT DEFAULT '',
            ex_indirizzo TEXT DEFAULT '', ex_cf TEXT DEFAULT '',
            ex_doc TEXT DEFAULT '', ex_doc_da TEXT DEFAULT '',
            ex_doc_dt TEXT DEFAULT '', ex_pat TEXT DEFAULT '',
            ex_cat TEXT DEFAULT '', ex_pat_r TEXT DEFAULT '',
            ex_pat_s TEXT DEFAULT '',
            -- auto
            marca_modello TEXT DEFAULT '', targa TEXT DEFAULT '',
            telaio TEXT DEFAULT '', cilindrata TEXT DEFAULT '',
            alimentazione TEXT DEFAULT '', anno TEXT DEFAULT '',
            colore TEXT DEFAULT '', km_iniziali TEXT DEFAULT '',
            -- date
            data_inizio TEXT DEFAULT '', ora_inizio TEXT DEFAULT '',
            data_fine TEXT DEFAULT '', ora_fine TEXT DEFAULT '',
            giorni TEXT DEFAULT '',
            -- tariffe
            prezzo_noleggio TEXT DEFAULT '', km_compresi TEXT DEFAULT '',
            deposito TEXT DEFAULT '', km_extra TEXT DEFAULT '',
            penale TEXT DEFAULT '', costo_violazione TEXT DEFAULT '',
            diff_carburante TEXT DEFAULT '', riconsegna_premium TEXT DEFAULT '',
            -- meta
            contratto_path TEXT DEFAULT '',
            verbale_stato TEXT DEFAULT '⏳ In attesa',
            verbale_path TEXT DEFAULT '',
            note TEXT DEFAULT '',
            nome_cognome TEXT GENERATED ALWAYS AS (cl_nome || ' ' || cl_cognome) STORED,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS verbali (
            id SERIAL PRIMARY KEY, noleggio_id INTEGER,
            data TEXT, ora TEXT, targa TEXT,
            km_iniziali TEXT, km_attuali TEXT, carburante TEXT,
            tipo_riconsegna TEXT, pulizia TEXT, pulizia_premium TEXT,
            oggetti TEXT, oggetti_desc TEXT, danno TEXT, tipo_danno TEXT,
            posizione_danno TEXT, costo_danno TEXT, descrizione TEXT,
            operatore TEXT, stato TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS auto (
            id SERIAL PRIMARY KEY, marca_modello TEXT, targa TEXT UNIQUE,
            telaio TEXT DEFAULT '', cilindrata TEXT DEFAULT '',
            alimentazione TEXT DEFAULT '', anno TEXT DEFAULT '',
            colore TEXT DEFAULT '', km INTEGER DEFAULT 0,
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS access_log (
            id SERIAL PRIMARY KEY, ts TIMESTAMPTZ DEFAULT NOW(),
            username TEXT, role TEXT, success BOOLEAN,
            ip TEXT, hostname TEXT, os_info TEXT, machine TEXT
        );
        """)
        print("[DB] Tables ready")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def create_token(data: dict):
    return jwt.encode({**data, "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)},
                      SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        p = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not p.get("sub"): raise HTTPException(401, "Token non valido")
        return p
    except JWTError:
        raise HTTPException(401, "Token scaduto")

def admin_only(p=Depends(verify_token)):
    if p.get("role") != "admin": raise HTTPException(403, "Solo admin")
    return p

app = FastAPI(title="FTO Gestionale", version="3.2", docs_url=None, redoc_url=None)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET","POST","PUT","DELETE"],
    allow_headers=["Authorization","Content-Type"],
    allow_credentials=True)

@app.on_event("startup")
def startup():
    try: init_db()
    except Exception as e: print(f"[WARN] DB: {e}")

frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
static_path   = os.path.join(frontend_path, "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")

@app.get("/")
def root():
    idx = os.path.join(frontend_path, "templates", "index.html")
    if os.path.exists(idx): return FileResponse(idx)
    return {"status": "FTO v3.2"}

# ── AUTH ──────────────────────────────────────────────────────
class LoginReq(BaseModel):
    username: str; password: str
    ip: Optional[str] = ""; hostname: Optional[str] = ""

@app.post("/api/auth/login")
def login(req: LoginReq, request: Request):
    ip = get_ip(request)
    check_brute(ip)
    username = req.username.strip().lower()
    user = USERS.get(username)
    success = user is not None and user["hash"] == _h(req.password)
    try:
        with db() as conn:
            conn.cursor().execute(
                "INSERT INTO access_log(username,role,success,ip,hostname,os_info,machine)"
                " VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (username, user["role"] if user else "?", success,
                 ip, req.hostname, platform.system(), platform.machine()))
    except: pass
    if not success:
        fail_login(ip)
        raise HTTPException(401, "Username o password errati")
    ok_login(ip)
    return {"access_token": create_token({"sub":username,"role":user["role"],"display":user["display"]}),
            "token_type":"bearer","display":user["display"],"role":user["role"]}

@app.get("/api/auth/me")
def me(p=Depends(verify_token)):
    return {"username":p["sub"],"display":p["display"],"role":p["role"]}

# ── NOLEGGI ───────────────────────────────────────────────────
class NoleggioIn(BaseModel):
    data_contratto: Optional[str]=""
    cl_nome: Optional[str]=""; cl_cognome: Optional[str]=""
    cl_luogo: Optional[str]=""; cl_data_nascita: Optional[str]=""
    cl_indirizzo: Optional[str]=""; cl_cf: Optional[str]=""
    cl_doc: Optional[str]=""; cl_doc_da: Optional[str]=""
    cl_doc_dt: Optional[str]=""; cl_pat: Optional[str]=""
    cl_cat: Optional[str]=""; cl_pat_r: Optional[str]=""
    cl_pat_s: Optional[str]=""
    soc_nome: Optional[str]=""; soc_sede: Optional[str]=""
    soc_cf: Optional[str]=""; soc_piva: Optional[str]=""
    gu_nome: Optional[str]=""; gu_cognome: Optional[str]=""
    gu_luogo: Optional[str]=""; gu_data_nascita: Optional[str]=""
    gu_indirizzo: Optional[str]=""; gu_cf: Optional[str]=""
    gu_doc: Optional[str]=""; gu_doc_da: Optional[str]=""
    gu_doc_dt: Optional[str]=""; gu_pat: Optional[str]=""
    gu_cat: Optional[str]=""; gu_pat_r: Optional[str]=""
    gu_pat_s: Optional[str]=""
    ex_nome: Optional[str]=""; ex_cognome: Optional[str]=""
    ex_luogo: Optional[str]=""; ex_data_nascita: Optional[str]=""
    ex_indirizzo: Optional[str]=""; ex_cf: Optional[str]=""
    ex_doc: Optional[str]=""; ex_doc_da: Optional[str]=""
    ex_doc_dt: Optional[str]=""; ex_pat: Optional[str]=""
    ex_cat: Optional[str]=""; ex_pat_r: Optional[str]=""
    ex_pat_s: Optional[str]=""
    marca_modello: Optional[str]=""; targa: Optional[str]=""
    telaio: Optional[str]=""; cilindrata: Optional[str]=""
    alimentazione: Optional[str]=""; anno: Optional[str]=""
    colore: Optional[str]=""; km_iniziali: Optional[str]=""
    data_inizio: Optional[str]=""; ora_inizio: Optional[str]=""
    data_fine: Optional[str]=""; ora_fine: Optional[str]=""
    giorni: Optional[str]=""
    prezzo_noleggio: Optional[str]=""; km_compresi: Optional[str]=""
    deposito: Optional[str]=""; km_extra: Optional[str]=""
    penale: Optional[str]=""; costo_violazione: Optional[str]=""
    diff_carburante: Optional[str]=""; riconsegna_premium: Optional[str]=""
    contratto_path: Optional[str]=""; note: Optional[str]=""

NOLEGGIO_COLS = [
    "data_contratto",
    "cl_nome","cl_cognome","cl_luogo","cl_data_nascita","cl_indirizzo","cl_cf",
    "cl_doc","cl_doc_da","cl_doc_dt","cl_pat","cl_cat","cl_pat_r","cl_pat_s",
    "soc_nome","soc_sede","soc_cf","soc_piva",
    "gu_nome","gu_cognome","gu_luogo","gu_data_nascita","gu_indirizzo","gu_cf",
    "gu_doc","gu_doc_da","gu_doc_dt","gu_pat","gu_cat","gu_pat_r","gu_pat_s",
    "ex_nome","ex_cognome","ex_luogo","ex_data_nascita","ex_indirizzo","ex_cf",
    "ex_doc","ex_doc_da","ex_doc_dt","ex_pat","ex_cat","ex_pat_r","ex_pat_s",
    "marca_modello","targa","telaio","cilindrata","alimentazione","anno","colore","km_iniziali",
    "data_inizio","ora_inizio","data_fine","ora_fine","giorni",
    "prezzo_noleggio","km_compresi","deposito","km_extra","penale",
    "costo_violazione","diff_carburante","riconsegna_premium",
    "contratto_path","note",
]

@app.get("/api/noleggi")
def list_noleggi(request: Request, q:Optional[str]=None, nome:Optional[str]=None,
    auto:Optional[str]=None, da:Optional[str]=None, a:Optional[str]=None,
    prezzo_min:Optional[float]=None, prezzo_max:Optional[float]=None,
    stato:Optional[str]=None, p=Depends(verify_token)):
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor()
        sql = "SELECT * FROM noleggi WHERE 1=1"; params = []
        if q:
            sql += " AND (nome_cognome ILIKE %s OR marca_modello ILIKE %s OR targa ILIKE %s)"
            params += [f"%{q}%"]*3
        if nome: sql += " AND nome_cognome ILIKE %s"; params.append(f"%{nome}%")
        if auto:
            sql += " AND (marca_modello ILIKE %s OR targa ILIKE %s)"
            params += [f"%{auto}%"]*2
        if da:
            sql += " AND TO_DATE(NULLIF(data_inizio,''),'DD/MM/YYYY') >= TO_DATE(%s,'DD/MM/YYYY')"
            params.append(da)
        if a:
            sql += " AND TO_DATE(NULLIF(data_inizio,''),'DD/MM/YYYY') <= TO_DATE(%s,'DD/MM/YYYY')"
            params.append(a)
        if prezzo_min is not None:
            sql += " AND NULLIF(prezzo_noleggio,'')::numeric >= %s"; params.append(prezzo_min)
        if prezzo_max is not None:
            sql += " AND NULLIF(prezzo_noleggio,'')::numeric <= %s"; params.append(prezzo_max)
        if stato and stato != "tutti":
            if stato == "attesa": sql += " AND (verbale_stato ILIKE '%attesa%' OR verbale_stato='')"
            elif stato == "ok":   sql += " AND verbale_stato ILIKE '%OK%'"
            elif stato == "danno": sql += " AND verbale_stato ILIKE '%Danno%'"
        cur.execute(sql + " ORDER BY id DESC", params)
        return cur.fetchall()

@app.get("/api/noleggi/{id}")
def get_noleggio(id:int, request:Request, p=Depends(verify_token)):
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor(); cur.execute("SELECT * FROM noleggi WHERE id=%s",(id,))
        row = cur.fetchone()
        if not row: raise HTTPException(404,"Non trovato")
        return row

@app.post("/api/noleggi", status_code=201)
def create_noleggio(data: NoleggioIn, request:Request, p=Depends(verify_token)):
    rate_limit(get_ip(request))
    vals = [getattr(data, c) for c in NOLEGGIO_COLS]
    cols_sql = ",".join(NOLEGGIO_COLS)
    ph = ",".join(["%s"]*len(NOLEGGIO_COLS))
    with db() as conn:
        cur = conn.cursor()
        cur.execute(f"INSERT INTO noleggi ({cols_sql}) VALUES ({ph}) RETURNING id", vals)
        return {"id": cur.fetchone()["id"]}

@app.put("/api/noleggi/{id}")
def update_noleggio(id:int, data:NoleggioIn, request:Request, p=Depends(admin_only)):
    rate_limit(get_ip(request))
    update_cols = [c for c in NOLEGGIO_COLS if c != "data_contratto"]
    set_sql = ",".join(f"{c}=%s" for c in update_cols) + ",updated_at=NOW()"
    vals = [getattr(data, c) for c in update_cols] + [id]
    with db() as conn:
        conn.cursor().execute(f"UPDATE noleggi SET {set_sql} WHERE id=%s", vals)
        return {"ok": True}

@app.delete("/api/noleggi/{id}")
def delete_noleggio(id:int, request:Request, p=Depends(admin_only)):
    rate_limit(get_ip(request))
    with db() as conn:
        conn.cursor().execute("DELETE FROM noleggi WHERE id=%s",(id,))
        return {"ok": True}

# ── VERBALI ───────────────────────────────────────────────────
class VerbaleIn(BaseModel):
    noleggio_id:int; data:str; ora:str; targa:str
    km_iniziali:str; km_attuali:str; carburante:str
    tipo_riconsegna:str; pulizia:str; pulizia_premium:str
    oggetti:str; oggetti_desc:Optional[str]=""
    danno:str; tipo_danno:Optional[str]=""
    posizione_danno:Optional[str]=""; costo_danno:Optional[str]=""
    descrizione:Optional[str]=""; operatore:str; stato:str

@app.post("/api/verbali", status_code=201)
def create_verbale(data:VerbaleIn, request:Request, p=Depends(verify_token)):
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""INSERT INTO verbali
          (noleggio_id,data,ora,targa,km_iniziali,km_attuali,carburante,
           tipo_riconsegna,pulizia,pulizia_premium,oggetti,oggetti_desc,
           danno,tipo_danno,posizione_danno,costo_danno,descrizione,operatore,stato)
          VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
          (data.noleggio_id,data.data,data.ora,data.targa,data.km_iniziali,
           data.km_attuali,data.carburante,data.tipo_riconsegna,data.pulizia,
           data.pulizia_premium,data.oggetti,data.oggetti_desc,data.danno,
           data.tipo_danno,data.posizione_danno,data.costo_danno,
           data.descrizione,data.operatore,data.stato))
        vid = cur.fetchone()["id"]
        cur.execute("UPDATE noleggi SET verbale_stato=%s,updated_at=NOW() WHERE id=%s",
                    (data.stato,data.noleggio_id))
        try:
            km_new = int(float(data.km_attuali.replace(",","")))
            cur.execute("UPDATE auto SET km=%s,updated_at=NOW() WHERE targa=%s",(km_new,data.targa))
        except: pass
        return {"id":vid}

@app.get("/api/verbali/pending")
def pending_verbali(request:Request, p=Depends(verify_token)):
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""SELECT id,nome_cognome,marca_modello,targa,data_inizio,km_iniziali
          FROM noleggi WHERE verbale_stato ILIKE '%attesa%' OR verbale_stato=''
          ORDER BY id DESC""")
        return cur.fetchall()

# ── AUTO ──────────────────────────────────────────────────────
class AutoIn(BaseModel):
    marca_modello:str; targa:str
    telaio:Optional[str]=""; cilindrata:Optional[str]=""
    alimentazione:Optional[str]=""; anno:Optional[str]=""
    colore:Optional[str]=""; km:Optional[int]=0

@app.get("/api/auto")
def list_auto(request:Request, p=Depends(verify_token)):
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor(); cur.execute("SELECT * FROM auto ORDER BY marca_modello")
        return cur.fetchall()

@app.post("/api/auto", status_code=201)
def create_auto(data:AutoIn, request:Request, p=Depends(admin_only)):
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""INSERT INTO auto(marca_modello,targa,telaio,cilindrata,alimentazione,anno,colore,km)
          VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
          ON CONFLICT(targa) DO UPDATE SET marca_modello=EXCLUDED.marca_modello,
          km=EXCLUDED.km,updated_at=NOW() RETURNING id""",
          (data.marca_modello,data.targa,data.telaio,data.cilindrata,
           data.alimentazione,data.anno,data.colore,data.km))
        return {"id":cur.fetchone()["id"]}

# ── LOGS ──────────────────────────────────────────────────────
@app.get("/api/logs")
def get_logs(request:Request, p=Depends(admin_only)):
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id,
                   TO_CHAR(ts AT TIME ZONE 'Europe/Rome', 'DD/MM/YYYY HH24:MI:SS') AS ts,
                   username, role, success, ip, hostname, os_info, machine
            FROM access_log
            ORDER BY id DESC LIMIT 200
        """)
        rows = cur.fetchall()
        return [dict(r) for r in rows]


# ── CONTRATTO PDF ─────────────────────────────────────────────
@app.get("/api/noleggi/{id}/contratto")
def genera_contratto(id: int, request: Request, token: str = None, p=None):
    # Accept token as query param for browser direct download
    from fastapi.security.utils import get_authorization_scheme_param
    if token:
        try:
            p = verify_token(token)
        except:
            raise HTTPException(401, "Token non valido")
    else:
        auth = request.headers.get("Authorization","")
        _, tok = get_authorization_scheme_param(auth)
        p = verify_token(tok) if tok else None
    if not p:
        raise HTTPException(401, "Non autorizzato")
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM noleggi WHERE id=%s", (id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Noleggio non trovato")

    # Build context mapping all template placeholders to DB fields
    def v(val):
        if val is None or str(val).strip() in ("", "nan"): return "—"
        return str(val)

    ctx = {
        "cliente_nome_cognome":                         v(r["cl_nome"]) + " " + v(r["cl_cognome"]),
        "cliente_luogo_nascita":                        v(r["cl_luogo"]),
        "cliente_data_nascita":                         v(r["cl_data_nascita"]),
        "cliente_indirizzo_residenza":                  v(r["cl_indirizzo"]),
        "cliente_codice_fiscale":                       v(r["cl_cf"]),
        "cliente_numero_documento":                     v(r["cl_doc"]),
        "cliente_documento_rilasciato_da":              v(r["cl_doc_da"]),
        "cliente_documento_data_rilascio":              v(r["cl_doc_dt"]),
        "cliente_numero_patente":                       v(r["cl_pat"]),
        "cliente_categoria_patente":                    v(r["cl_cat"]),
        "cliente_patente_data_rilascio":                v(r["cl_pat_r"]),
        "cliente_patente_scadenza":                     v(r["cl_pat_s"]),
        "societa_nome":                                 v(r["soc_nome"]),
        "societa_sede":                                 v(r["soc_sede"]),
        "societa_codice_fiscale":                       v(r["soc_cf"]),
        "societa_partita_iva":                          v(r["soc_piva"]),
        "guidatore_nome_cognome":                       v(r["gu_nome"]) + " " + v(r["gu_cognome"]),
        "guidatore_luogo_nascita":                      v(r["gu_luogo"]),
        "guidatore_data_nascita":                       v(r["gu_data_nascita"]),
        "guidatore_indirizzo_residenza":                v(r["gu_indirizzo"]),
        "guidatore_codice_fiscale":                     v(r["gu_cf"]),
        "guidatore_numero_documento":                   v(r["gu_doc"]),
        "guidatore_documento_rilasciato_da":            v(r["gu_doc_da"]),
        "guidatore_documento_data_rilascio":            v(r["gu_doc_dt"]),
        "guidatore_numero_patente":                     v(r["gu_pat"]),
        "guidatore_categoria_patente":                  v(r["gu_cat"]),
        "guidatore_patente_data_rilascio":              v(r["gu_pat_r"]),
        "guidatore_patente_scadenza":                   v(r["gu_pat_s"]),
        "conducente_aggiuntivo_nome_cognome":           v(r["ex_nome"]) + " " + v(r["ex_cognome"]),
        "conducente_aggiuntivo_luogo_nascita":          v(r["ex_luogo"]),
        "conducente_aggiuntivo_data_nascita":           v(r["ex_data_nascita"]),
        "conducente_aggiuntivo_indirizzo_residenza":    v(r["ex_indirizzo"]),
        "conducente_aggiuntivo_codice_fiscale":         v(r["ex_cf"]),
        "conducente_aggiuntivo_numero_documento":       v(r["ex_doc"]),
        "conducente_aggiuntivo_documento_rilasciato_da": v(r["ex_doc_da"]),
        "conducente_aggiuntivo_documento_data_rilascio": v(r["ex_doc_dt"]),
        "conducente_aggiuntivo_numero_patente":         v(r["ex_pat"]),
        "conducente_aggiuntivo_categoria_patente":      v(r["ex_cat"]),
        "conducente_aggiuntivo_patente_data_rilascio":  v(r["ex_pat_r"]),
        "conducente_aggiuntivo_patente_scadenza":       v(r["ex_pat_s"]),
        "marca_modello":        v(r["marca_modello"]),
        "targa":                v(r["targa"]),
        "telaio":               v(r["telaio"]),
        "cilindrata":           v(r["cilindrata"]),
        "alimentazione":        v(r["alimentazione"]),
        "anno":                 v(r["anno"]),
        "colore":               v(r["colore"]),
        "km":                   v(r["km_iniziali"]),
        "data_inizio":          v(r["data_inizio"]),
        "ora_inizio":           v(r["ora_inizio"]),
        "data_fine":            v(r["data_fine"]),
        "ora_fine":             v(r["ora_fine"]),
        "prezzo_noleggio":      v(r["prezzo_noleggio"]),
        "km_compresi":          v(r["km_compresi"]),
        "km_extra":             v(r["km_extra"]),
        "riconsegna_premium":   v(r["riconsegna_premium"]),
        "penale":               v(r["penale"]),
        "deposito":             v(r["deposito"]),
        "costo_violazione":     v(r["costo_violazione"]),
        "diff_carburante":      v(r["diff_carburante"]),
        "firma_data":           v(r["data_contratto"]),
    }

    # Load template and fill placeholders
    import os
    template_path = os.path.join(os.path.dirname(__file__), "..", "template", "contratto_template.docx")
    if not os.path.exists(template_path):
        raise HTTPException(500, "Template contratto non trovato sul server. Carica contratto_template.docx in backend/template/")

    doc = DocxDocument(template_path)

    def fill_para(para):
        for key, val in ctx.items():
            placeholder = "{{" + key + "}}"
            if placeholder in para.text:
                for run in para.runs:
                    if placeholder in run.text:
                        run.text = run.text.replace(placeholder, val)
                # If placeholder spans multiple runs, rebuild
                if placeholder in para.text:
                    full = "".join(r.text for r in para.runs)
                    full = full.replace(placeholder, val)
                    for i, run in enumerate(para.runs):
                        run.text = full if i == 0 else ""

    for para in doc.paragraphs:
        fill_para(para)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    fill_para(para)

    # Save to bytes and return as download
    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)

    nome = f"contratto_{r['cl_nome']}_{r['cl_cognome']}_{r['data_contratto'] or 'FTO'}.docx".replace("/", "-").replace(" ", "_")

    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f"attachment; filename={nome}"}
    )


# ── GENERA CONTRATTO PDF ──────────────────────────────────────
from fastapi.responses import StreamingResponse
import io
from datetime import datetime as dt

@app.get("/api/contratto/{id}")
def genera_contratto_v2(id: int, request: Request, token: str = None):
    from fastapi.security.utils import get_authorization_scheme_param
    if token:
        try:
            p = verify_token(token)
        except:
            raise HTTPException(401, "Token non valido")
    else:
        auth = request.headers.get("Authorization","")
        _, tok = get_authorization_scheme_param(auth)
        try: p = verify_token(tok) if tok else None
        except: raise HTTPException(401, "Non autorizzato")
    if not p:
        raise HTTPException(401, "Non autorizzato")
    rate_limit(get_ip(request))
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM noleggi WHERE id=%s", (id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Noleggio non trovato")

    # Build PDF
    buf = io.BytesIO()
    _build_pdf(buf, dict(r))
    buf.seek(0)

    nome = f"contratto_{r['cl_nome']}_{r['cl_cognome']}_{id}.pdf"
    return StreamingResponse(buf, media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={nome}"})


def _v(r, key, default="____________"):
    """Get value from record, return default if empty."""
    v = r.get(key, "") or ""
    if str(v).strip() in ("", "nan", "—", "-"):
        return default
    return str(v).strip()


def _build_pdf(buf, r):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT

    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm, bottomMargin=18*mm)

    W = A4[0] - 40*mm
    styles = getSampleStyleSheet()

    def style(name, **kwargs):
        s = ParagraphStyle(name, parent=styles['Normal'], **kwargs)
        return s

    S_TITLE  = style('title',  fontSize=11, fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=4)
    S_SUB    = style('sub',    fontSize=9,  fontName='Helvetica',      alignment=TA_CENTER, spaceAfter=2, textColor=colors.HexColor('#444444'))
    S_HEAD   = style('head',   fontSize=9,  fontName='Helvetica-Bold', spaceBefore=8, spaceAfter=3)
    S_BODY   = style('body',   fontSize=8,  fontName='Helvetica',      leading=12, alignment=TA_JUSTIFY, spaceAfter=4)
    S_FIELD  = style('field',  fontSize=8,  fontName='Helvetica',      leading=12, spaceAfter=2)
    S_SIGN   = style('sign',   fontSize=8,  fontName='Helvetica',      spaceBefore=6, spaceAfter=2)
    S_BOLD   = style('bold',   fontSize=8,  fontName='Helvetica-Bold', spaceAfter=2)

    story = []

    def H(txt): story.append(Paragraph(txt, S_HEAD))
    def P(txt): story.append(Paragraph(txt, S_BODY))
    def F(txt): story.append(Paragraph(txt, S_FIELD))
    def SP(n=4): story.append(Spacer(1, n*mm))
    def HR(): story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=4, spaceBefore=4))

    # ── INTESTAZIONE ──
    story.append(Paragraph("CONTRATTO DI NOLEGGIO A BREVE TERMINE DI AUTOVETTURA SENZA CONDUCENTE", S_TITLE))
    story.append(Paragraph("da valere ai sensi e per gli effetti di legge", S_SUB))
    HR()

    # Parti
    story.append(Paragraph("<b>tra</b>", S_BODY))
    P("FTO Rent S.r.l. (Partita IVA 14550780960) con sede legale in Lacchiarella (MI), Via Milite Ignoto n. 5, CAP 20084, nella persona del legale rappresentante pro tempore <b>Sig. Christian Arbi Karim</b>, di seguito denominata <b>\"Locatore\"</b>")
    story.append(Paragraph("<b>e</b>", S_BODY))

    P(f"Il Sig./La Sig.ra <b>{_v(r,'cl_nome')} {_v(r,'cl_cognome')}</b>, nato/a a {_v(r,'cl_luogo')} il {_v(r,'cl_data_nascita')}, residente in {_v(r,'cl_indirizzo')}, codice fiscale {_v(r,'cl_cf')}, documento d'identità n. {_v(r,'cl_doc')} rilasciato da {_v(r,'cl_doc_da')} in data {_v(r,'cl_doc_dt')}, patente di guida n. {_v(r,'cl_pat')} cat. {_v(r,'cl_cat')} rilasciata in data {_v(r,'cl_pat_r')}, con scadenza {_v(r,'cl_pat_s')}, in proprio quale persona fisica in qualità di legale rappresentante della società {_v(r,'soc_nome','—')} con sede in {_v(r,'soc_sede','—')} C.F. {_v(r,'soc_cf','—')} P.IVA {_v(r,'soc_piva','—')}, di seguito denominato/a <b>\"Cliente\"</b>")

    gu_nome = f"{_v(r,'gu_nome','')} {_v(r,'gu_cognome','')}".strip()
    if gu_nome and gu_nome != r.get('cl_nome','') + ' ' + r.get('cl_cognome',''):
        P(f"Il Sig./La Sig.ra <b>{gu_nome}</b>, nato/a a {_v(r,'gu_luogo')} il {_v(r,'gu_data_nascita')}, residente in {_v(r,'gu_indirizzo')}, codice fiscale {_v(r,'gu_cf')}, documento d'identità n. {_v(r,'gu_doc')} rilasciato da {_v(r,'gu_doc_da')} in data {_v(r,'gu_doc_dt')}, patente di guida n. {_v(r,'gu_pat')} cat. {_v(r,'gu_cat')} rilasciata in data {_v(r,'gu_pat_r')}, con scadenza {_v(r,'gu_pat_s')}, di seguito denominato/a <b>\"Guidatore\"</b>")

    ex_nome = f"{_v(r,'ex_nome','')} {_v(r,'ex_cognome','')}".strip()
    if ex_nome and ex_nome not in ('', '— —', '____________ ____________'):
        P(f"Il Sig./La Sig.ra <b>{ex_nome}</b>, nato/a a {_v(r,'ex_luogo')} il {_v(r,'ex_data_nascita')}, residente in {_v(r,'ex_indirizzo')}, codice fiscale {_v(r,'ex_cf')}, documento d'identità n. {_v(r,'ex_doc')} rilasciato da {_v(r,'ex_doc_da')} in data {_v(r,'ex_doc_dt')}, patente di guida n. {_v(r,'ex_pat')} cat. {_v(r,'ex_cat')} rilasciata in data {_v(r,'ex_pat_r')}, con scadenza {_v(r,'ex_pat_s')}, di seguito denominato/a <b>\"Conducente aggiuntivo\"</b>")

    HR()

    # ── ART. 1 — OGGETTO ──
    H("Art. 1 — Oggetto del Contratto")
    P("La società noleggiante concede in noleggio al Cliente come sopra identificato, che accetta, l'autovettura di seguito descritta:")
    SP(2)

    data_auto = [
        ["Marca e modello:", _v(r,'marca_modello'), "Targa:", _v(r,'targa')],
        ["Numero telaio:", _v(r,'telaio'), "Cilindrata:", _v(r,'cilindrata')],
        ["Alimentazione:", _v(r,'alimentazione'), "Anno:", _v(r,'anno')],
        ["Colore:", _v(r,'colore'), "Km alla consegna:", _v(r,'km_iniziali')],
    ]
    t = Table(data_auto, colWidths=[35*mm, 50*mm, 35*mm, 50*mm])
    t.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f8f8')),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#dddddd')),
    ]))
    story.append(t)
    SP(3)

    # ── ART. 2 — STATO AUTOVETTURA (condensed) ──
    H("Art. 2 — Stato dell'Autovettura")
    P("Il veicolo viene consegnato al Cliente in perfetto stato di funzionamento, manutenzione e pulizia, con il serbatoio pieno e con tutti i documenti previsti dalla legge. Il veicolo è dotato di sistema GPS; il Cliente ne autorizza l'uso per finalità di tutela e recupero del veicolo.")

    # ── ART. 3 — COPERTURE ──
    H("Art. 3 — Coperture Assicurative")
    P("RCA massimale €10.000.000; Incendio e furto (scoperto 20%, min. €400); KASKO (scoperto 25%, min. €1.500).")

    # ── ART. 4 — DURATA ──
    H("Art. 4 — Durata del Noleggio")
    P(f"Il noleggio inizia il <b>{_v(r,'data_inizio')}</b> alle ore <b>{_v(r,'ora_inizio')}</b> e termina il <b>{_v(r,'data_fine')}</b> alle ore <b>{_v(r,'ora_fine')}</b>. Il veicolo dovrà essere riconsegnato presso la sede operativa in Sesto San Giovanni (MI), Piazza Indro Montanelli n. 20.")
    P(f"In caso di riconsegna in altro luogo: costo aggiuntivo di Euro <b>{_v(r,'riconsegna_premium')}</b>. In caso di ritardo: penale di Euro <b>{_v(r,'penale')}</b> per ogni giorno di ritardo.")

    # ── ART. 5 — KM ──
    H("Art. 5 — Limitazione di Chilometraggio")
    P(f"L'utilizzo è limitato a <b>{_v(r,'km_compresi')}</b> km inclusi. In caso di eccedenza: Euro <b>{_v(r,'km_extra')}</b> per ogni km eccedente.")

    # ── ART. 6 — TERRITORIO ──
    H("Art. 6 — Limitazioni Territoriali")
    P("L'utilizzo è consentito nell'Unione Europea. Qualsiasi espatrio richiede autorizzazione scritta del Locatore.")

    # ── ART. 7 — CORRISPETTIVO ──
    H("Art. 7 — Corrispettivo e Modalità di Pagamento")
    P(f"Corrispettivo per il noleggio: Euro <b>{_v(r,'prezzo_noleggio')}</b>, comprensivo di <b>{_v(r,'km_compresi')}</b> km.")
    P(f"Deposito cauzionale: Euro <b>{_v(r,'deposito')}</b>, restituibile entro 30 giorni dalla riconsegna previa verifica.")
    P("Pagamento mediante bonifico istantaneo IBAN: <b>IT34W0306909530100000062828</b> intestato a FTO Rent S.r.l., contestualmente alla firma.")

    # ── ART. 11 — RESP CLIENTE ──
    H("Art. 11 — Responsabilità del Cliente")
    P(f"In caso di violazione delle norme stradali con sequestro del veicolo: importo forfettario di Euro <b>{_v(r,'costo_violazione')}</b> per danni da fermo veicolo.")

    # ── ART. 17 — RICONSEGNA ──
    H("Art. 17 — Riconsegna e Verifiche")
    P(f"In caso di differenza nel livello carburante rispetto alla consegna: tariffa di Euro <b>{_v(r,'diff_carburante')}</b> per il servizio \"Pieno\".")

    # ── DISPOSIZIONI FINALI ──
    H("Disposizioni Finali")
    P("Il presente contratto è disciplinato dalla legge italiana. Foro competente: Tribunale di Milano. Il Cliente dichiara di aver letto attentamente il contratto e di accettarne integralmente le condizioni.")

    HR()

    # ── FIRME ──
    firma_data = r.get('data_contratto') or dt.today().strftime('%d/%m/%Y')
    story.append(Paragraph(f"Lacchiarella (MI), lì <b>{firma_data}</b>", S_SIGN))
    SP(3)

    data_firme = [
        ["Il Locatore", "Il Cliente", "Il Guidatore (se diverso)"],
        ["FTO Rent S.r.l.\nSig. Christian Arbi Karim", "__________________________", "__________________________"],
    ]
    t2 = Table(data_firme, colWidths=[W/3]*3)
    t2.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTNAME', (0,1), (-1,1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LINEBELOW', (0,1), (-1,1), 0.5, colors.HexColor('#999999')),
    ]))
    story.append(t2)
    SP(4)

    if ex_nome and ex_nome not in ('', '— —'):
        story.append(Paragraph("Il Conducente Aggiuntivo", S_SIGN))
        story.append(Paragraph("__________________________", S_SIGN))
        SP(3)

    HR()
    # Clausole vessatorie
    story.append(Paragraph("<b>Approvazione Specifica delle Clausole</b> (artt. 1341-1342 c.c.)", S_BOLD))
    P("Il Cliente approva specificamente: Art. 2 Stato autovettura; Art. 4 Durata noleggio; Art. 5 Chilometraggio; Art. 6 Limitazioni territoriali; Art. 7 Corrispettivo; Art. 10 Obblighi cliente; Art. 11 Responsabilità; Art. 12 Solidarietà; Art. 14 Sinistri; Art. 16 Furto; Art. 17 Riconsegna; Art. 19 Risoluzione; Art. 20 Recesso; Art. 24 Foro competente.")
    story.append(Paragraph(f"Lacchiarella (MI), lì <b>{firma_data}</b>", S_SIGN))
    story.append(Paragraph("Firma del Cliente: __________________________", S_SIGN))

    HR()
    story.append(Paragraph("<b>Consenso al Trattamento dei Dati Personali</b> (GDPR - Reg. UE 2016/679)", S_BOLD))
    P("Il sottoscritto dichiara di aver ricevuto l'informativa sul trattamento dei dati personali e presta il proprio consenso al trattamento per le finalità indicate, ivi compresa la geolocalizzazione del veicolo.")
    story.append(Paragraph(f"Lacchiarella (MI), lì <b>{firma_data}</b>", S_SIGN))
    story.append(Paragraph("Firma del Cliente: __________________________", S_SIGN))

    doc.build(story)
