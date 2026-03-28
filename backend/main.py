"""
FTO Gestionale Noleggio — FastAPI Backend
Tutti i dati su PostgreSQL (Supabase), auth JWT, API REST completa.
"""
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from datetime import datetime, timedelta
from typing import Optional, List
import os, hashlib, json, platform, uuid
from jose import JWTError, jwt
from pydantic import BaseModel
import psycopg2
import psycopg2.extras
from contextlib import contextmanager

# ─────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("SECRET_KEY", "fto-secret-change-in-prod-2025")
ALGORITHM   = "HS256"
TOKEN_EXPIRE_HOURS = 12
DATABASE_URL = os.getenv("DATABASE_URL", "")  # set on Railway

# Users (passwords as SHA-256)
def _h(pw): return hashlib.sha256(pw.encode()).hexdigest()

USERS = {
    "ak":       {"hash": _h("ak47ven"),   "role": "admin",    "display": "Ak"},
    "toad":     {"hash": _h("caramello"), "role": "admin",    "display": "Toad"},
    "fuma":     {"hash": _h("Alex2001$"), "role": "admin",    "display": "Fuma"},
    "utente 1": {"hash": _h("ftorent$"),  "role": "employee", "display": "Utente 1"},
}

# ─────────────────────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Create tables if they don't exist."""
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS noleggi (
            id              SERIAL PRIMARY KEY,
            data_contratto  TEXT,
            nome_cognome    TEXT,
            marca_modello   TEXT,
            targa           TEXT,
            telaio          TEXT,
            cilindrata      TEXT,
            alimentazione   TEXT,
            anno            TEXT,
            colore          TEXT,
            km_iniziali     TEXT,
            data_inizio     TEXT,
            ora_inizio      TEXT,
            data_fine       TEXT,
            ora_fine        TEXT,
            giorni          TEXT,
            prezzo_noleggio TEXT,
            km_compresi     TEXT,
            deposito        TEXT,
            km_extra        TEXT,
            penale          TEXT,
            costo_violazione TEXT,
            diff_carburante TEXT,
            riconsegna_premium TEXT,
            contratto_path  TEXT,
            verbale_stato   TEXT DEFAULT '⏳ In attesa',
            verbale_path    TEXT DEFAULT '',
            note            TEXT DEFAULT '',
            created_at      TIMESTAMPTZ DEFAULT NOW(),
            updated_at      TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS verbali (
            id              SERIAL PRIMARY KEY,
            noleggio_id     INTEGER REFERENCES noleggi(id) ON DELETE SET NULL,
            data            TEXT,
            ora             TEXT,
            targa           TEXT,
            km_iniziali     TEXT,
            km_attuali      TEXT,
            carburante      TEXT,
            tipo_riconsegna TEXT,
            pulizia         TEXT,
            pulizia_premium TEXT,
            oggetti         TEXT,
            oggetti_desc    TEXT,
            danno           TEXT,
            tipo_danno      TEXT,
            posizione_danno TEXT,
            costo_danno     TEXT,
            descrizione     TEXT,
            operatore       TEXT,
            stato           TEXT,
            cartella        TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS auto (
            id            SERIAL PRIMARY KEY,
            marca_modello TEXT,
            targa         TEXT UNIQUE,
            telaio        TEXT,
            cilindrata    TEXT,
            alimentazione TEXT,
            anno          TEXT,
            colore        TEXT,
            km            INTEGER DEFAULT 0,
            updated_at    TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS access_log (
            id        SERIAL PRIMARY KEY,
            ts        TIMESTAMPTZ DEFAULT NOW(),
            username  TEXT,
            role      TEXT,
            success   BOOLEAN,
            ip        TEXT,
            hostname  TEXT,
            os_info   TEXT,
            machine   TEXT
        );
        """)
        print("[DB] Tables ready")

# ─────────────────────────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def create_token(data: dict):
    exp = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode({**data, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None: raise HTTPException(status_code=401, detail="Token non valido")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token scaduto o non valido")

def admin_only(payload=Depends(verify_token)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Solo gli amministratori possono eseguire questa azione")
    return payload

# ─────────────────────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────────────────────
app = FastAPI(title="FTO Gestionale", version="3.0")

app.add_middleware(CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True)

@app.on_event("startup")
def startup():
    try:
        init_db()
    except Exception as e:
        print(f"[WARN] DB init: {e}")

# Serve frontend
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(os.path.join(frontend_path, "static")):
    app.mount("/static", StaticFiles(directory=os.path.join(frontend_path, "static")), name="static")

@app.get("/")
def root():
    idx = os.path.join(frontend_path, "templates", "index.html")
    if os.path.exists(idx):
        return FileResponse(idx)
    return {"status": "FTO API running"}

# ─────────────────────────────────────────────────────────────
#  AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str
    ip: Optional[str] = "N/A"
    hostname: Optional[str] = "N/A"

@app.post("/api/auth/login")
def login(req: LoginRequest):
    username = req.username.strip().lower()
    user = USERS.get(username)
    success = user is not None and user["hash"] == _h(req.password)

    # Log the attempt
    try:
        with db() as conn:
            conn.cursor().execute(
                "INSERT INTO access_log (username, role, success, ip, hostname, os_info, machine) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (username, user["role"] if user else "unknown", success,
                 req.ip, req.hostname, platform.system(), platform.machine()))
    except Exception as e:
        print(f"[WARN] log: {e}")

    if not success:
        raise HTTPException(status_code=401, detail="Username o password errati")

    token = create_token({"sub": username, "role": user["role"], "display": user["display"]})
    return {"access_token": token, "token_type": "bearer",
            "display": user["display"], "role": user["role"]}

@app.get("/api/auth/me")
def me(payload=Depends(verify_token)):
    return {"username": payload["sub"], "display": payload["display"], "role": payload["role"]}

# ─────────────────────────────────────────────────────────────
#  NOLEGGI ENDPOINTS
# ─────────────────────────────────────────────────────────────
class NoleggioCreate(BaseModel):
    data_contratto: Optional[str] = ""
    nome_cognome: Optional[str] = ""
    marca_modello: Optional[str] = ""
    targa: Optional[str] = ""
    telaio: Optional[str] = ""
    cilindrata: Optional[str] = ""
    alimentazione: Optional[str] = ""
    anno: Optional[str] = ""
    colore: Optional[str] = ""
    km_iniziali: Optional[str] = ""
    data_inizio: Optional[str] = ""
    ora_inizio: Optional[str] = ""
    data_fine: Optional[str] = ""
    ora_fine: Optional[str] = ""
    giorni: Optional[str] = ""
    prezzo_noleggio: Optional[str] = ""
    km_compresi: Optional[str] = ""
    deposito: Optional[str] = ""
    km_extra: Optional[str] = ""
    penale: Optional[str] = ""
    costo_violazione: Optional[str] = ""
    diff_carburante: Optional[str] = ""
    riconsegna_premium: Optional[str] = ""
    contratto_path: Optional[str] = ""
    note: Optional[str] = ""

class NoleggioUpdate(NoleggioCreate):
    pass

@app.get("/api/noleggi")
def list_noleggi(
    q: Optional[str] = None,
    nome: Optional[str] = None,
    auto: Optional[str] = None,
    da: Optional[str] = None,
    a: Optional[str] = None,
    prezzo_min: Optional[float] = None,
    prezzo_max: Optional[float] = None,
    stato: Optional[str] = None,
    payload=Depends(verify_token)
):
    with db() as conn:
        cur = conn.cursor()
        sql = "SELECT * FROM noleggi WHERE 1=1"
        params = []

        if q:
            sql += " AND (nome_cognome ILIKE %s OR marca_modello ILIKE %s OR targa ILIKE %s)"
            params += [f"%{q}%", f"%{q}%", f"%{q}%"]
        if nome:
            sql += " AND nome_cognome ILIKE %s"
            params.append(f"%{nome}%")
        if auto:
            sql += " AND (marca_modello ILIKE %s OR targa ILIKE %s)"
            params += [f"%{auto}%", f"%{auto}%"]
        if da:
            # Filter: data_inizio >= da (compare as text DD/MM/YYYY → convert)
            sql += " AND TO_DATE(NULLIF(data_inizio,''), 'DD/MM/YYYY') >= TO_DATE(%s, 'DD/MM/YYYY')"
            params.append(da)
        if a:
            sql += " AND TO_DATE(NULLIF(data_inizio,''), 'DD/MM/YYYY') <= TO_DATE(%s, 'DD/MM/YYYY')"
            params.append(a)
        if prezzo_min is not None:
            sql += " AND NULLIF(prezzo_noleggio,'')::numeric >= %s"
            params.append(prezzo_min)
        if prezzo_max is not None:
            sql += " AND NULLIF(prezzo_noleggio,'')::numeric <= %s"
            params.append(prezzo_max)
        if stato and stato != "tutti":
            if stato == "attesa":
                sql += " AND (verbale_stato ILIKE '%attesa%' OR verbale_stato IS NULL OR verbale_stato='')"
            elif stato == "ok":
                sql += " AND verbale_stato ILIKE '%OK%'"
            elif stato == "danno":
                sql += " AND verbale_stato ILIKE '%Danno%'"

        sql += " ORDER BY id DESC"
        cur.execute(sql, params)
        return cur.fetchall()

@app.get("/api/noleggi/{id}")
def get_noleggio(id: int, payload=Depends(verify_token)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM noleggi WHERE id=%s", (id,))
        row = cur.fetchone()
        if not row: raise HTTPException(404, "Noleggio non trovato")
        return row

@app.post("/api/noleggi", status_code=201)
def create_noleggio(data: NoleggioCreate, payload=Depends(verify_token)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO noleggi
          (data_contratto,nome_cognome,marca_modello,targa,telaio,cilindrata,
           alimentazione,anno,colore,km_iniziali,data_inizio,ora_inizio,
           data_fine,ora_fine,giorni,prezzo_noleggio,km_compresi,deposito,
           km_extra,penale,costo_violazione,diff_carburante,riconsegna_premium,
           contratto_path,note,verbale_stato,verbale_path)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'⏳ In attesa','')
        RETURNING id
        """, (data.data_contratto, data.nome_cognome, data.marca_modello,
              data.targa, data.telaio, data.cilindrata, data.alimentazione,
              data.anno, data.colore, data.km_iniziali, data.data_inizio,
              data.ora_inizio, data.data_fine, data.ora_fine, data.giorni,
              data.prezzo_noleggio, data.km_compresi, data.deposito,
              data.km_extra, data.penale, data.costo_violazione,
              data.diff_carburante, data.riconsegna_premium,
              data.contratto_path, data.note))
        return {"id": cur.fetchone()["id"]}

@app.put("/api/noleggi/{id}")
def update_noleggio(id: int, data: NoleggioUpdate, payload=Depends(admin_only)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
        UPDATE noleggi SET
          nome_cognome=%s,marca_modello=%s,targa=%s,telaio=%s,cilindrata=%s,
          alimentazione=%s,anno=%s,colore=%s,km_iniziali=%s,data_inizio=%s,
          ora_inizio=%s,data_fine=%s,ora_fine=%s,giorni=%s,prezzo_noleggio=%s,
          km_compresi=%s,deposito=%s,km_extra=%s,penale=%s,costo_violazione=%s,
          diff_carburante=%s,riconsegna_premium=%s,note=%s,updated_at=NOW()
        WHERE id=%s
        """, (data.nome_cognome, data.marca_modello, data.targa, data.telaio,
              data.cilindrata, data.alimentazione, data.anno, data.colore,
              data.km_iniziali, data.data_inizio, data.ora_inizio, data.data_fine,
              data.ora_fine, data.giorni, data.prezzo_noleggio, data.km_compresi,
              data.deposito, data.km_extra, data.penale, data.costo_violazione,
              data.diff_carburante, data.riconsegna_premium, data.note, id))
        return {"ok": True}

@app.delete("/api/noleggi/{id}")
def delete_noleggio(id: int, payload=Depends(admin_only)):
    with db() as conn:
        conn.cursor().execute("DELETE FROM noleggi WHERE id=%s", (id,))
        return {"ok": True}

# ─────────────────────────────────────────────────────────────
#  VERBALI ENDPOINTS
# ─────────────────────────────────────────────────────────────
class VerbaleCreate(BaseModel):
    noleggio_id: int
    data: str
    ora: str
    targa: str
    km_iniziali: str
    km_attuali: str
    carburante: str
    tipo_riconsegna: str
    pulizia: str
    pulizia_premium: str
    oggetti: str
    oggetti_desc: Optional[str] = ""
    danno: str
    tipo_danno: Optional[str] = ""
    posizione_danno: Optional[str] = ""
    costo_danno: Optional[str] = ""
    descrizione: Optional[str] = ""
    operatore: str
    stato: str

@app.post("/api/verbali", status_code=201)
def create_verbale(data: VerbaleCreate, payload=Depends(verify_token)):
    with db() as conn:
        cur = conn.cursor()
        # Insert verbale
        cur.execute("""
        INSERT INTO verbali
          (noleggio_id,data,ora,targa,km_iniziali,km_attuali,carburante,
           tipo_riconsegna,pulizia,pulizia_premium,oggetti,oggetti_desc,
           danno,tipo_danno,posizione_danno,costo_danno,descrizione,operatore,stato)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
        """, (data.noleggio_id, data.data, data.ora, data.targa,
              data.km_iniziali, data.km_attuali, data.carburante,
              data.tipo_riconsegna, data.pulizia, data.pulizia_premium,
              data.oggetti, data.oggetti_desc, data.danno, data.tipo_danno,
              data.posizione_danno, data.costo_danno, data.descrizione,
              data.operatore, data.stato))
        vid = cur.fetchone()["id"]

        # Update noleggio status
        cur.execute(
            "UPDATE noleggi SET verbale_stato=%s, updated_at=NOW() WHERE id=%s",
            (data.stato, data.noleggio_id))

        # Update auto km
        try:
            km_new = int(float(data.km_attuali.replace(",","")))
            cur.execute(
                "UPDATE auto SET km=%s, updated_at=NOW() WHERE targa=%s",
                (km_new, data.targa))
        except: pass

        return {"id": vid}

@app.get("/api/verbali/pending")
def pending_verbali(payload=Depends(verify_token)):
    """Noleggi senza verbale (per il dropdown nel form verbale)."""
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
        SELECT id, nome_cognome, marca_modello, targa, data_inizio, km_iniziali
        FROM noleggi
        WHERE verbale_stato ILIKE '%attesa%' OR verbale_stato IS NULL OR verbale_stato=''
        ORDER BY id DESC
        """)
        return cur.fetchall()

# ─────────────────────────────────────────────────────────────
#  AUTO ENDPOINTS
# ─────────────────────────────────────────────────────────────
class AutoCreate(BaseModel):
    marca_modello: str
    targa: str
    telaio: Optional[str] = ""
    cilindrata: Optional[str] = ""
    alimentazione: Optional[str] = ""
    anno: Optional[str] = ""
    colore: Optional[str] = ""
    km: Optional[int] = 0

@app.get("/api/auto")
def list_auto(payload=Depends(verify_token)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM auto ORDER BY marca_modello")
        return cur.fetchall()

@app.post("/api/auto", status_code=201)
def create_auto(data: AutoCreate, payload=Depends(admin_only)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO auto (marca_modello,targa,telaio,cilindrata,alimentazione,anno,colore,km)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (targa) DO UPDATE SET
          marca_modello=EXCLUDED.marca_modello, km=EXCLUDED.km, updated_at=NOW()
        RETURNING id
        """, (data.marca_modello, data.targa, data.telaio, data.cilindrata,
              data.alimentazione, data.anno, data.colore, data.km))
        return {"id": cur.fetchone()["id"]}

# ─────────────────────────────────────────────────────────────
#  ACCESS LOG ENDPOINT (admin only)
# ─────────────────────────────────────────────────────────────
@app.get("/api/logs")
def get_logs(payload=Depends(admin_only)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM access_log ORDER BY ts DESC LIMIT 200")
        rows = cur.fetchall()
        return [dict(r) for r in rows]
