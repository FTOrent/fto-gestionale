# 🚀 GUIDA DEPLOY — FTO Gestionale Web
## Da zero a online in 30 minuti

---

## COSA HAI BISOGNO
- Account GitHub (gratuito) → github.com
- Account Supabase (gratuito) → supabase.com
- Account Railway (gratuito) → railway.app
- Il tuo dominio ftorent.it (già ce l'hai)

---

## PASSO 1 — Crea il database su Supabase (5 minuti)

1. Vai su **supabase.com** → "Start your project" → accedi con GitHub
2. Clicca **"New project"**
3. Dai un nome: `fto-gestionale`
4. Scegli una password per il database (salvala da qualche parte)
5. Region: **EU West (Ireland)** — la più vicina all'Italia
6. Clicca **"Create new project"** e aspetta 2 minuti

7. Quando è pronto, vai su **Settings → Database**
8. Scorri fino a **"Connection string"** → seleziona **"URI"**
9. Copia la stringa — assomiglia a:
   ```
   postgresql://postgres:[TUA-PASSWORD]@db.xxxxxxxxxxxx.supabase.co:5432/postgres
   ```
10. **SALVALA** — ti serve nel passo 3

---

## PASSO 2 — Carica il codice su GitHub (5 minuti)

1. Vai su **github.com** → clicca "+" in alto → **"New repository"**
2. Nome: `fto-gestionale`
3. Lascia tutto il resto default → **"Create repository"**

4. Sul tuo Mac, apri il **Terminale** e scrivi questi comandi uno alla volta:

```bash
cd ~/Desktop
# Sposta la cartella fto_web sul Desktop se non c'è già
```

```bash
cd fto_web
git init
git add .
git commit -m "FTO Gestionale v3.0"
git branch -M main
git remote add origin https://github.com/TUO-USERNAME/fto-gestionale.git
git push -u origin main
```

⚠️ Sostituisci `TUO-USERNAME` con il tuo username GitHub

---

## PASSO 3 — Deploy su Railway (10 minuti)

1. Vai su **railway.app** → "Login with GitHub"
2. Clicca **"New Project"**
3. Scegli **"Deploy from GitHub repo"**
4. Seleziona `fto-gestionale`
5. Railway inizierà a buildare automaticamente

6. Clicca sul progetto → **"Variables"** → aggiungi queste due:

   | Nome variabile | Valore |
   |---|---|
   | `DATABASE_URL` | La stringa copiata da Supabase nel Passo 1 |
   | `SECRET_KEY` | Una stringa casuale, es: `fto2025-chiave-segreta-oscar` |

7. Clicca **"Deploy"** (o aspetta che riparta automaticamente)

8. Dopo 2-3 minuti vedrai **"Active"** in verde ✅

9. Clicca su **"Settings"** → **"Networking"** → copia il dominio Railway
   (tipo: `fto-gestionale-production.up.railway.app`)

---

## PASSO 4 — Collega il tuo dominio ftorent.it (10 minuti)

**Su Railway:**
1. Vai su Settings → Networking → **"Custom Domain"**
2. Scrivi: `gestionale.ftorent.it`
3. Railway ti darà un valore CNAME, tipo: `fto-gestionale-production.up.railway.app`

**Sul pannello del tuo provider di dominio** (dove hai comprato ftorent.it):
1. Vai su **DNS / Gestione DNS**
2. Aggiungi un nuovo record:
   - Tipo: `CNAME`
   - Nome/Host: `gestionale`
   - Valore: il CNAME che ti ha dato Railway
   - TTL: `300` (o "Automatico")
3. Salva

⏱ Aspetta 5-30 minuti per la propagazione DNS

---

## PASSO 5 — Test finale

Apri nel browser: **https://gestionale.ftorent.it**

Dovresti vedere la schermata di login FTO.

Prova ad accedere con:
- Username: `ak` / Password: `ak47ven`

Se funziona, sei online! 🎉

---

## CREDENZIALI UTENTI

| Username | Password | Ruolo |
|---|---|---|
| ak | ak47ven | Admin |
| toad | caramello | Admin |
| fuma | Alex2001$ | Admin |
| utente 1 | ftorent$ | Dipendente |

---

## SE QUALCOSA VA STORTO

**Errore "Database connection":**
→ Controlla che DATABASE_URL in Railway sia corretta (copia-incolla di nuovo da Supabase)

**Errore "Build failed":**
→ Vai su Railway → Deployments → clicca sull'ultimo deploy → vedi i log

**Il dominio non funziona:**
→ Aspetta ancora 30 minuti per la propagazione DNS
→ Prova prima con l'URL diretto di Railway

**Per qualsiasi problema:**
→ Manda screenshot dell'errore e lo risolviamo

---

## AGGIORNAMENTI FUTURI

Quando vuoi aggiornare il software:
```bash
cd ~/Desktop/fto_web
git add .
git commit -m "Aggiornamento"
git push
```
Railway si aggiorna automaticamente in 2 minuti.

---

## COSTI

- **Supabase Free**: 500MB database, più che sufficiente per anni di noleggi
- **Railway Free**: 500 ore/mese di utilizzo (sufficiente per uso normale)
- **Railway Starter** (se servirà): $5/mese per utilizzo illimitato

Per 4 utenti con uso normale, il piano gratuito basta tranquillamente.
