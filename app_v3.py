# =========================================================
# app.py — Sistema Multiusuário (Streamlit + Google Sheets)
# Login/Cadastro + Usuário/Admin + Reservas + Aprovações
# + E-mails:
#   - ao ADMIN: novo cadastro e nova reserva
#   - ao USUÁRIO: quando ADMIN aprovar/rejeitar cadastro e confirmar/rejeitar reserva
#
# Cabeçalhos (EXATOS):
# users:
#   username|name|email|role|password_hash|created_at
# cadastro_requests:
#   id|name|username|email|password_hash|status|created_at|reviewed_at|reviewed_by|review_reason
# reservas (com início/fim):
#   id|name|username|equipment|date|start_time|end_time|status|created_at|reviewed_at|reviewed_by|review_reason
#
# Secrets necessários:
# GSHEET_SPREADSHEET_ID="..."
# [GSERVICE] ... json service account ...
# [EMAIL]
# SMTP_HOST="smtp.gmail.com"
# SMTP_PORT=587
# SMTP_USER="seuemail@..."
# SMTP_PASS="SENHA_DE_APP"
# FROM="seuemail@..."
# ADMIN_TO="admin@..."
# =========================================================

import os
import time
import base64
import uuid
import hashlib
import hmac
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
from gspread.exceptions import APIError, WorksheetNotFound, SpreadsheetNotFound
from PIL import Image

# ---------------------------------------------------------
# CONFIG (set_page_config SEMPRE primeiro)
# ---------------------------------------------------------
st.set_page_config(page_title="Laboratório Multiusuário ICB", layout="wide")

# Banner (opcional)
try:
    banner = Image.open("multiusuáriov2.png")  # ajuste o caminho se necessário
    st.image(banner, use_container_width=True)
except Exception:
    pass

st.title("Sistema de Gerenciamento de Reserva de Equipamentos")

# Secrets: proteje contra KeyError e dá mensagem amigável
SPREADSHEET_ID = st.secrets.get("GSHEET_SPREADSHEET_ID", "")
if not SPREADSHEET_ID:
    st.error("Faltou configurar GSHEET_SPREADSHEET_ID nos Secrets do Streamlit.")
    st.info('Vá em Manage app → Settings → Secrets e adicione:\nGSHEET_SPREADSHEET_ID = "..."')
    st.stop()

SHEET_USERS = "users"
SHEET_CAD = "cadastro_requests"
SHEET_RES = "reservas"

# Cabeçalhos EXATOS
HEADERS_USERS = ["username", "name", "email", "role", "password_hash", "created_at"]
HEADERS_CAD = [
    "id", "name", "username", "email", "password_hash", "status",
    "created_at", "reviewed_at", "reviewed_by", "review_reason"
]
HEADERS_RES = [
    "id", "name", "username", "equipment", "date", "start_time", "end_time", "status",
    "created_at", "reviewed_at", "reviewed_by", "review_reason"
]

EQUIPAMENTOS = [
    "Microscópio",
    "Centrífuga",
    "PCR",
    "Freezer -80°C",
    "Espectrofotômetro",
]

def gerar_horarios(inicio=8, fim=18, passo_min=30):
    hs = []
    total_ini = inicio * 60
    total_fim = fim * 60
    for m in range(total_ini, total_fim + 1, passo_min):
        hs.append(f"{m//60:02d}:{m%60:02d}")
    return hs

HORARIOS = gerar_horarios(8, 18, 30)  # 08:00–18:00 a cada 30 min

# ---------------------------------------------------------
# CSS
# ---------------------------------------------------------
st.markdown(
    """
<style>
.block-card {
  background:#f7f7f9;
  border:1px solid #e7e7ee;
  padding:14px;
  border-radius:10px;
}
.big-status-ok {
  background:#b9f6ca;
  padding:12px;
  font-size:18px;
  border-radius:10px;
  text-align:center;
}
.big-status-bad {
  background:#ff8a80;
  padding:12px;
  font-size:18px;
  border-radius:10px;
  text-align:center;
}
.small-muted { color:#666; font-size:0.9rem; }
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# E-MAIL (genérico + admin wrapper)
# ---------------------------------------------------------
def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Envia e-mail usando SMTP configurado em st.secrets["EMAIL"].
    Não derruba o app se falhar.
    """
    if "EMAIL" not in st.secrets:
        return False

    try:
        cfg = st.secrets["EMAIL"]

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg["FROM"]
        msg["To"] = to_email
        msg.set_content(body)

        host = cfg["SMTP_HOST"]
        port = int(cfg["SMTP_PORT"])
        user = cfg["SMTP_USER"]
        pwd = cfg["SMTP_PASS"]

        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(user, pwd)
            smtp.send_message(msg)

        return True
    except Exception as e:
        st.warning(f"Não consegui enviar e-mail (aviso): {e}")
        return False

def send_admin_email(subject: str, body: str) -> bool:
    """Envia sempre para o ADMIN_TO."""
    if "EMAIL" not in st.secrets:
        return False
    return send_email(st.secrets["EMAIL"]["ADMIN_TO"], subject, body)

# ---------------------------------------------------------
# PASSWORD HASH (PBKDF2)
# ---------------------------------------------------------
def hash_password(password: str, salt: bytes | None = None, iterations: int = 200_000) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"pbkdf2_sha256${iterations}$"
        f"{base64.b64encode(salt).decode()}$"
        f"{base64.b64encode(dk).decode()}"
    )

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, it, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(it))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# ---------------------------------------------------------
# GOOGLE SHEETS CLIENT
# ---------------------------------------------------------
@st.cache_resource
def gclient():
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    creds = Credentials.from_service_account_info(st.secrets["GSERVICE"], scopes=scopes)
    return gspread.authorize(creds)

def _extract_api_error_info(e: APIError):
    status = getattr(getattr(e, "response", None), "status_code", None)
    text = getattr(getattr(e, "response", None), "text", "")
    text = text[:400] + ("..." if text and len(text) > 400 else "")
    return status, text

def _retryable(status):
    return status in (429, 500, 503)

@st.cache_resource
def spreadsheet():
    last_err = None
    for attempt in range(4):
        try:
            return gclient().open_by_key(SPREADSHEET_ID)
        except APIError as e:
            last_err = e
            status, _ = _extract_api_error_info(e)
            if _retryable(status):
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
        except SpreadsheetNotFound:
            raise
    raise last_err

def clear_cache():
    st.cache_data.clear()

# ---------------------------------------------------------
# HEALTH CHECK + BOOTSTRAP
# ---------------------------------------------------------
def sheets_health_check_or_stop():
    try:
        sh = spreadsheet()
        return sh
    except SpreadsheetNotFound:
        st.error("Planilha não encontrada. Confirme o GSHEET_SPREADSHEET_ID no Secrets.")
        st.stop()
    except APIError as e:
        status, text = _extract_api_error_info(e)
        st.error("Falha ao acessar a planilha. Isso costuma ser permissão/API/quota.")
        with st.expander("Detalhes técnicos (diagnóstico)"):
            st.write("HTTP status:", status)
            if text:
                st.write("Resposta (parcial):", text)
            st.write("Service account:", st.secrets["GSERVICE"].get("client_email"))
            st.write("Spreadsheet ID:", SPREADSHEET_ID)
        st.info(
            "Checklist rápido:\n"
            "1) Compartilhe a planilha com o e-mail do service account como Editor.\n"
            "2) Habilite Google Sheets API e Google Drive API no Google Cloud.\n"
            "3) Se for quota/instabilidade, tente novamente / reinicie o app."
        )
        st.stop()

def get_worksheets_map_with_retry(sh):
    last_err = None
    for attempt in range(4):
        try:
            wlist = sh.worksheets()
            return {w.title: w for w in wlist}
        except APIError as e:
            last_err = e
            status, _ = _extract_api_error_info(e)
            if _retryable(status):
                time.sleep(1.5 * (attempt + 1))
                continue
            break

    status, text = _extract_api_error_info(last_err) if last_err else (None, "")
    st.error("Falha ao listar abas da planilha (metadata).")
    with st.expander("Detalhes técnicos (diagnóstico)"):
        st.write("HTTP status:", status)
        if text:
            st.write("Resposta (parcial):", text)
        st.write("Service account:", st.secrets["GSERVICE"].get("client_email"))
        st.write("Spreadsheet ID:", SPREADSHEET_ID)
    st.stop()

def ensure_header(ws_obj, headers: list[str]):
    vals = ws_obj.get_all_values()
    if not vals:
        ws_obj.append_row(headers)
        return
    # Se existir apenas cabeçalho e for diferente, atualiza a linha 1
    if len(vals) == 1 and vals[0] != headers:
        ws_obj.update("1:1", [headers])

def ensure_worksheets(sh):
    wmap = get_worksheets_map_with_retry(sh)

    targets = [
        (SHEET_USERS, HEADERS_USERS),
        (SHEET_CAD, HEADERS_CAD),
        (SHEET_RES, HEADERS_RES),
    ]

    for title, headers in targets:
        if title not in wmap:
            ws_obj = sh.add_worksheet(title=title, rows=2000, cols=max(12, len(headers)))
            ws_obj.append_row(headers)
            wmap[title] = ws_obj
        else:
            ensure_header(wmap[title], headers)

_sh = sheets_health_check_or_stop()
try:
    ensure_worksheets(_sh)
except APIError as e:
    status, text = _extract_api_error_info(e)
    st.error("Falha ao preparar as abas/cabeçalhos no Google Sheets.")
    with st.expander("Detalhes técnicos (diagnóstico)"):
        st.write("HTTP status:", status)
        if text:
            st.write("Resposta (parcial):", text)
        st.write("Service account:", st.secrets["GSERVICE"].get("client_email"))
        st.write("Spreadsheet ID:", SPREADSHEET_ID)
    st.stop()

# ---------------------------------------------------------
# Helpers: ws + leitura robusta
# ---------------------------------------------------------
def ws(sheet_name: str):
    try:
        return spreadsheet().worksheet(sheet_name)
    except WorksheetNotFound:
        ensure_worksheets(spreadsheet())
        return spreadsheet().worksheet(sheet_name)

@st.cache_data(ttl=15, show_spinner=False)
def read_df(sheet_name: str) -> pd.DataFrame:
    last_err = None
    for attempt in range(4):
        try:
            w = ws(sheet_name)
            values = w.get_all_values()
            if not values:
                return pd.DataFrame()
            return pd.DataFrame(values[1:], columns=values[0]).fillna("")
        except APIError as e:
            last_err = e
            status, _ = _extract_api_error_info(e)
            if _retryable(status):
                time.sleep(1.5 * (attempt + 1))
                continue
            break

    status, text = _extract_api_error_info(last_err) if last_err else (None, "")
    st.error("Não consegui ler a planilha no Google Sheets.")
    with st.expander("Detalhes técnicos (diagnóstico)"):
        st.write("Sheet:", sheet_name)
        st.write("HTTP status:", status)
        if text:
            st.write("Resposta (parcial):", text)
    return pd.DataFrame()

# ---------------------------------------------------------
# AUTH
# ---------------------------------------------------------
def users_get(username: str):
    df = read_df(SHEET_USERS)
    if df.empty or "username" not in df.columns:
        return None
    m = df["username"].str.lower() == username.lower()
    return df[m].iloc[0].to_dict() if m.any() else None

def authenticate(username: str, password: str):
    u = users_get(username)
    if not u:
        return False, "Usuário inválido."
    if verify_password(password, str(u.get("password_hash", ""))):
        return True, u
    return False, "Senha inválida."

def is_admin(user_dict: dict) -> bool:
    return str(user_dict.get("role", "")).strip().lower() == "admin"

# ---------------------------------------------------------
# CADASTRO REQUESTS (email ao admin + email ao usuário na revisão)
# ---------------------------------------------------------
def cadastro_submit(name: str, username: str, email: str, password: str):
    if users_get(username):
        return False, "Este username já existe."

    df_cad = read_df(SHEET_CAD)
    if not df_cad.empty:
        m = (df_cad["username"].str.lower() == username.lower()) & (df_cad["status"] == "Pendente")
        if m.any():
            return False, "Já existe um cadastro pendente com esse username."

    req_id = str(uuid.uuid4())
    created_utc = datetime.utcnow().isoformat(timespec="seconds")

    ws(SHEET_CAD).append_row([
        req_id,
        name.strip(),
        username.strip(),
        email.strip(),
        hash_password(password),
        "Pendente",
        created_utc,
        "",
        "",
        "",
    ])
    clear_cache()

    # e-mail ao admin
    send_admin_email(
        subject="Novo pedido de cadastro (Laboratório Multiusuário)",
        body=(
            "Chegou um novo pedido de cadastro.\n\n"
            f"ID: {req_id}\n"
            f"Nome: {name}\n"
            f"Username: {username}\n"
            f"Email: {email}\n"
            f"Data/hora (UTC): {created_utc}\n\n"
            "Acesse o painel de administrador para aprovar/rejeitar."
        ),
    )

    return True, "Cadastro enviado para aprovação do administrador."

def cadastro_review(request_id: str, action: str, admin_username: str, reason: str = ""):
    w = ws(SHEET_CAD)
    vals = w.get_all_values()
    if len(vals) < 2:
        return False, "Não há solicitações."

    headers = vals[0]
    rows = vals[1:]
    df = pd.DataFrame(rows, columns=headers).fillna("")

    idx = df.index[df["id"] == request_id]
    if len(idx) == 0:
        return False, "Solicitação não encontrada."
    i = int(idx[0])

    status = "Aprovado" if action == "Aprovar" else "Rejeitado"
    reviewed_utc = datetime.utcnow().isoformat(timespec="seconds")

    df.loc[i, "status"] = status
    df.loc[i, "reviewed_at"] = reviewed_utc
    df.loc[i, "reviewed_by"] = admin_username
    df.loc[i, "review_reason"] = reason

    if action == "Aprovar":
        ws(SHEET_USERS).append_row([
            df.loc[i, "username"],
            df.loc[i, "name"],
            df.loc[i, "email"],
            "user",
            df.loc[i, "password_hash"],
            datetime.utcnow().isoformat(timespec="seconds"),
        ])

    # Atualiza a linha do request
    row_number = i + 2
    col_map = {h: (j + 1) for j, h in enumerate(headers)}
    for col in ["status", "reviewed_at", "reviewed_by", "review_reason"]:
        if col in col_map:
            w.update_cell(row_number, col_map[col], str(df.loc[i, col]))

    clear_cache()

    # e-mail ao usuário (sempre que o admin revisar)
    user_email = str(df.loc[i, "email"]).strip()
    if user_email:
        send_email(
            to_email=user_email,
            subject=f"Cadastro {status} — Laboratório Multiusuário",
            body=(
                f"Olá, {df.loc[i,'name']}!\n\n"
                f"Seu pedido de cadastro foi: {status}.\n"
                f"Usuário: {df.loc[i,'username']}\n"
                f"Revisado por: {admin_username}\n"
                f"Data/hora (UTC): {reviewed_utc}\n"
                + (f"\nMotivo informado: {reason}\n" if reason else "\n")
                + ("Se aprovado, você já pode fazer login no sistema.\n" if status == "Aprovado" else "")
            ),
        )

    return True, f"Solicitação {status.lower()}."

# ---------------------------------------------------------
# RESERVAS (email ao admin + email ao usuário na revisão)
# ---------------------------------------------------------
def _to_minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)

def slot_available(df_res: pd.DataFrame, equipment: str, date: str, start_time: str, end_time: str) -> bool:
    # validação: fim precisa ser maior que início
    if _to_minutes(end_time) <= _to_minutes(start_time):
        return False

    if df_res.empty:
        return True

    needed = {"equipment", "date", "status"}
    if not needed.issubset(set(df_res.columns)):
        return True

    df_day = df_res[
        (df_res["equipment"] == equipment) &
        (df_res["date"] == date) &
        (df_res["status"].isin(["Pendente", "Confirmado"]))
    ].copy()

    if df_day.empty:
        return True

    req_s = _to_minutes(start_time)
    req_e = _to_minutes(end_time)

    has_new = {"start_time", "end_time"}.issubset(df_day.columns)
    has_old = "time" in df_day.columns

    intervals = []
    if has_new:
        for _, r in df_day.iterrows():
            s = str(r.get("start_time", "")).strip()
            e = str(r.get("end_time", "")).strip()
            if s and e:
                try:
                    intervals.append((_to_minutes(s), _to_minutes(e)))
                except Exception:
                    pass
    elif has_old:
        for _, r in df_day.iterrows():
            t = str(r.get("time", "")).strip()
            if t:
                try:
                    s = _to_minutes(t)
                    e = s + 60  # assume 1h na versão antiga
                    intervals.append((s, e))
                except Exception:
                    pass

    for s, e in intervals:
        # sobreposição: [req_s, req_e) com [s, e)
        if req_s < e and req_e > s:
            return False

    return True

def reserva_submit(user: dict, equipment: str, date: str, start_time: str, end_time: str):
    res_id = str(uuid.uuid4())
    created_utc = datetime.utcnow().isoformat(timespec="seconds")

    ws(SHEET_RES).append_row([
        res_id,
        user.get("name", ""),
        user.get("username", ""),
        equipment,
        date,
        start_time,
        end_time,
        "Pendente",
        created_utc,
        "",
        "",
        "",
    ])
    clear_cache()

    # e-mail ao admin
    send_admin_email(
        subject="Nova solicitação de reserva de equipamento",
        body=(
            "Chegou uma nova solicitação de reserva.\n\n"
            f"ID: {res_id}\n"
            f"Solicitante: {user.get('name','')} ({user.get('username','')})\n"
            f"Equipamento: {equipment}\n"
            f"Data: {date}\n"
            f"Início: {start_time}\n"
            f"Fim: {end_time}\n"
            f"Data/hora (UTC): {created_utc}\n\n"
            "Acesse o painel de administrador para confirmar/rejeitar."
        ),
    )

def reserva_review(reserva_id: str, action: str, admin_username: str, reason: str = ""):
    w = ws(SHEET_RES)
    vals = w.get_all_values()
    if len(vals) < 2:
        return False, "Não há reservas."

    headers = vals[0]
    rows = vals[1:]
    df = pd.DataFrame(rows, columns=headers).fillna("")

    if "id" not in df.columns:
        return False, "A aba 'reservas' não tem a coluna 'id'."

    idx = df.index[df["id"] == reserva_id]
    if len(idx) == 0:
        return False, "Reserva não encontrada."
    i = int(idx[0])

    status = "Confirmado" if action == "Confirmar" else "Rejeitado"
    reviewed_utc = datetime.utcnow().isoformat(timespec="seconds")

    df.loc[i, "status"] = status
    df.loc[i, "reviewed_at"] = reviewed_utc
    df.loc[i, "reviewed_by"] = admin_username
    df.loc[i, "review_reason"] = reason

    row_number = i + 2
    col_map = {h: (j + 1) for j, h in enumerate(headers)}
    for col in ["status", "reviewed_at", "reviewed_by", "review_reason"]:
        if col in col_map:
            w.update_cell(row_number, col_map[col], str(df.loc[i, col]))

    clear_cache()

    # e-mail ao usuário (busca e-mail em users usando o username)
    req_username = str(df.loc[i, "username"]).strip() if "username" in df.columns else ""
    u = users_get(req_username) if req_username else None
    user_email = str(u.get("email", "")).strip() if u else ""

    st_time = str(df.loc[i, "start_time"]).strip() if "start_time" in df.columns else ""
    en_time = str(df.loc[i, "end_time"]).strip() if "end_time" in df.columns else ""

    if user_email:
        send_email(
            to_email=user_email,
            subject=f"Reserva {status} — {df.loc[i,'equipment']} ({df.loc[i,'date']})",
            body=(
                f"Olá, {df.loc[i,'name']}!\n\n"
                f"Sua solicitação de reserva foi: {status}.\n"
                f"Equipamento: {df.loc[i,'equipment']}\n"
                f"Data: {df.loc[i,'date']}\n"
                f"Início: {st_time}\n"
                f"Fim: {en_time}\n"
                f"Revisado por: {admin_username}\n"
                f"Data/hora (UTC): {reviewed_utc}\n"
                + (f"\nMotivo informado: {reason}\n" if reason else "\n")
            ),
        )

    return True, f"Reserva {status.lower()}."

# ---------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------
if "logged" not in st.session_state:
    st.session_state.logged = False
if "user" not in st.session_state:
    st.session_state.user = {}

# ---------------------------------------------------------
# TELA INICIAL: LOGIN / CADASTRO
# ---------------------------------------------------------
if not st.session_state.logged:
    tab_login, tab_cad = st.tabs(["🔑 Login", "📝 Cadastro"])

    with tab_login:
        st.markdown("<div class='block-card'>", unsafe_allow_html=True)
        u = st.text_input("Usuário", key="login_user")
        p = st.text_input("Senha", type="password", key="login_pass")
        if st.button("Entrar", use_container_width=True):
            ok, res = authenticate(u, p)
            if ok:
                st.session_state.logged = True
                st.session_state.user = res
                st.rerun()
            else:
                st.error(res)
        st.markdown("</div>", unsafe_allow_html=True)

    with tab_cad:
        st.markdown("<div class='block-card'>", unsafe_allow_html=True)
        name = st.text_input("Nome completo", key="cad_name")
        username = st.text_input("Username (login)", key="cad_username")
        email = st.text_input("Email", key="cad_email")
        pw1 = st.text_input("Senha", type="password", key="cad_pw1")
        pw2 = st.text_input("Confirmar senha", type="password", key="cad_pw2")

        if st.button("Solicitar cadastro", use_container_width=True):
            if not name.strip() or not username.strip() or not email.strip():
                st.error("Preencha nome, username e email.")
            elif len(pw1) < 6:
                st.error("Use uma senha com pelo menos 6 caracteres.")
            elif pw1 != pw2:
                st.error("As senhas não coincidem.")
            else:
                ok, msg = cadastro_submit(name, username, email, pw1)
                (st.success if ok else st.error)(msg)

        st.info("Após solicitar, o administrador precisa aprovar para você conseguir fazer login.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.stop()

# ---------------------------------------------------------
# ÁREA LOGADA
# ---------------------------------------------------------
user = st.session_state.user
st.success(f"Logado como **{user.get('name','')}**  | perfil: **{user.get('role','user')}**")

# ---------------------------------------------------------
# PAINEL ADMIN
# ---------------------------------------------------------
if is_admin(user):
    st.subheader("🛠️ Painel do Administrador")

    df_users = read_df(SHEET_USERS)
    df_cad = read_df(SHEET_CAD)
    df_res = read_df(SHEET_RES)

    a1, a2, a3 = st.tabs([
        "👥 Pessoas cadastradas",
        "👤 Cadastros (pendentes + histórico)",
        "📅 Reservas (pendentes + histórico)",
    ])

    # --- Pessoas cadastradas ---
    with a1:
        if df_users.empty:
            st.info("Ainda não há usuários cadastrados.")
        else:
            cols = [c for c in ["username", "name", "email", "role", "created_at"] if c in df_users.columns]
            view = df_users[cols] if cols else df_users
            st.dataframe(view, use_container_width=True)
            st.caption("Para tornar alguém admin: edite 'role' para 'admin' na aba users.")

    # --- Cadastros: pendentes + histórico ---
    with a2:
        if df_cad.empty:
            st.info("Ainda não há solicitações de cadastro.")
        else:
            pend = df_cad[df_cad.get("status", "") == "Pendente"]
            hist = df_cad[df_cad.get("status", "").isin(["Aprovado", "Rejeitado"])]

            tpend, thist = st.tabs(["Pendentes", "Histórico (Aprovados/Rejeitados)"])

            with tpend:
                if pend.empty:
                    st.info("Nenhum cadastro pendente.")
                else:
                    cols = [c for c in ["id", "name", "username", "email", "created_at", "status"] if c in pend.columns]
                    st.dataframe(pend[cols] if cols else pend, use_container_width=True)

                    sel_id = st.selectbox("Selecione um cadastro (id) para revisar", pend["id"].tolist())
                    reason = st.text_input("Motivo (opcional)", key="cad_reason")

                    cA, cR = st.columns(2)
                    with cA:
                        if st.button("Aprovar cadastro", use_container_width=True):
                            ok, msg = cadastro_review(sel_id, "Aprovar", user.get("username", "admin"), reason)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with cR:
                        if st.button("Rejeitar cadastro", use_container_width=True):
                            ok, msg = cadastro_review(sel_id, "Rejeitar", user.get("username", "admin"), reason)
                            (st.success if ok else st.error)(msg)
                            st.rerun()

            with thist:
                if hist.empty:
                    st.info("Ainda não há cadastros aprovados/rejeitados.")
                else:
                    cols = [c for c in ["name", "username", "email", "status", "created_at",
                                        "reviewed_at", "reviewed_by", "review_reason"] if c in hist.columns]
                    view = hist[cols] if cols else hist
                    by_cols = [c for c in ["reviewed_at", "created_at"] if c in view.columns]
                    if by_cols:
                        view = view.sort_values(by=by_cols, ascending=False)
                    st.dataframe(view, use_container_width=True)

    # --- Reservas: pendentes + histórico ---
    with a3:
        if df_res.empty:
            st.info("Ainda não há solicitações de reserva.")
        else:
            pend_res = df_res[df_res.get("status", "") == "Pendente"]
            hist_res = df_res[df_res.get("status", "").isin(["Confirmado", "Rejeitado"])]

            tpend, thist = st.tabs(["Pendentes", "Histórico (Confirmadas/Rejeitadas)"])

            with tpend:
                if pend_res.empty:
                    st.info("Nenhuma reserva pendente.")
                else:
                    cols = [c for c in ["id", "name", "username", "equipment", "date",
                                        "start_time", "end_time", "status", "created_at"] if c in pend_res.columns]
                    st.dataframe(pend_res[cols] if cols else pend_res, use_container_width=True)

                    sel_id = st.selectbox("Selecione uma reserva (id) para revisar", pend_res["id"].tolist(), key="res_sel")
                    reason = st.text_input("Motivo (opcional)", key="res_reason")

                    cC, cX = st.columns(2)
                    with cC:
                        if st.button("Confirmar reserva", use_container_width=True):
                            ok, msg = reserva_review(sel_id, "Confirmar", user.get("username", "admin"), reason)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with cX:
                        if st.button("Rejeitar reserva", use_container_width=True):
                            ok, msg = reserva_review(sel_id, "Rejeitar", user.get("username", "admin"), reason)
                            (st.success if ok else st.error)(msg)
                            st.rerun()

            with thist:
                if hist_res.empty:
                    st.info("Ainda não há reservas confirmadas/rejeitadas.")
                else:
                    cols = [c for c in ["name", "username", "equipment", "date",
                                        "start_time", "end_time", "status", "created_at",
                                        "reviewed_at", "reviewed_by", "review_reason"] if c in hist_res.columns]
                    view = hist_res[cols] if cols else hist_res
                    by_cols = [c for c in ["reviewed_at", "created_at"] if c in view.columns]
                    if by_cols:
                        view = view.sort_values(by=by_cols, ascending=False)
                    st.dataframe(view, use_container_width=True)

    st.divider()

# ---------------------------------------------------------
# PAINEL USUÁRIO (e admin também pode solicitar)
# ---------------------------------------------------------
st.subheader("📌 Solicitar uso de equipamento")

df_res = read_df(SHEET_RES)

# Regra: data mínima = hoje + 7 dias
min_date = (datetime.today().date() + timedelta(days=7))

c1, c2, c3, c4 = st.columns([2, 2, 2, 2])
with c1:
    equip = st.selectbox("Equipamento", EQUIPAMENTOS)
with c2:
    date_obj = st.date_input("Data", min_date, min_value=min_date)
with c3:
    start_time = st.selectbox("Início", HORARIOS, key="start_time")
with c4:
    try:
        i = HORARIOS.index(start_time)
        default_end = min(i + 2, len(HORARIOS) - 1)  # 1h depois (2 passos de 30min)
    except Exception:
        default_end = 0
    end_time = st.selectbox("Fim", HORARIOS, index=default_end, key="end_time")

# Segurança extra (mesmo com min_value)
if date_obj < min_date:
    st.error("A data mínima para reserva é 7 dias a partir de hoje.")
    st.stop()

date_str = date_obj.strftime("%d/%m/%Y")
avail = slot_available(df_res, equip, date_str, start_time, end_time)

st.markdown(
    "<div class='big-status-ok'>Disponível</div>" if avail else "<div class='big-status-bad'>Indisponível</div>",
    unsafe_allow_html=True,
)

if st.button("Enviar pedido de reserva", use_container_width=True):
    if avail:
        reserva_submit(user, equip, date_str, start_time, end_time)
        st.success("Pedido enviado (status: Pendente).")
        st.rerun()
    else:
        if _to_minutes(end_time) <= _to_minutes(start_time):
            st.error("O horário de fim precisa ser maior que o horário de início.")
        else:
            st.error("Horário indisponível para este equipamento (conflito com outra reserva).")

st.subheader("📋 Meus pedidos (pendentes e finalizados)")

df_res = read_df(SHEET_RES)
if df_res.empty or "username" not in df_res.columns:
    st.info("Você ainda não fez pedidos.")
else:
    mine = df_res[df_res["username"] == user.get("username", "")]
    if mine.empty:
        st.info("Você ainda não fez pedidos.")
    else:
        pend = mine[mine.get("status", "") == "Pendente"]
        done = mine[mine.get("status", "").isin(["Confirmado", "Rejeitado"])]

        tpend, tdone = st.tabs(["Pendentes", "Finalizados (Confirmados/Rejeitados)"])

        with tpend:
            if pend.empty:
                st.info("Sem pedidos pendentes.")
            else:
                cols = [c for c in ["equipment", "date", "start_time", "end_time", "status", "created_at"] if c in pend.columns]
                st.dataframe(pend[cols] if cols else pend, use_container_width=True)

        with tdone:
            if done.empty:
                st.info("Sem pedidos finalizados.")
            else:
                cols = [c for c in ["equipment", "date", "start_time", "end_time", "status",
                                    "created_at", "reviewed_at", "review_reason"] if c in done.columns]
                st.dataframe(done[cols] if cols else done, use_container_width=True)

st.divider()

if st.button("Sair"):
    st.session_state.logged = False
    st.session_state.user = {}
    st.rerun()
