# =========================================================
# app.py — Login/Cadastro + User/Admin + Aprovações (Sheets)
# (com retry + diagnóstico seguro para APIError do gspread)
# =========================================================

import os
import time
import base64
import uuid
import hashlib
import hmac
from datetime import datetime

import pandas as pd
import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
from gspread.exceptions import APIError, WorksheetNotFound

# ---------------------------------------------------------
# CONFIG BÁSICA
# ---------------------------------------------------------
st.set_page_config(page_title="Laboratório Multiusuário ICB", layout="wide")
st.title("Sistema de gerenciamento do Laboratório Multiusuário ICB")

# Deve existir no Secrets do Streamlit:
# GSHEET_SPREADSHEET_ID = "..."
# [GSERVICE] ... JSON do service account ...
SPREADSHEET_ID = st.secrets["GSHEET_SPREADSHEET_ID"]

SHEET_USERS = "users"
SHEET_CAD = "cadastro_requests"
SHEET_RES = "reservas"

EQUIPAMENTOS = [
    "Microscópio",
    "Centrífuga",
    "PCR",
    "Freezer -80°C",
    "Espectrofotômetro",
]
HORARIOS = [f"{h:02d}:00" for h in range(8, 18)]  # 08:00–17:00

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
# HASH DE SENHA (PBKDF2)
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

@st.cache_resource
def spreadsheet():
    return gclient().open_by_key(SPREADSHEET_ID)

def clear_cache():
    st.cache_data.clear()

# ---------------------------------------------------------
# BOOTSTRAP DAS ABAS (cria se não existir)
# ---------------------------------------------------------
def ensure_worksheets():
    sh = spreadsheet()

    def ensure_sheet(title: str, headers: list[str]):
        try:
            w = sh.worksheet(title)
        except WorksheetNotFound:
            w = sh.add_worksheet(title=title, rows=2000, cols=max(10, len(headers)))
            w.append_row(headers)
            return

        vals = w.get_all_values()
        if not vals:
            w.append_row(headers)
            return

        # Se só tem cabeçalho e ele não bate, atualiza (sem mexer em dados existentes)
        if len(vals) == 1:
            existing_headers = vals[0]
            if existing_headers != headers:
                w.update("1:1", [headers])

    ensure_sheet(
        SHEET_USERS,
        ["id", "name", "username", "email", "password_hash", "role", "status", "created_at"],
    )
    ensure_sheet(
        SHEET_CAD,
        ["id", "name", "username", "email", "password_hash", "status", "created_at",
         "reviewed_at", "reviewed_by", "review_reason"],
    )
    ensure_sheet(
        SHEET_RES,
        ["id", "name", "username", "equipment", "date", "time", "status", "created_at",
         "reviewed_at", "reviewed_by", "review_reason"],
    )

ensure_worksheets()

# ---------------------------------------------------------
# Helpers: worksheet + leitura robusta (retry + diagnóstico)
# ---------------------------------------------------------
def ws(sheet_name: str):
    try:
        return spreadsheet().worksheet(sheet_name)
    except WorksheetNotFound:
        ensure_worksheets()
        return spreadsheet().worksheet(sheet_name)

def _extract_api_error_info(e: APIError):
    status = getattr(getattr(e, "response", None), "status_code", None)
    text = getattr(getattr(e, "response", None), "text", "")
    text = text[:400] + ("..." if text and len(text) > 400 else "")
    return status, text

@st.cache_data(ttl=15, show_spinner=False)
def read_df(sheet_name: str) -> pd.DataFrame:
    last_err = None

    # retry simples para erros temporários (quota/instabilidade)
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
            if status in (429, 500, 503):
                time.sleep(1.5 * (attempt + 1))
                continue
            break

    status, text = _extract_api_error_info(last_err) if last_err else (None, "")
    st.error(
        "Não consegui ler a planilha no Google Sheets.\n\n"
        "Causas mais comuns:\n"
        "• A planilha NÃO está compartilhada com o e-mail do service account\n"
        "• Google Sheets API/Drive API desabilitada no projeto\n"
        "• Quota/limite temporário (tente novamente)\n"
    )
    with st.expander("Detalhes técnicos (diagnóstico)"):
        st.write("Sheet:", sheet_name)
        st.write("HTTP status:", status)
        if text:
            st.write("Resposta (parcial):", text)
        st.write("Service account:", st.secrets["GSERVICE"].get("client_email"))
        st.write("Spreadsheet ID:", SPREADSHEET_ID)

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
    status = str(u.get("status", "")).strip().lower()
    if status and status not in ["ativo", "active"]:
        return False, "Usuário não está ativo (aguarde aprovação/regularização)."
    if verify_password(password, str(u.get("password_hash", ""))):
        return True, u
    return False, "Senha inválida."

def is_admin(user_dict: dict) -> bool:
    return str(user_dict.get("role", "")).strip().lower() == "admin"

# ---------------------------------------------------------
# CADASTRO (solicitação) + REVIEW (admin)
# ---------------------------------------------------------
def cadastro_submit(name: str, username: str, email: str, password: str):
    if users_get(username):
        return False, "Este username já existe em usuários."

    df_cad = read_df(SHEET_CAD)
    if not df_cad.empty and "username" in df_cad.columns and "status" in df_cad.columns:
        m = (df_cad["username"].str.lower() == username.lower()) & (df_cad["status"] == "Pendente")
        if m.any():
            return False, "Já existe um cadastro pendente com esse username."

    ws(SHEET_CAD).append_row([
        str(uuid.uuid4()),
        name.strip(),
        username.strip(),
        email.strip(),
        hash_password(password),
        "Pendente",
        datetime.utcnow().isoformat(timespec="seconds"),
        "",
        "",
        "",
    ])
    clear_cache()
    return True, "Cadastro enviado para aprovação do administrador."

def cadastro_review(request_id: str, action: str, admin_username: str, reason: str = ""):
    w = ws(SHEET_CAD)
    vals = w.get_all_values()
    if len(vals) < 2:
        return False, "Não há solicitações."

    headers = vals[0]
    rows = vals[1:]
    df = pd.DataFrame(rows, columns=headers).fillna("")

    if "id" not in df.columns:
        return False, "Aba cadastro_requests sem coluna 'id'."

    idx = df.index[df["id"] == request_id]
    if len(idx) == 0:
        return False, "Solicitação não encontrada."
    i = int(idx[0])

    status = "Aprovado" if action == "Aprovar" else "Rejeitado"
    df.loc[i, "status"] = status
    df.loc[i, "reviewed_at"] = datetime.utcnow().isoformat(timespec="seconds")
    df.loc[i, "reviewed_by"] = admin_username
    df.loc[i, "review_reason"] = reason

    # Se aprovou, cria usuário
    if action == "Aprovar":
        ws(SHEET_USERS).append_row([
            str(uuid.uuid4()),
            df.loc[i, "name"],
            df.loc[i, "username"],
            df.loc[i, "email"],
            df.loc[i, "password_hash"],
            "user",      # padrão
            "Ativo",
            datetime.utcnow().isoformat(timespec="seconds"),
        ])

    row_number = i + 2
    col_map = {h: (j + 1) for j, h in enumerate(headers)}
    for col in ["status", "reviewed_at", "reviewed_by", "review_reason"]:
        if col in col_map:
            w.update_cell(row_number, col_map[col], str(df.loc[i, col]))

    clear_cache()
    return True, f"Solicitação {status.lower()}."

# ---------------------------------------------------------
# RESERVAS (user solicita; admin confirma/rejeita)
# ---------------------------------------------------------
def slot_available(df_res: pd.DataFrame, equipment: str, date: str, time_str: str) -> bool:
    if df_res.empty:
        return True
    if not all(c in df_res.columns for c in ["equipment", "date", "time", "status"]):
        return True
    m = (
        (df_res["equipment"] == equipment) &
        (df_res["date"] == date) &
        (df_res["time"] == time_str) &
        (df_res["status"].isin(["Pendente", "Confirmado"]))
    )
    return not m.any()

def reserva_submit(user: dict, equipment: str, date: str, time_str: str):
    ws(SHEET_RES).append_row([
        str(uuid.uuid4()),
        user.get("name", ""),
        user.get("username", ""),
        equipment,
        date,
        time_str,
        "Pendente",
        datetime.utcnow().isoformat(timespec="seconds"),
        "",
        "",
        "",
    ])
    clear_cache()

def reserva_review(reserva_id: str, action: str, admin_username: str, reason: str = ""):
    w = ws(SHEET_RES)
    vals = w.get_all_values()
    if len(vals) < 2:
        return False, "Não há reservas."

    headers = vals[0]
    rows = vals[1:]
    df = pd.DataFrame(rows, columns=headers).fillna("")

    if "id" not in df.columns:
        return False, "Aba reservas sem coluna 'id'."

    idx = df.index[df["id"] == reserva_id]
    if len(idx) == 0:
        return False, "Reserva não encontrada."
    i = int(idx[0])

    status = "Confirmado" if action == "Confirmar" else "Rejeitado"
    df.loc[i, "status"] = status
    df.loc[i, "reviewed_at"] = datetime.utcnow().isoformat(timespec="seconds")
    df.loc[i, "reviewed_by"] = admin_username
    df.loc[i, "review_reason"] = reason

    row_number = i + 2
    col_map = {h: (j + 1) for j, h in enumerate(headers)}
    for col in ["status", "reviewed_at", "reviewed_by", "review_reason"]:
        if col in col_map:
            w.update_cell(row_number, col_map[col], str(df.loc[i, col]))

    clear_cache()
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

df_res = read_df(SHEET_RES)

# ---------------------------------------------------------
# PAINEL ADMIN
# ---------------------------------------------------------
if is_admin(user):
    st.subheader("🛠️ Painel do Administrador")
    t1, t2 = st.tabs(["👤 Cadastros pendentes", "📅 Reservas pendentes"])

    with t1:
        df_cad = read_df(SHEET_CAD)
        pend = df_cad[df_cad.get("status", "") == "Pendente"] if not df_cad.empty else pd.DataFrame()

        if pend.empty:
            st.info("Nenhuma solicitação de cadastro pendente.")
        else:
            cols = [c for c in ["id", "name", "username", "email", "created_at", "status"] if c in pend.columns]
            st.dataframe(pend[cols], use_container_width=True)

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

    with t2:
        pend_res = df_res[df_res.get("status", "") == "Pendente"] if not df_res.empty else pd.DataFrame()

        if pend_res.empty:
            st.info("Nenhuma solicitação de reserva pendente.")
        else:
            cols = [c for c in ["id", "username", "equipment", "date", "time", "status", "created_at"] if c in pend_res.columns]
            st.dataframe(pend_res[cols], use_container_width=True)

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

    st.divider()

# ---------------------------------------------------------
# PAINEL USUÁRIO (e admin também pode solicitar)
# ---------------------------------------------------------
st.subheader("📌 Solicitar uso de equipamento")

c1, c2, c3 = st.columns([2, 2, 2])

with c1:
    equip = st.selectbox("Equipamento", EQUIPAMENTOS)

with c2:
    date_obj = st.date_input("Data", datetime.today().date())

with c3:
    time_str = st.selectbox("Horário", HORARIOS)

date_str = date_obj.strftime("%d/%m/%Y")
avail = slot_available(df_res, equip, date_str, time_str)

st.markdown(
    "<div class='big-status-ok'>Disponível</div>" if avail else "<div class='big-status-bad'>Indisponível</div>",
    unsafe_allow_html=True,
)

if st.button("Enviar pedido de reserva", use_container_width=True):
    if avail:
        reserva_submit(user, equip, date_str, time_str)
        st.success("Pedido enviado (status: Pendente).")
        st.rerun()
    else:
        st.error("Horário indisponível para este equipamento.")

st.subheader("📋 Meus pedidos (reservas)")
df_res = read_df(SHEET_RES)

if df_res.empty or "username" not in df_res.columns:
    st.info("Você ainda não fez pedidos.")
else:
    mine = df_res[df_res["username"] == user.get("username", "")]
    if mine.empty:
        st.info("Você ainda não fez pedidos.")
    else:
        # ordena se as colunas existirem
        sort_cols = [c for c in ["date", "time", "created_at"] if c in mine.columns]
        if sort_cols:
            mine = mine.sort_values(by=sort_cols, ascending=[True] * len(sort_cols), errors="ignore")
        st.dataframe(mine, use_container_width=True)

st.divider()

if st.button("Sair"):
    st.session_state.logged = False
    st.session_state.user = {}
    st.rerun()
```
