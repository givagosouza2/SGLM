import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from gspread.exceptions import SpreadsheetNotFound, WorksheetNotFound, APIError
from datetime import datetime
import uuid
import os, base64, hashlib, hmac

# =========================================================
# CONFIG
# =========================================================
st.set_page_config(page_title="Lab Multiusuário ICB", layout="wide")

SPREADSHEET_ID = st.secrets.get("GSHEET_SPREADSHEET_ID", "").strip()

SHEET_USERS = "users"
SHEET_CAD = "cadastro_requests"
SHEET_RES = "reservas"

USERS_HEADER = ["username", "name", "email", "role", "password_hash", "created_at"]
CAD_HEADER = ["id", "username", "name", "email", "lab", "password_hash",
              "status", "created_at", "reviewed_at", "reviewed_by"]
RES_HEADER = ["id", "name", "username", "equipment", "date", "time",
              "status", "created_at", "reviewed_at", "reviewed_by"]

DEFAULT_ADMIN = {
    "username": "admin",
    "name": "Administrador",
    "email": "admin@icb.ufpa.br",
    "password": "admin123",
}

# =========================================================
# SEGURANÇA – HASH DE SENHA
# =========================================================
def hash_password(password: str, salt: bytes | None = None, iterations: int = 200_000) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}$" \
           f"{base64.b64encode(salt).decode()}$" \
           f"{base64.b64encode(dk).decode()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, it, salt_b64, hash_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(it))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# =========================================================
# GOOGLE SHEETS – CONEXÃO SEGURA
# =========================================================
@st.cache_resource
def gsheet_client():
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    try:
        creds = Credentials.from_service_account_info(
            st.secrets["GSERVICE"], scopes=scopes
        )
        return gspread.authorize(creds)
    except Exception as e:
        st.error("Erro ao criar credenciais Google.")
        st.exception(e)
        st.stop()

@st.cache_resource
def spreadsheet():
    if not SPREADSHEET_ID:
        st.error("GSHEET_SPREADSHEET_ID não definido nos Secrets.")
        st.stop()

    try:
        return gsheet_client().open_by_key(SPREADSHEET_ID)
    except SpreadsheetNotFound:
        st.error("Planilha não encontrada.")
        st.write("Compartilhe a planilha com:")
        st.code(st.secrets["GSERVICE"].get("client_email"))
        st.stop()
    except APIError as e:
        st.error("Erro da API Google ao abrir a planilha.")
        st.code(str(e))
        st.stop()

def ws(name: str):
    try:
        return spreadsheet().worksheet(name)
    except WorksheetNotFound:
        st.error(f"Aba '{name}' não existe. Crie-a manualmente.")
        st.stop()

# =========================================================
# UTILIDADES SHEETS
# =========================================================
def ensure_headers(sheet_name: str, header: list[str]):
    w = ws(sheet_name)
    values = w.get_all_values()
    if not values:
        w.append_row(header)
        return
    if values[0] != header:
        st.warning(f"Cabeçalho da aba '{sheet_name}' diferente do esperado.")

def read_df(sheet_name: str) -> pd.DataFrame:
    w = ws(sheet_name)
    values = w.get_all_values()
    if not values or len(values) == 1:
        return pd.DataFrame(columns=values[0] if values else [])
    return pd.DataFrame(values[1:], columns=values[0])

def append_row(sheet_name: str, row: dict):
    w = ws(sheet_name)
    header = w.row_values(1)
    w.append_row([row.get(col, "") for col in header])

def update_by_id(sheet_name: str, row_id: str, updates: dict):
    w = ws(sheet_name)
    values = w.get_all_values()
    header = values[0]
    id_col = header.index("id")
    for i, row in enumerate(values[1:], start=2):
        if row[id_col] == row_id:
            for k, v in updates.items():
                if k in header:
                    w.update_cell(i, header.index(k) + 1, v)
            return True
    return False

# =========================================================
# INIT
# =========================================================
ensure_headers(SHEET_USERS, USERS_HEADER)
ensure_headers(SHEET_CAD, CAD_HEADER)
ensure_headers(SHEET_RES, RES_HEADER)

# =========================================================
# GARANTE ADMIN
# =========================================================
def ensure_admin():
    df = read_df(SHEET_USERS)
    if df.empty or not (df["role"] == "admin").any():
        append_row(SHEET_USERS, {
            "username": DEFAULT_ADMIN["username"],
            "name": DEFAULT_ADMIN["name"],
            "email": DEFAULT_ADMIN["email"],
            "role": "admin",
            "password_hash": hash_password(DEFAULT_ADMIN["password"]),
            "created_at": datetime.utcnow().isoformat(timespec="seconds")
        })

ensure_admin()

# =========================================================
# SESSION
# =========================================================
if "logged" not in st.session_state:
    st.session_state.logged = False
if "user" not in st.session_state:
    st.session_state.user = {}
if "role" not in st.session_state:
    st.session_state.role = "user"

# =========================================================
# AUTH
# =========================================================
def authenticate(username, password):
    df = read_df(SHEET_USERS)
    if df.empty:
        return False, "Sem usuários cadastrados."
    m = df["username"].str.lower() == username.lower()
    if not m.any():
        return False, "Usuário inválido."
    row = df[m].iloc[0]
    if verify_password(password, row["password_hash"]):
        return True, row.to_dict()
    return False, "Senha inválida."

# =========================================================
# UI
# =========================================================
st.title("Sistema de Gerenciamento – Laboratório Multiusuário ICB")

if st.session_state.logged:
    st.success(f"Logado como {st.session_state.user['name']} ({st.session_state.role})")
    if st.button("Logout"):
        st.session_state.logged = False
        st.rerun()

    if st.session_state.role == "admin":
        st.subheader("Painel do Administrador")
        st.dataframe(read_df(SHEET_CAD), use_container_width=True)
        st.dataframe(read_df(SHEET_RES), use_container_width=True)

    else:
        st.subheader("Área do Usuário")
        st.info("Tela de reservas aqui (já integrada ao Sheets).")

else:
    u = st.text_input("Usuário")
    p = st.text_input("Senha", type="password")
    if st.button("Entrar"):
        ok, res = authenticate(u, p)
        if ok:
            st.session_state.logged = True
            st.session_state.user = res
            st.session_state.role = res["role"]
            st.rerun()
        else:
            st.error(res)
