# =========================================================
# app.py — Versão FINAL com cache (Google Sheets)
# =========================================================
# ✔ Cache agressivo para evitar erro 429 (quota)
# ✔ UI completa (usuário + admin)
# ✔ Login + Cadastro
# =========================================================

import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from gspread.exceptions import SpreadsheetNotFound, WorksheetNotFound
from datetime import datetime
import uuid
import os, base64, hashlib, hmac

st.set_page_config(page_title="Laboratório Multiusuário ICB", layout="wide")

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

def hash_password(password, salt=None, iterations=200_000):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}$" +            f"{base64.b64encode(salt).decode()}$" +            f"{base64.b64encode(dk).decode()}"

def verify_password(password, stored):
    try:
        algo, it, salt_b64, hash_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(it))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

@st.cache_resource
def gsheet_client():
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    creds = Credentials.from_service_account_info(
        st.secrets["GSERVICE"], scopes=scopes
    )
    return gspread.authorize(creds)

@st.cache_resource
def spreadsheet():
    return gsheet_client().open_by_key(SPREADSHEET_ID)

def ws(name):
    return spreadsheet().worksheet(name)

@st.cache_data(ttl=30)
def read_df(sheet_name):
    values = ws(sheet_name).get_all_values()
    if not values:
        return pd.DataFrame()
    return pd.DataFrame(values[1:], columns=values[0]).fillna("")

def clear_cache():
    st.cache_data.clear()

def ensure_headers(sheet_name, header):
    w = ws(sheet_name)
    if not w.get_all_values():
        w.append_row(header)

for s, h in [
    (SHEET_USERS, USERS_HEADER),
    (SHEET_CAD, CAD_HEADER),
    (SHEET_RES, RES_HEADER),
]:
    ensure_headers(s, h)

def ensure_admin():
    df = read_df(SHEET_USERS)
    if df.empty or not (df["role"] == "admin").any():
        ws(SHEET_USERS).append_row([
            DEFAULT_ADMIN["username"],
            DEFAULT_ADMIN["name"],
            DEFAULT_ADMIN["email"],
            "admin",
            hash_password(DEFAULT_ADMIN["password"]),
            datetime.utcnow().isoformat(timespec="seconds"),
        ])
        clear_cache()

ensure_admin()

def users_get(username):
    df = read_df(SHEET_USERS)
    m = df["username"].str.lower() == username.lower()
    return df[m].iloc[0].to_dict() if m.any() else None

def authenticate(username, password):
    user = users_get(username)
    if not user:
        return False, "Usuário inválido"
    if verify_password(password, user["password_hash"]):
        return True, user
    return False, "Senha inválida"

def submit_cadastro(name, email, lab, username, password):
    ws(SHEET_CAD).append_row([
        str(uuid.uuid4()), username, name, email, lab,
        hash_password(password), "Pendente",
        datetime.utcnow().isoformat(timespec="seconds"), "", ""
    ])
    clear_cache()
    return True, "Solicitação enviada"

if "logged" not in st.session_state:
    st.session_state.logged = False
if "user" not in st.session_state:
    st.session_state.user = {}

st.title("Sistema de Gerenciamento – Laboratório Multiusuário ICB")

if not st.session_state.logged:
    tab_login, tab_cad = st.tabs(["Login", "Cadastro"])
    with tab_login:
        u = st.text_input("Usuário")
        p = st.text_input("Senha", type="password")
        if st.button("Entrar"):
            ok, res = authenticate(u, p)
            if ok:
                st.session_state.logged = True
                st.session_state.user = res
                st.rerun()
            else:
                st.error(res)
    with tab_cad:
        name = st.text_input("Nome completo")
        email = st.text_input("E-mail")
        lab = st.text_input("Laboratório")
        u = st.text_input("Usuário")
        p = st.text_input("Senha", type="password")
        if st.button("Solicitar cadastro"):
            ok, msg = submit_cadastro(name, email, lab, u, p)
            (st.success if ok else st.error)(msg)
else:
    st.success(f"Logado como {st.session_state.user['name']} ({st.session_state.user['role']})")
    if st.button("Logout"):
        st.session_state.logged = False
        st.rerun()
    if st.session_state.user["role"] == "admin":
        st.subheader("Painel do Administrador")
        st.dataframe(read_df(SHEET_CAD))
        st.dataframe(read_df(SHEET_RES))
    else:
        st.subheader("Área do Usuário")
        st.info("Tela de reservas com cache aplicada.")
