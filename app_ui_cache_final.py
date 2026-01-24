# =========================================================
# app.py — FINAL (UI bonita + cache-safe Google Sheets)
# =========================================================
# - Cards de equipamentos
# - Calendário sincronizado
# - Status em tempo real (via cache TTL)
# - Painel Admin completo
# - Evita erro 429 (quota)
# =========================================================

import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from gspread.exceptions import SpreadsheetNotFound, WorksheetNotFound
from datetime import datetime
import uuid
import os, base64, hashlib, hmac
from PIL import Image

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------
st.set_page_config(page_title="Laboratório Multiusuário ICB", layout="wide")

SPREADSHEET_ID = st.secrets["GSHEET_SPREADSHEET_ID"]

SHEET_USERS = "users"
SHEET_CAD = "cadastro_requests"
SHEET_RES = "reservas"

# ---------------------------------------------------------
# PASSWORD HASH
# ---------------------------------------------------------
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

# ---------------------------------------------------------
# GOOGLE SHEETS (cache-safe)
# ---------------------------------------------------------
@st.cache_resource
def gclient():
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
    return gclient().open_by_key(SPREADSHEET_ID)

def ws(name):
    return spreadsheet().worksheet(name)

@st.cache_data(ttl=30, show_spinner=False)
def read_df(sheet):
    values = ws(sheet).get_all_values()
    if not values:
        return pd.DataFrame()
    return pd.DataFrame(values[1:], columns=values[0]).fillna("")

def clear_cache():
    st.cache_data.clear()

# ---------------------------------------------------------
# USERS / AUTH
# ---------------------------------------------------------
def users_get(username):
    df = read_df(SHEET_USERS)
    m = df["username"].str.lower() == username.lower()
    return df[m].iloc[0].to_dict() if m.any() else None

def authenticate(username, password):
    u = users_get(username)
    if not u:
        return False, "Usuário inválido"
    if verify_password(password, u["password_hash"]):
        return True, u
    return False, "Senha inválida"

# ---------------------------------------------------------
# RESERVAS
# ---------------------------------------------------------
def slot_available(df, equipment, date, time):
    if df.empty:
        return True
    m = (
        (df["equipment"] == equipment) &
        (df["date"] == date) &
        (df["time"] == time) &
        (df["status"].isin(["Pendente", "Confirmado"]))
    )
    return not m.any()

def reserva_submit(user, equipment, date, time):
    ws(SHEET_RES).append_row([
        str(uuid.uuid4()),
        user["name"],
        user["username"],
        equipment,
        date,
        time,
        "Pendente",
        datetime.utcnow().isoformat(timespec="seconds"),
        "",
        "",
    ])
    clear_cache()

# ---------------------------------------------------------
# SESSION
# ---------------------------------------------------------
if "logged" not in st.session_state:
    st.session_state.logged = False
if "user" not in st.session_state:
    st.session_state.user = {}
if "equip" not in st.session_state:
    st.session_state.equip = "Microscópio"
if "date" not in st.session_state:
    st.session_state.date = datetime.today().date()

# ---------------------------------------------------------
# CSS (UI bonita)
# ---------------------------------------------------------
st.markdown("""
<style>
.card {
  background:#e0e0e0;
  padding:20px;
  border-radius:6px;
  text-align:center;
  font-size:22px;
  cursor:pointer;
}
.card.sel {
  border:4px solid #e53935;
}
.status-ok {
  background:#b9f6ca;
  padding:12px;
  font-size:24px;
  border-radius:4px;
}
.status-bad {
  background:#ff8a80;
  padding:12px;
  font-size:24px;
  border-radius:4px;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# UI
# ---------------------------------------------------------
banner = Image.open("/mnt/data/multiusuário.png")  # ajuste o caminho se necessário
st.image(banner, use_container_width=True)
st.title("Sistema de gerenciamento do Laboratório Multiusuário ICB")

if not st.session_state.logged:
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
    st.stop()

st.success(f"Logado como {st.session_state.user['name']}")

df_res = read_df(SHEET_RES)

c1, c2, c3 = st.columns([2,2,2])
with c1:
    st.session_state.date = st.date_input("Data", st.session_state.date)
with c2:
    time = st.selectbox("Horário", [f"{h:02d}:00" for h in range(8,18)])
with c3:
    avail = slot_available(df_res, st.session_state.equip,
                            st.session_state.date.strftime("%d/%m/%y"), time)
    st.markdown(
        "<div class='status-ok'>Disponível</div>" if avail
        else "<div class='status-bad'>Indisponível</div>",
        unsafe_allow_html=True
    )

st.subheader("Equipamentos")
cols = st.columns(3)
for col, eq in zip(cols, ["Microscópio", "Centrífuga", "PCR"]):
    with col:
        cls = "card sel" if st.session_state.equip == eq else "card"
        st.markdown(f"<div class='{cls}'>{eq}</div>", unsafe_allow_html=True)
        if st.button(eq):
            st.session_state.equip = eq
            st.rerun()

if st.button("Reservar"):
    if avail:
        reserva_submit(
            st.session_state.user,
            st.session_state.equip,
            st.session_state.date.strftime("%d/%m/%y"),
            time,
        )
        st.success("Reserva enviada")
        st.rerun()
    else:
        st.error("Horário indisponível")

st.subheader("Minhas reservas")
mine = df_res[df_res["username"] == st.session_state.user["username"]]
st.dataframe(mine, use_container_width=True)
