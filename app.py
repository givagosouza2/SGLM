import streamlit as st
import pandas as pd
from pathlib import Path
import os, base64, hashlib, hmac
from pandas.errors import EmptyDataError
from datetime import date

# =========================
# CONFIG
# =========================
st.set_page_config(page_title="Laboratório Multiusuário ICB", layout="wide")

USERS_CSV = Path("users.csv")
CADASTRO_REQ_CSV = Path("cadastro_requests.csv")
RESERVAS_CSV = Path("reservas.csv")

USERS_COLUMNS = ["username", "name", "email", "role", "password_hash", "created_at"]

# Solicitações de cadastro (pendente -> aprovado/rejeitado)
CAD_REQ_COLUMNS = ["username", "name", "email", "lab", "password_hash", "status", "created_at", "reviewed_at", "reviewed_by"]

# Solicitações de reserva (pendente -> confirmado/rejeitado)
RES_COLUMNS = ["name", "username", "equipment", "date", "time", "status", "created_at", "reviewed_at", "reviewed_by"]

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"  # troque depois do primeiro login
DEFAULT_ADMIN_NAME = "Administrador"
DEFAULT_ADMIN_EMAIL = "admin@icb.ufpa.br"

# =========================
# SEGURANÇA (hash de senha)
# =========================
def hash_password(password: str, salt: bytes | None = None, iterations: int = 200_000) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(dk).decode("utf-8"),
    )

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, it, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(it)
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected = base64.b64decode(hash_b64.encode("utf-8"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# =========================
# CSV HELPERS
# =========================
def _ensure_csv(path: Path, cols: list[str]):
    if not path.exists() or path.stat().st_size == 0:
        pd.DataFrame(columns=cols).to_csv(path, index=False)
        return
    try:
        df = pd.read_csv(path, dtype=str).fillna("")
        changed = False
        for c in cols:
            if c not in df.columns:
                df[c] = ""
                changed = True
        df = df[cols]
        if changed:
            df.to_csv(path, index=False)
    except EmptyDataError:
        pd.DataFrame(columns=cols).to_csv(path, index=False)

def _load_csv(path: Path, cols: list[str]) -> pd.DataFrame:
    _ensure_csv(path, cols)
    try:
        df = pd.read_csv(path, dtype=str).fillna("")
    except EmptyDataError:
        df = pd.DataFrame(columns=cols)
        df.to_csv(path, index=False)
    # garante ordem
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols]

def _save_csv(path: Path, df: pd.DataFrame):
    df.to_csv(path, index=False)

# =========================
# USERS
# =========================
def load_users() -> pd.DataFrame:
    df = _load_csv(USERS_CSV, USERS_COLUMNS)
    if not df.empty:
        df["role"] = df["role"].replace("", "user").str.lower()
        df.loc[~df["role"].isin(["admin", "user"]), "role"] = "user"
    return df

def save_users(df: pd.DataFrame):
    _save_csv(USERS_CSV, df[USERS_COLUMNS])

# =========================
# PRIMEIRO ADMIN (AUTO)
# =========================
def ensure_default_admin():
    df = load_users()
    if not df.empty and (df["role"] == "admin").any():
        return

    # se existir "admin", promove
    if not df.empty and (df["username"].str.lower() == DEFAULT_ADMIN_USERNAME.lower()).any():
        idx = df[df["username"].str.lower() == DEFAULT_ADMIN_USERNAME.lower()].index[0]
        df.at[idx, "role"] = "admin"
        if not df.at[idx, "password_hash"]:
            df.at[idx, "password_hash"] = hash_password(DEFAULT_ADMIN_PASSWORD)
        if not df.at[idx, "name"]:
            df.at[idx, "name"] = DEFAULT_ADMIN_NAME
        if not df.at[idx, "email"]:
            df.at[idx, "email"] = DEFAULT_ADMIN_EMAIL
        if not df.at[idx, "created_at"]:
            df.at[idx, "created_at"] = pd.Timestamp.now().isoformat(timespec="seconds")
        save_users(df)
        return

    new_row = {
        "username": DEFAULT_ADMIN_USERNAME,
        "name": DEFAULT_ADMIN_NAME,
        "email": DEFAULT_ADMIN_EMAIL,
        "role": "admin",
        "password_hash": hash_password(DEFAULT_ADMIN_PASSWORD),
        "created_at": pd.Timestamp.now().isoformat(timespec="seconds"),
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    save_users(df)

# =========================
# AUTH
# =========================
def authenticate_user(username: str, password: str) -> tuple[bool, dict | str]:
    df = load_users()
    username = username.strip()
    if not username or not password:
        return False, "Informe usuário e senha."

    mask = df["username"].str.lower() == username.lower()
    if not mask.any():
        return False, "Usuário ou senha inválidos."

    row = df[mask].iloc[0]
    if verify_password(password, row["password_hash"]):
        return True, {
            "username": row["username"],
            "name": row["name"],
            "role": row.get("role", "user"),
            "email": row.get("email", ""),
        }
    return False, "Usuário ou senha inválidos."

# =========================
# CADASTRO REQUESTS
# =========================
def load_cadastro_requests() -> pd.DataFrame:
    df = _load_csv(CADASTRO_REQ_CSV, CAD_REQ_COLUMNS)
    if not df.empty:
        df["status"] = df["status"].replace("", "Pendente")
    return df

def save_cadastro_requests(df: pd.DataFrame):
    _save_csv(CADASTRO_REQ_CSV, df[CAD_REQ_COLUMNS])

def submit_cadastro_request(name: str, email: str, lab: str, username: str, password: str) -> tuple[bool, str]:
    name = name.strip()
    email = email.strip()
    lab = lab.strip()
    username = username.strip()

    if not name or not email or not lab or not username or not password:
        return False, "Preencha todos os campos."

    if username.lower() == DEFAULT_ADMIN_USERNAME.lower():
        return False, "Este usuário é reservado. Escolha outro."

    users = load_users()
    if not users.empty and (users["username"].str.lower() == username.lower()).any():
        return False, "Esse usuário já está cadastrado."

    req = load_cadastro_requests()
    # já existe solicitação aberta?
    if not req.empty:
        mask = req["username"].str.lower() == username.lower()
        if mask.any() and (req.loc[mask, "status"].iloc[-1] == "Pendente"):
            return False, "Já existe uma solicitação pendente para este usuário."

    new_row = {
        "username": username,
        "name": name,
        "email": email,
        "lab": lab,
        "password_hash": hash_password(password),
        "status": "Pendente",
        "created_at": pd.Timestamp.now().isoformat(timespec="seconds"),
        "reviewed_at": "",
        "reviewed_by": "",
    }
    req = pd.concat([req, pd.DataFrame([new_row])], ignore_index=True)
    save_cadastro_requests(req)
    return True, "Solicitação enviada ao administrador (status: Pendente)."

def approve_cadastro_request(row_idx: int, admin_user: str) -> tuple[bool, str]:
    req = load_cadastro_requests()
    if row_idx < 0 or row_idx >= len(req):
        return False, "Solicitação inválida."

    if req.at[row_idx, "status"] != "Pendente":
        return False, "Esta solicitação já foi analisada."

    username = req.at[row_idx, "username"]
    users = load_users()
    if not users.empty and (users["username"].str.lower() == username.lower()).any():
        # Marca como aprovado, mas não duplica
        req.at[row_idx, "status"] = "Aprovado"
        req.at[row_idx, "reviewed_at"] = pd.Timestamp.now().isoformat(timespec="seconds")
        req.at[row_idx, "reviewed_by"] = admin_user
        save_cadastro_requests(req)
        return True, "Solicitação aprovada (usuário já existia no sistema)."

    new_user = {
        "username": req.at[row_idx, "username"],
        "name": req.at[row_idx, "name"],
        "email": req.at[row_idx, "email"],
        "role": "user",
        "password_hash": req.at[row_idx, "password_hash"],
        "created_at": pd.Timestamp.now().isoformat(timespec="seconds"),
    }
    users = pd.concat([users, pd.DataFrame([new_user])], ignore_index=True)
    save_users(users)

    req.at[row_idx, "status"] = "Aprovado"
    req.at[row_idx, "reviewed_at"] = pd.Timestamp.now().isoformat(timespec="seconds")
    req.at[row_idx, "reviewed_by"] = admin_user
    save_cadastro_requests(req)
    return True, f"Cadastro aprovado e usuário '{username}' criado."

def reject_cadastro_request(row_idx: int, admin_user: str) -> tuple[bool, str]:
    req = load_cadastro_requests()
    if row_idx < 0 or row_idx >= len(req):
        return False, "Solicitação inválida."
    if req.at[row_idx, "status"] != "Pendente":
        return False, "Esta solicitação já foi analisada."

    req.at[row_idx, "status"] = "Rejeitado"
    req.at[row_idx, "reviewed_at"] = pd.Timestamp.now().isoformat(timespec="seconds")
    req.at[row_idx, "reviewed_by"] = admin_user
    save_cadastro_requests(req)
    return True, "Solicitação rejeitada."

def delete_cadastro_request(row_idx: int) -> tuple[bool, str]:
    req = load_cadastro_requests()
    if row_idx < 0 or row_idx >= len(req):
        return False, "Solicitação inválida."
    req = req.drop(req.index[row_idx]).reset_index(drop=True)
    save_cadastro_requests(req)
    return True, "Solicitação removida."

# =========================
# RESERVAS (REQUESTS)
# =========================
def load_reservas() -> pd.DataFrame:
    df = _load_csv(RESERVAS_CSV, RES_COLUMNS)
    if not df.empty:
        df["status"] = df["status"].replace("", "Pendente")
    return df

def save_reservas(df: pd.DataFrame):
    _save_csv(RESERVAS_CSV, df[RES_COLUMNS])

def slot_is_available(date_str: str, time_str: str, equipment: str) -> bool:
    df = load_reservas()
    if df.empty:
        return True
    # Bloqueia se existir Pendente OU Confirmado para o mesmo slot/equip
    mask = (df["date"] == date_str) & (df["time"] == time_str) & (df["equipment"] == equipment) & (df["status"].isin(["Pendente", "Confirmado"]))
    return not mask.any()

def submit_reserva_request(name: str, username: str, equipment: str, date_str: str, time_str: str) -> tuple[bool, str]:
    if not equipment:
        return False, "Selecione um equipamento."

    if not slot_is_available(date_str, time_str, equipment):
        return False, "Este horário já está reservado/pendente para este equipamento."

    df = load_reservas()
    new_row = {
        "name": name,
        "username": username,
        "equipment": equipment,
        "date": date_str,
        "time": time_str,
        "status": "Pendente",
        "created_at": pd.Timestamp.now().isoformat(timespec="seconds"),
        "reviewed_at": "",
        "reviewed_by": "",
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    save_reservas(df)
    return True, "Solicitação de reserva enviada (status: Pendente)."

def approve_reserva(row_idx: int, admin_user: str) -> tuple[bool, str]:
    df = load_reservas()
    if row_idx < 0 or row_idx >= len(df):
        return False, "Reserva inválida."
    if df.at[row_idx, "status"] != "Pendente":
        return False, "Esta solicitação já foi analisada."

    # Checa se ficou indisponível por outra confirmação
    d = df.at[row_idx, "date"]
    t = df.at[row_idx, "time"]
    eq = df.at[row_idx, "equipment"]

    # Se já existe Confirmado no slot, rejeita automaticamente
    mask_conf = (df["date"] == d) & (df["time"] == t) & (df["equipment"] == eq) & (df["status"] == "Confirmado")
    if mask_conf.any():
        df.at[row_idx, "status"] = "Rejeitado"
        df.at[row_idx, "reviewed_at"] = pd.Timestamp.now().isoformat(timespec="seconds")
        df.at[row_idx, "reviewed_by"] = admin_user
        save_reservas(df)
        return True, "Já existia uma reserva Confirmada nesse slot. Esta foi Rejeitada."

    df.at[row_idx, "status"] = "Confirmado"
    df.at[row_idx, "reviewed_at"] = pd.Timestamp.now().isoformat(timespec="seconds")
    df.at[row_idx, "reviewed_by"] = admin_user
    save_reservas(df)
    return True, "Reserva Confirmada."

def reject_reserva(row_idx: int, admin_user: str) -> tuple[bool, str]:
    df = load_reservas()
    if row_idx < 0 or row_idx >= len(df):
        return False, "Reserva inválida."
    if df.at[row_idx, "status"] != "Pendente":
        return False, "Esta solicitação já foi analisada."

    df.at[row_idx, "status"] = "Rejeitado"
    df.at[row_idx, "reviewed_at"] = pd.Timestamp.now().isoformat(timespec="seconds")
    df.at[row_idx, "reviewed_by"] = admin_user
    save_reservas(df)
    return True, "Reserva Rejeitada."

def delete_reserva(row_idx: int) -> tuple[bool, str]:
    df = load_reservas()
    if row_idx < 0 or row_idx >= len(df):
        return False, "Reserva inválida."
    df = df.drop(df.index[row_idx]).reset_index(drop=True)
    save_reservas(df)
    return True, "Reserva removida."

# =========================
# CSS (parecido com seus mocks)
# =========================
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
    .page-title { font-size: 50px; font-weight: 800; line-height: 1.05; margin-bottom: 6px; }
    .subtitle { font-size: 20px; font-weight: 400; margin-bottom: 8px; }
    .content-wrap { max-width: 1300px; margin-left: 0; margin-right: auto; }

    div[data-baseweb="tabs"] button[role="tab"] {
        font-size: 25px !important;
        font-weight: 500 !important;
        padding: 0 !important;
        margin-right: 28px !important;
        color: #111 !important;
    }
    div[data-baseweb="tabs"] button[aria-selected="true"] { color: #e53935 !important; }
    div[data-baseweb="tab-highlight"] { background-color: #e53935 !important; height: 4px !important; }
    div[data-baseweb="tabs"] { margin-bottom: 18px; }

    .field-label { font-size: 20px; font-weight: 400; margin-top: 18px; margin-bottom: 2px; color: #111; }

    div[data-testid="stTextInput"] input,
    div[data-testid="stTextInput"] input:focus,
    div[data-testid="stTextInput"] input:active {
        background: #d9d9d9 !important;
        border: 0px solid transparent !important;
        height: 40px !important;
        font-size: 20px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
    }
    div[data-testid="stTextInput"] label { display: none !important; }

    div[data-testid="stDateInput"] label { display:none !important; }
    div[data-testid="stDateInput"] input {
        background: #d9d9d9 !important;
        border: 0 !important;
        height: 40px !important;
        font-size: 20px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
    }

    div[data-testid="stSelectbox"] label { display:none !important; }
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div {
        background: #d9d9d9 !important;
        border: 0 !important;
        min-height: 40px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
        font-size: 20px !important;
    }

    /* USER SCREEN */
    .top-label { font-size: 42px; font-weight: 400; }
    .status-box {
        padding: 14px 18px;
        border-radius: 2px;
        font-size: 20px;
        display:flex;
        align-items:center;
        justify-content:center;
        height: 30px;
        background: #b9f0b9;
    }
    .status-box.bad { background: #f7b3b3; }

    .equip-card {
        background: #d9d9d9;
        border: 6px solid transparent;
        border-radius: 2px;
        padding: 18px 16px;
        height: 240px;
        display:flex;
        flex-direction:column;
        justify-content:center;
        align-items:center;
        gap: 14px;
        user-select:none;
    }
    .equip-card.selected { border-color: #ff2b2b; }
    .equip-icon { font-size: 96px; line-height: 1; }
    .equip-name { font-size: 34px; font-weight: 400; margin-top: 6px; }

    .reserve-btn button {
        font-size: 20px !important;
        padding: 14px 28px !important;
        border-radius: 999px !important;
        border: 6px solid #111 !important;
        background: #fff !important;
    }

    /* ADMIN LIST (rows) */
    .row-head {
        font-size: 20px;
        font-weight: 400;
        margin-top: 10px;
        margin-bottom: 6px;
    }
    .req-row {
        background: #6e84ad;
        color: #ffffff;
        padding: 18px 18px;
        border-radius: 2px;
        margin: 10px 0;
    }
    .req-row.light {
        background: #b7c5de;
        color: #111111;
    }
    .req-grid-3 {
        display: grid;
        grid-template-columns: 1.2fr 1.8fr 0.6fr 0.2fr;
        gap: 12px;
        align-items: center;
    }
    .req-grid-5 {
        display: grid;
        grid-template-columns: 1.2fr 1.2fr 0.9fr 0.8fr 0.9fr;
        gap: 12px;
        align-items: center;
    }
    .stButton > button {
        border-radius: 999px !important;
        border: 4px solid #111 !important;
        background: #fff !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# =========================
# INIT
# =========================
ensure_default_admin()
_ensure_csv(CADASTRO_REQ_CSV, CAD_REQ_COLUMNS)
_ensure_csv(RESERVAS_CSV, RES_COLUMNS)

# =========================
# SESSION DEFAULTS
# =========================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_name" not in st.session_state:
    st.session_state.user_name = ""
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = "user"
if "selected_equipment" not in st.session_state:
    st.session_state.selected_equipment = "Equipamento 1"

# Datas sincronizadas (duas keys diferentes)
if "user_date_top" not in st.session_state:
    st.session_state.user_date_top = pd.Timestamp.today().date()
if "user_date_side" not in st.session_state:
    st.session_state.user_date_side = st.session_state.user_date_top

def sync_top_to_side():
    if st.session_state.user_date_side != st.session_state.user_date_top:
        st.session_state.user_date_side = st.session_state.user_date_top

def sync_side_to_top():
    if st.session_state.user_date_top != st.session_state.user_date_side:
        st.session_state.user_date_top = st.session_state.user_date_side

# =========================
# UI HELPERS
# =========================
def equipment_block(label: str, icon: str, selected: bool, key_btn: str):
    cls = "equip-card selected" if selected else "equip-card"
    st.markdown(
        f"""
        <div class="{cls}">
            <div class="equip-icon">{icon}</div>
            <div class="equip-name">{label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button(label, key=key_btn):
        st.session_state.selected_equipment = label
        st.rerun()

def status_text_color(status: str) -> str:
    s = (status or "").lower()
    if s == "aprovado" or s == "confirmado":
        return "color: #b9f0b9; font-weight:600;"
    if s == "pendente":
        return "color: #ff9c9c; font-weight:600;"
    if s == "rejeitado":
        return "color: #ff9c9c; font-weight:600;"
    return "font-weight:600;"

# =========================
# PAGE HEADER
# =========================
st.markdown('<div class="content-wrap">', unsafe_allow_html=True)
st.markdown(
    '<div class="page-title">Sistema de gerenciamento de uso<br>'
    'do laboratório Multiusuário do ICB</div>',
    unsafe_allow_html=True
)

# =========================
# LOGGED IN AREA
# =========================
if st.session_state.logged_in:
    colL, colR = st.columns([1, 6])
    with colL:
        if st.button("Sair (Logout)"):
            st.session_state.logged_in = False
            st.session_state.user_name = ""
            st.session_state.username = ""
            st.session_state.role = "user"
            st.rerun()

    # -------------------------
    # ADMIN VIEW (como os mocks)
    # -------------------------
    if st.session_state.role == "admin":
        st.markdown('<div class="subtitle">Solicitações ao administrador</div>', unsafe_allow_html=True)
        tab_cad, tab_res = st.tabs(["Cadastro", "Reservas"])

        # ======= TAB CADASTRO =======
        with tab_cad:
            st.markdown('<div class="row-head">Nome&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Laboratório&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Cadastro</div>', unsafe_allow_html=True)
            req = load_cadastro_requests().copy()
            if req.empty:
                st.info("Nenhuma solicitação de cadastro.")
            else:
                # mais recentes primeiro
                req = req.sort_values("created_at", ascending=False).reset_index(drop=True)

                for i, r in req.iterrows():
                    is_pending = (r["status"] == "Pendente")
                    row_class = "req-row" if (i % 2 == 0) else "req-row light"

                    st.markdown(
                        f"""
                        <div class="{row_class}">
                          <div class="req-grid-3">
                            <div style="font-size:34px;">{r["name"]}</div>
                            <div style="font-size:34px;">{r["lab"]}</div>
                            <div style="font-size:34px; {status_text_color(r["status"])}">{r["status"]}</div>
                            <div></div>
                          </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                    b1, b2, b3, b4 = st.columns([1.6, 1.6, 1.2, 5.6])
                    with b1:
                        if is_pending and st.button("✅ Aprovar", key=f"cad_ap_{i}"):
                            ok, msg = approve_cadastro_request(i, st.session_state.username)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with b2:
                        if is_pending and st.button("❌ Rejeitar", key=f"cad_rj_{i}"):
                            ok, msg = reject_cadastro_request(i, st.session_state.username)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with b3:
                        if st.button("🗑️", key=f"cad_del_{i}"):
                            ok, msg = delete_cadastro_request(i)
                            (st.success if ok else st.error)(msg)
                            st.rerun()

        # ======= TAB RESERVAS =======
        with tab_res:
            st.markdown('<div class="row-head">Nome&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Equipamento&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Data&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Horário&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Status</div>', unsafe_allow_html=True)
            res = load_reservas().copy()
            if res.empty:
                st.info("Nenhuma solicitação de reserva.")
            else:
                res = res.sort_values("created_at", ascending=False).reset_index(drop=True)
                for i, r in res.iterrows():
                    is_pending = (r["status"] == "Pendente")
                    row_class = "req-row" if (i % 2 == 0) else "req-row light"
                    st.markdown(
                        f"""
                        <div class="{row_class}">
                          <div class="req-grid-5">
                            <div style="font-size:34px;">{r["name"]}</div>
                            <div style="font-size:34px;">{r["equipment"]}</div>
                            <div style="font-size:34px;">{r["date"]}</div>
                            <div style="font-size:34px;">{r["time"]}</div>
                            <div style="font-size:34px; {status_text_color(r["status"])}">{r["status"]}</div>
                          </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                    c1, c2, c3, c4 = st.columns([1.8, 1.8, 1.0, 5.4])
                    with c1:
                        if is_pending and st.button("✅ Confirmar", key=f"res_ok_{i}"):
                            ok, msg = approve_reserva(i, st.session_state.username)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with c2:
                        if is_pending and st.button("❌ Rejeitar", key=f"res_no_{i}"):
                            ok, msg = reject_reserva(i, st.session_state.username)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with c3:
                        if st.button("🗑️", key=f"res_del_{i}"):
                            ok, msg = delete_reserva(i)
                            (st.success if ok else st.error)(msg)
                            st.rerun()

        st.stop()

    # -------------------------
    # USER SCREEN (solicita reserva pendente)
    # -------------------------
    c1, c2, c3, c4, c5 = st.columns([1.1, 2.0, 1.2, 2.2, 3.5])

    with c1:
        st.markdown('<div class="top-label">Data</div>', unsafe_allow_html=True)
    with c2:
        st.date_input("Data", key="user_date_top", on_change=sync_top_to_side)
    with c3:
        st.markdown('<div class="top-label">Horário</div>', unsafe_allow_html=True)
    with c4:
        times = [f"{h:02d}:00" for h in range(8, 19)]
        picked_time = st.selectbox("Horário", times, index=2, key="user_time")
    with c5:
        st.markdown('<div class="top-label">Status</div>', unsafe_allow_html=True)

    date_str = st.session_state.user_date_top.strftime("%d/%m/%y")
    equip = st.session_state.selected_equipment
    available = slot_is_available(date_str, picked_time, equip)

    st.markdown(
        '<div class="status-box">Disponível</div>' if available else '<div class="status-box bad">Indisponível</div>',
        unsafe_allow_html=True
    )

    st.write("")
    left, mid1, mid2, mid3, right = st.columns([1.6, 1.4, 1.4, 1.4, 2.4])

    with left:
        st.caption("Calendário")
        st.date_input(" ", key="user_date_side", on_change=sync_side_to_top)

    # recomputa com data sincronizada
    date_str = st.session_state.user_date_top.strftime("%d/%m/%y")
    equip = st.session_state.selected_equipment
    available = slot_is_available(date_str, picked_time, equip)

    with mid1:
        equipment_block("Equipamento 1", "🔬", equip == "Equipamento 1", "sel_eq1")
    with mid2:
        equipment_block("Equipamento 2", "🧫", equip == "Equipamento 2", "sel_eq2")
    with mid3:
        equipment_block("Equipamento 3", "🖨️", equip == "Equipamento 3", "sel_eq3")

    with right:
        st.write(""); st.write(""); st.write("")
        st.markdown('<div class="reserve-btn">', unsafe_allow_html=True)
        clicked = st.button("Reservar →", key="btn_reservar")
        st.markdown("</div>", unsafe_allow_html=True)

        if clicked:
            ok, msg = submit_reserva_request(
                name=st.session_state.user_name,
                username=st.session_state.username,
                equipment=st.session_state.selected_equipment,
                date_str=date_str,
                time_str=picked_time
            )
            (st.success if ok else st.error)(msg)
            if ok:
                st.rerun()

    st.markdown("### Minhas reservas")
    allr = load_reservas()
    mine = allr[allr["username"].str.lower() == st.session_state.username.lower()].copy() if not allr.empty else pd.DataFrame()
    if mine.empty:
        st.info("Você ainda não tem solicitações de reserva.")
    else:
        mine = mine.sort_values("created_at", ascending=False)
        st.dataframe(mine[["equipment", "date", "time", "status", "created_at"]], use_container_width=True, hide_index=True)

    st.stop()

# =========================
# LOGIN / CADASTRO (agora é solicitação)
# =========================
tab_login, tab_cadastro = st.tabs(["Login", "Cadastro"])

with tab_login:
    st.markdown('<div class="field-label">Usuário</div>', unsafe_allow_html=True)
    usuario = st.text_input("Usuário", key="login_usuario")

    st.markdown('<div class="field-label">Senha</div>', unsafe_allow_html=True)
    senha = st.text_input("Senha", type="password", key="login_senha")

    if st.button("Entrar →", key="btn_entrar"):
        ok, payload = authenticate_user(usuario, senha)
        if ok:
            st.session_state.logged_in = True
            st.session_state.user_name = payload["name"]
            st.session_state.username = payload["username"]
            st.session_state.role = payload["role"]
            st.rerun()
        else:
            st.error(payload)

with tab_cadastro:
    coluna1,coluna2 = st.columns(2)
    with coluna1:
        st.markdown('<div class="field-label">Nome completo</div>', unsafe_allow_html=True)
        nome = st.text_input("Nome completo", key="cad_nome")
    
        st.markdown('<div class="field-label">E-mail</div>', unsafe_allow_html=True)
        email = st.text_input("E-mail", key="cad_email")
    
        st.markdown('<div class="field-label">Laboratório</div>', unsafe_allow_html=True)
        lab = st.text_input("Laboratório", key="cad_lab")

    with coluna2: 
        st.markdown('<div class="field-label">Usuário</div>', unsafe_allow_html=True)
        novo_usuario = st.text_input("Usuário", key="cad_usuario")
    
        st.markdown('<div class="field-label">Senha</div>', unsafe_allow_html=True)
        nova_senha = st.text_input("Senha", type="password", key="cad_senha")

        st.text("")
        st.text("")
    
        if st.button("Solicitar cadastro →", key="btn_cadastrar"):
            ok, msg = submit_cadastro_request(nome, email, lab, novo_usuario, nova_senha)
            (st.success if ok else st.error)(msg)

st.markdown("</div>", unsafe_allow_html=True)
