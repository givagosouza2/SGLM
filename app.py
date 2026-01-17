import streamlit as st
import pandas as pd
import gspread
import os, base64, hashlib, hmac
from datetime import datetime
import uuid

# =========================
# CONFIG
# =========================
st.set_page_config(page_title="Laboratório Multiusuário ICB", layout="wide")

SHEET_USERS = "users"
SHEET_CAD = "cadastro_requests"
SHEET_RES = "reservas"

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"  # troque depois do primeiro login
DEFAULT_ADMIN_NAME = "Administrador"
DEFAULT_ADMIN_EMAIL = "admin@icb.ufpa.br"


# =========================
# HASH DE SENHA
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
# GOOGLE SHEETS (conn)
# =========================
@st.cache_resource
def gsheet_client():
    return gspread.service_account_from_dict(st.secrets["GSERVICE"])

@st.cache_resource
def spreadsheet():
    return gsheet_client().open_by_key(st.secrets["GSHEET_SPREADSHEET_ID"])

def ws(name: str):
    return spreadsheet().worksheet(name)

def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds")

def new_id():
    return f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"

# =========================
# SHEETS helpers
# =========================
def ensure_headers(sheet_name: str, header: list[str]):
    w = ws(sheet_name)
    values = w.get_all_values()
    if not values:
        w.append_row(header, value_input_option="USER_ENTERED")
        return
    current = values[0]
    if current != header:
        # não sobrescreve automaticamente para não destruir dados
        # apenas alerta
        st.warning(f"A aba '{sheet_name}' tem cabeçalho diferente do esperado. Verifique a linha 1.")
        # segue assim mesmo

def read_df(sheet_name: str) -> pd.DataFrame:
    w = ws(sheet_name)
    values = w.get_all_values()
    if not values:
        return pd.DataFrame()
    header = values[0]
    rows = values[1:]
    if not rows:
        return pd.DataFrame(columns=header)
    return pd.DataFrame(rows, columns=header).fillna("")

def append_row_dict(sheet_name: str, row_dict: dict):
    w = ws(sheet_name)
    header = w.row_values(1)
    row = [str(row_dict.get(col, "")) for col in header]
    w.append_row(row, value_input_option="USER_ENTERED")

def find_row_index_by_id(sheet_name: str, id_value: str) -> int | None:
    w = ws(sheet_name)
    values = w.get_all_values()
    if not values:
        return None
    header = values[0]
    if "id" not in header:
        return None
    id_col = header.index("id")
    # procura em memória para reduzir chamadas
    for i, row in enumerate(values[1:], start=2):  # linhas na planilha começam em 1; dados em 2
        if len(row) > id_col and row[id_col] == id_value:
            return i
    return None

def update_row_by_id(sheet_name: str, id_value: str, updates: dict) -> bool:
    w = ws(sheet_name)
    values = w.get_all_values()
    if not values:
        return False
    header = values[0]
    row_i = find_row_index_by_id(sheet_name, id_value)
    if row_i is None:
        return False
    for k, v in updates.items():
        if k in header:
            col_i = header.index(k) + 1
            w.update_cell(row_i, col_i, str(v))
    return True

def delete_row_by_id(sheet_name: str, id_value: str) -> bool:
    w = ws(sheet_name)
    row_i = find_row_index_by_id(sheet_name, id_value)
    if row_i is None:
        return False
    w.delete_rows(row_i)
    return True


# =========================
# "DB" functions
# =========================
USERS_HEADER = ["username", "name", "email", "role", "password_hash", "created_at"]
CAD_HEADER = ["id", "username", "name", "email", "lab", "password_hash", "status", "created_at", "reviewed_at", "reviewed_by"]
RES_HEADER = ["id", "name", "username", "equipment", "date", "time", "status", "created_at", "reviewed_at", "reviewed_by"]

def init_sheets():
    ensure_headers(SHEET_USERS, USERS_HEADER)
    ensure_headers(SHEET_CAD, CAD_HEADER)
    ensure_headers(SHEET_RES, RES_HEADER)

def users_get(username: str) -> dict | None:
    df = read_df(SHEET_USERS)
    if df.empty:
        return None
    if "username" not in df.columns:
        return None
    m = df["username"].astype(str).str.lower() == username.lower()
    if not m.any():
        return None
    return df[m].iloc[0].to_dict()

def users_exists(username: str) -> bool:
    return users_get(username) is not None

def users_insert(username: str, name: str, email: str, role: str, password_hash: str):
    append_row_dict(SHEET_USERS, {
        "username": username,
        "name": name,
        "email": email,
        "role": role,
        "password_hash": password_hash,
        "created_at": now_iso(),
    })

def users_has_admin() -> bool:
    df = read_df(SHEET_USERS)
    if df.empty or "role" not in df.columns:
        return False
    return (df["role"].astype(str).str.lower() == "admin").any()

def ensure_default_admin():
    if not users_has_admin():
        if not users_exists(DEFAULT_ADMIN_USERNAME):
            users_insert(
                DEFAULT_ADMIN_USERNAME,
                DEFAULT_ADMIN_NAME,
                DEFAULT_ADMIN_EMAIL,
                "admin",
                hash_password(DEFAULT_ADMIN_PASSWORD)
            )
        else:
            # Se admin existe como user, promove
            df = read_df(SHEET_USERS)
            m = df["username"].astype(str).str.lower() == DEFAULT_ADMIN_USERNAME.lower()
            if m.any():
                # Atualiza role na planilha
                # (precisa achar linha pelo username)
                w = ws(SHEET_USERS)
                values = w.get_all_values()
                header = values[0]
                ucol = header.index("username")
                rcol = header.index("role") + 1
                for i, row in enumerate(values[1:], start=2):
                    if len(row) > ucol and row[ucol].lower() == DEFAULT_ADMIN_USERNAME.lower():
                        w.update_cell(i, rcol, "admin")
                        break

def cadastro_has_pending(username: str) -> bool:
    df = read_df(SHEET_CAD)
    if df.empty:
        return False
    m = (df["username"].astype(str).str.lower() == username.lower()) & (df["status"] == "Pendente")
    return m.any()

def submit_cadastro(name: str, email: str, lab: str, username: str, password: str) -> tuple[bool, str]:
    name = name.strip()
    email = email.strip()
    lab = lab.strip()
    username = username.strip()

    if not name or not email or not lab or not username or not password:
        return False, "Preencha todos os campos."

    if username.lower() == DEFAULT_ADMIN_USERNAME.lower():
        return False, "Este usuário é reservado. Escolha outro."

    if users_exists(username):
        return False, "Esse usuário já está cadastrado."

    if cadastro_has_pending(username):
        return False, "Já existe uma solicitação pendente para este usuário."

    append_row_dict(SHEET_CAD, {
        "id": new_id(),
        "username": username,
        "name": name,
        "email": email,
        "lab": lab,
        "password_hash": hash_password(password),
        "status": "Pendente",
        "created_at": now_iso(),
        "reviewed_at": "",
        "reviewed_by": "",
    })
    return True, "Solicitação enviada ao administrador (status: Pendente)."

def cadastro_list() -> pd.DataFrame:
    return read_df(SHEET_CAD)

def cadastro_approve(req_id: str, admin_user: str) -> tuple[bool, str]:
    df = cadastro_list()
    if df.empty:
        return False, "Solicitação não encontrada."
    m = df["id"].astype(str) == str(req_id)
    if not m.any():
        return False, "Solicitação não encontrada."
    row = df[m].iloc[0].to_dict()
    if row.get("status") != "Pendente":
        return False, "Solicitação já analisada."

    username = row["username"]
    if not users_exists(username):
        users_insert(username, row["name"], row["email"], "user", row["password_hash"])

    update_row_by_id(SHEET_CAD, req_id, {
        "status": "Aprovado",
        "reviewed_at": now_iso(),
        "reviewed_by": admin_user
    })
    return True, f"Cadastro aprovado. Usuário '{username}' liberado."

def cadastro_reject(req_id: str, admin_user: str) -> tuple[bool, str]:
    ok = update_row_by_id(SHEET_CAD, req_id, {
        "status": "Rejeitado",
        "reviewed_at": now_iso(),
        "reviewed_by": admin_user
    })
    return (True, "Solicitação rejeitada.") if ok else (False, "Solicitação não encontrada.")

def cadastro_delete(req_id: str) -> tuple[bool, str]:
    ok = delete_row_by_id(SHEET_CAD, req_id)
    return (True, "Solicitação removida.") if ok else (False, "Solicitação não encontrada.")

def reservas_list() -> pd.DataFrame:
    return read_df(SHEET_RES)

def slot_available(equipment: str, date_str: str, time_str: str) -> bool:
    df = reservas_list()
    if df.empty:
        return True
    m = (
        (df["equipment"] == equipment)
        & (df["date"] == date_str)
        & (df["time"] == time_str)
        & (df["status"].isin(["Pendente", "Confirmado"]))
    )
    return not m.any()

def reserva_submit(name: str, username: str, equipment: str, date_str: str, time_str: str) -> tuple[bool, str]:
    if not equipment:
        return False, "Selecione um equipamento."
    if not slot_available(equipment, date_str, time_str):
        return False, "Este horário já está reservado/pendente para este equipamento."

    append_row_dict(SHEET_RES, {
        "id": new_id(),
        "name": name,
        "username": username,
        "equipment": equipment,
        "date": date_str,
        "time": time_str,
        "status": "Pendente",
        "created_at": now_iso(),
        "reviewed_at": "",
        "reviewed_by": "",
    })
    return True, "Solicitação de reserva enviada (status: Pendente)."

def reserva_approve(res_id: str, admin_user: str) -> tuple[bool, str]:
    df = reservas_list()
    m = df["id"].astype(str) == str(res_id)
    if df.empty or not m.any():
        return False, "Reserva não encontrada."
    row = df[m].iloc[0].to_dict()
    if row.get("status") != "Pendente":
        return False, "Reserva já analisada."

    # Se já existe Confirmado no mesmo slot, rejeita
    m_conf = (
        (df["equipment"] == row["equipment"])
        & (df["date"] == row["date"])
        & (df["time"] == row["time"])
        & (df["status"] == "Confirmado")
    )
    if m_conf.any():
        update_row_by_id(SHEET_RES, res_id, {
            "status": "Rejeitado",
            "reviewed_at": now_iso(),
            "reviewed_by": admin_user
        })
        return True, "Já existia uma reserva Confirmada nesse slot. Esta foi Rejeitada."

    update_row_by_id(SHEET_RES, res_id, {
        "status": "Confirmado",
        "reviewed_at": now_iso(),
        "reviewed_by": admin_user
    })
    return True, "Reserva Confirmada."

def reserva_reject(res_id: str, admin_user: str) -> tuple[bool, str]:
    ok = update_row_by_id(SHEET_RES, res_id, {
        "status": "Rejeitado",
        "reviewed_at": now_iso(),
        "reviewed_by": admin_user
    })
    return (True, "Reserva Rejeitada.") if ok else (False, "Reserva não encontrada.")

def reserva_delete(res_id: str) -> tuple[bool, str]:
    ok = delete_row_by_id(SHEET_RES, res_id)
    return (True, "Reserva removida.") if ok else (False, "Reserva não encontrada.")


# =========================
# CSS (mantido)
# =========================
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
    .page-title { font-size: 64px; font-weight: 800; line-height: 1.05; margin-bottom: 6px; }
    .subtitle { font-size: 34px; font-weight: 400; margin-bottom: 8px; }
    .content-wrap { max-width: 1300px; margin-left: 0; margin-right: auto; }

    div[data-baseweb="tabs"] button[role="tab"] {
        font-size: 40px !important;
        font-weight: 500 !important;
        padding: 0 !important;
        margin-right: 28px !important;
        color: #111 !important;
    }
    div[data-baseweb="tabs"] button[aria-selected="true"] { color: #e53935 !important; }
    div[data-baseweb="tab-highlight"] { background-color: #e53935 !important; height: 4px !important; }
    div[data-baseweb="tabs"] { margin-bottom: 18px; }

    .field-label { font-size: 44px; font-weight: 400; margin-top: 18px; margin-bottom: 10px; color: #111; }

    div[data-testid="stTextInput"] input,
    div[data-testid="stTextInput"] input:focus,
    div[data-testid="stTextInput"] input:active {
        background: #d9d9d9 !important;
        border: 0px solid transparent !important;
        height: 62px !important;
        font-size: 22px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
    }
    div[data-testid="stTextInput"] label { display: none !important; }

    div[data-testid="stDateInput"] label { display:none !important; }
    div[data-testid="stDateInput"] input {
        background: #d9d9d9 !important;
        border: 0 !important;
        height: 62px !important;
        font-size: 22px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
    }

    div[data-testid="stSelectbox"] label { display:none !important; }
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div {
        background: #d9d9d9 !important;
        border: 0 !important;
        min-height: 62px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
        font-size: 22px !important;
    }

    .top-label { font-size: 42px; font-weight: 400; }
    .status-box {
        padding: 14px 18px;
        border-radius: 2px;
        font-size: 44px;
        display:flex;
        align-items:center;
        justify-content:center;
        height: 64px;
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
        font-size: 44px !important;
        padding: 14px 28px !important;
        border-radius: 999px !important;
        border: 6px solid #111 !important;
        background: #fff !important;
    }

    .row-head {
        font-size: 44px;
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
        grid-template-columns: 1.2fr 1.8fr 0.6fr;
        gap: 12px;
        align-items: center;
    }
    .req-grid-5 {
        display: grid;
        grid-template-columns: 1.2fr 1.2fr 0.9fr 0.8fr 0.9fr;
        gap: 12px;
        align-items: center;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# =========================
# INIT SHEETS + ADMIN
# =========================
init_sheets()
ensure_default_admin()

# =========================
# SESSION STATE
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

# datas sincronizadas
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

def status_style(status: str) -> str:
    s = (status or "").lower()
    if s in ("aprovado", "confirmado"):
        return "color:#b9f0b9; font-weight:700;"
    if s == "pendente":
        return "color:#ffdf8a; font-weight:700;"
    if s == "rejeitado":
        return "color:#ff9c9c; font-weight:700;"
    return "font-weight:700;"


# =========================
# HEADER
# =========================
st.markdown('<div class="content-wrap">', unsafe_allow_html=True)
st.markdown(
    '<div class="page-title">Sistema de gerenciamento de uso<br>'
    'do laboratório Multiusuário do ICB</div>',
    unsafe_allow_html=True
)

# =========================
# LOGGED IN
# =========================
def authenticate_user(username: str, password: str):
    u = users_get(username.strip())
    if not u:
        return False, "Usuário ou senha inválidos."
    if verify_password(password, u["password_hash"]):
        return True, {"username": u["username"], "name": u["name"], "role": u["role"], "email": u["email"]}
    return False, "Usuário ou senha inválidos."


if st.session_state.logged_in:
    colL, colR = st.columns([1, 6])
    with colL:
        if st.button("Sair (Logout)"):
            st.session_state.logged_in = False
            st.session_state.user_name = ""
            st.session_state.username = ""
            st.session_state.role = "user"
            st.rerun()

    # ---------------- ADMIN ----------------
    if st.session_state.role == "admin":
        st.markdown('<div class="subtitle">Solicitações ao administrador</div>', unsafe_allow_html=True)
        tab_cad, tab_res = st.tabs(["Cadastro", "Reservas"])

        with tab_cad:
            st.markdown('<div class="row-head">Nome&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Laboratório&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Cadastro</div>', unsafe_allow_html=True)
            df = cadastro_list()
            if df.empty:
                st.info("Nenhuma solicitação de cadastro.")
            else:
                df = df.sort_values("created_at", ascending=False)
                for _, r in df.iterrows():
                    req_id = r["id"]
                    is_pending = (r["status"] == "Pendente")
                    st.markdown(
                        f"""
                        <div class="req-row">
                          <div class="req-grid-3">
                            <div style="font-size:34px;">{r["name"]}</div>
                            <div style="font-size:34px;">{r["lab"]}</div>
                            <div style="font-size:34px; {status_style(r["status"])}">{r["status"]}</div>
                          </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    b1, b2, b3, _ = st.columns([1.6, 1.6, 1.0, 5.8])
                    with b1:
                        if is_pending and st.button("✅ Aprovar", key=f"cad_ap_{req_id}"):
                            ok, msg = cadastro_approve(req_id, st.session_state.username)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with b2:
                        if is_pending and st.button("❌ Rejeitar", key=f"cad_rj_{req_id}"):
                            ok, msg = cadastro_reject(req_id, st.session_state.username)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with b3:
                        if st.button("🗑️", key=f"cad_del_{req_id}"):
                            ok, msg = cadastro_delete(req_id)
                            (st.success if ok else st.error)(msg)
                            st.rerun()

        with tab_res:
            st.markdown('<div class="row-head">Nome&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Equipamento&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Data&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Horário&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Status</div>', unsafe_allow_html=True)
            df = reservas_list()
            if df.empty:
                st.info("Nenhuma solicitação de reserva.")
            else:
                df = df.sort_values("created_at", ascending=False)
                for _, r in df.iterrows():
                    res_id = r["id"]
                    is_pending = (r["status"] == "Pendente")
                    st.markdown(
                        f"""
                        <div class="req-row light">
                          <div class="req-grid-5">
                            <div style="font-size:34px;">{r["name"]}</div>
                            <div style="font-size:34px;">{r["equipment"]}</div>
                            <div style="font-size:34px;">{r["date"]}</div>
                            <div style="font-size:34px;">{r["time"]}</div>
                            <div style="font-size:34px; {status_style(r["status"])}">{r["status"]}</div>
                          </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    c1, c2, c3, _ = st.columns([1.8, 1.8, 1.0, 5.4])
                    with c1:
                        if is_pending and st.button("✅ Confirmar", key=f"res_ok_{res_id}"):
                            ok, msg = reserva_approve(res_id, st.session_state.username)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with c2:
                        if is_pending and st.button("❌ Rejeitar", key=f"res_no_{res_id}"):
                            ok, msg = reserva_reject(res_id, st.session_state.username)
                            (st.success if ok else st.error)(msg)
                            st.rerun()
                    with c3:
                        if st.button("🗑️", key=f"res_del_{res_id}"):
                            ok, msg = reserva_delete(res_id)
                            (st.success if ok else st.error)(msg)
                            st.rerun()

        st.stop()

    # ---------------- USER SCREEN ----------------
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
    available = slot_available(equip, date_str, picked_time)

    st.markdown(
        '<div class="status-box">Disponível</div>' if available else '<div class="status-box bad">Indisponível</div>',
        unsafe_allow_html=True
    )

    st.write("")
    left, mid1, mid2, mid3, right = st.columns([1.6, 1.4, 1.4, 1.4, 2.4])

    with left:
        st.caption("Calendário")
        st.date_input(" ", key="user_date_side", on_change=sync_side_to_top)

    # recalcula com data sincronizada
    date_str = st.session_state.user_date_top.strftime("%d/%m/%y")
    equip = st.session_state.selected_equipment
    available = slot_available(equip, date_str, picked_time)

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
            ok, msg = reserva_submit(
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
    allr = reservas_list()
    if allr.empty:
        st.info("Você ainda não tem solicitações.")
    else:
        mine = allr[allr["username"].astype(str).str.lower() == st.session_state.username.lower()].copy()
        if mine.empty:
            st.info("Você ainda não tem solicitações.")
        else:
            mine = mine.sort_values("created_at", ascending=False)
            st.dataframe(mine[["equipment", "date", "time", "status", "created_at"]], use_container_width=True, hide_index=True)

    st.stop()

# =========================
# LOGIN / CADASTRO (solicitação)
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
    st.markdown('<div class="field-label">Nome completo</div>', unsafe_allow_html=True)
    nome = st.text_input("Nome completo", key="cad_nome")

    st.markdown('<div class="field-label">E-mail</div>', unsafe_allow_html=True)
    email = st.text_input("E-mail", key="cad_email")

    st.markdown('<div class="field-label">Laboratório</div>', unsafe_allow_html=True)
    lab = st.text_input("Laboratório", key="cad_lab")

    st.markdown('<div class="field-label">Usuário</div>', unsafe_allow_html=True)
    novo_usuario = st.text_input("Usuário", key="cad_usuario")

    st.markdown('<div class="field-label">Senha</div>', unsafe_allow_html=True)
    nova_senha = st.text_input("Senha", type="password", key="cad_senha")

    if st.button("Solicitar cadastro →", key="btn_cadastrar"):
        ok, msg = submit_cadastro(nome, email, lab, novo_usuario, nova_senha)
        (st.success if ok else st.error)(msg)

st.markdown("</div>", unsafe_allow_html=True)
