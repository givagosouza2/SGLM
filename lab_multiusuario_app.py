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
    "password": "admin123",   # troque depois no painel do admin
}

# =========================================================
# PASSWORD (hash)
# =========================================================
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
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected = base64.b64decode(hash_b64.encode("utf-8"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(it))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# =========================================================
# GOOGLE SHEETS (scopes + diagnostics)
# =========================================================
@st.cache_resource
def gsheet_client():
    try:
        info = st.secrets["GSERVICE"]
        scopes = [
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ]
        creds = Credentials.from_service_account_info(info, scopes=scopes)
        return gspread.authorize(creds)
    except Exception as e:
        st.error("Falha ao criar credenciais Google (GSERVICE) a partir de Secrets.")
        st.exception(e)
        st.stop()

@st.cache_resource
def spreadsheet():
    sid = st.secrets.get("GSHEET_SPREADSHEET_ID", "").strip()
    if not sid:
        st.error("GSHEET_SPREADSHEET_ID não foi encontrado nos Secrets.")
        st.stop()
    if "docs.google.com" in sid:
        st.error("GSHEET_SPREADSHEET_ID deve ser apenas o ID, não a URL inteira.")
        st.stop()

    try:
        return gsheet_client().open_by_key(sid)
    except SpreadsheetNotFound:
        client_email = st.secrets["GSERVICE"].get("client_email", "(não encontrado)")
        st.error("Não consegui abrir a planilha pelo ID informado (SpreadsheetNotFound).")
        st.markdown(
            f"""
Verifique:
- O ID está correto?
- Você compartilhou a planilha como **Editor** com a service account abaixo?

**Service account:** `{client_email}`
            """
        )
        st.stop()
    except APIError as e:
        st.error("Erro da API do Google ao abrir a planilha.")
        st.code(str(e))
        st.info("Confira se Google Sheets API e Google Drive API estão ativadas no Google Cloud do projeto.")
        st.stop()

def ensure_worksheet(name: str, header: list[str], rows: int = 2000, cols: int = 40):
    sh = spreadsheet()
    try:
        w = sh.worksheet(name)
    except WorksheetNotFound:
        w = sh.add_worksheet(title=name, rows=rows, cols=cols)

    # garante cabeçalho
    try:
        values = w.get_all_values()
    except APIError as e:
        st.error(f"Erro ao ler a aba '{name}'.")
        st.code(str(e))
        st.stop()

    if not values:
        w.append_row(header, value_input_option="USER_ENTERED")
    else:
        if values[0] != header:
            st.warning(f"Cabeçalho da aba '{name}' diferente do esperado. Verifique a linha 1 dessa aba.")
    return w

def ws(name: str):
    return spreadsheet().worksheet(name)

# =========================================================
# SHEETS helpers
# =========================================================
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
    for i, row in enumerate(values[1:], start=2):
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
            c = header.index(k) + 1
            w.update_cell(row_i, c, str(v))
    return True

def delete_row_by_id(sheet_name: str, id_value: str) -> bool:
    w = ws(sheet_name)
    row_i = find_row_index_by_id(sheet_name, id_value)
    if row_i is None:
        return False
    w.delete_rows(row_i)
    return True

def find_row_index_by_value(sheet_name: str, col_name: str, value: str) -> int | None:
    w = ws(sheet_name)
    values = w.get_all_values()
    if not values:
        return None
    header = values[0]
    if col_name not in header:
        return None
    col_i = header.index(col_name)
    target = str(value).strip().lower()
    for r, row in enumerate(values[1:], start=2):
        if len(row) > col_i and str(row[col_i]).strip().lower() == target:
            return r
    return None

def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds")

def new_id():
    return f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"

# =========================================================
# INIT SHEETS + DEFAULT ADMIN
# =========================================================
ensure_worksheet(SHEET_USERS, USERS_HEADER)
ensure_worksheet(SHEET_CAD, CAD_HEADER)
ensure_worksheet(SHEET_RES, RES_HEADER)

def users_get(username: str) -> dict | None:
    df = read_df(SHEET_USERS)
    if df.empty or "username" not in df.columns:
        return None
    m = df["username"].astype(str).str.lower() == username.strip().lower()
    if not m.any():
        return None
    return df[m].iloc[0].to_dict()

def users_has_admin() -> bool:
    df = read_df(SHEET_USERS)
    if df.empty or "role" not in df.columns:
        return False
    return (df["role"].astype(str).str.lower() == "admin").any()

def users_insert(username: str, name: str, email: str, role: str, password_hash: str):
    append_row_dict(SHEET_USERS, {
        "username": username,
        "name": name,
        "email": email,
        "role": role,
        "password_hash": password_hash,
        "created_at": now_iso(),
    })

def ensure_default_admin():
    if not users_has_admin():
        if users_get(DEFAULT_ADMIN["username"]) is None:
            users_insert(
                DEFAULT_ADMIN["username"],
                DEFAULT_ADMIN["name"],
                DEFAULT_ADMIN["email"],
                "admin",
                hash_password(DEFAULT_ADMIN["password"]),
            )
        else:
            # promove se existir
            w = ws(SHEET_USERS)
            values = w.get_all_values()
            header = values[0]
            if "username" in header and "role" in header:
                ucol = header.index("username")
                rcol = header.index("role") + 1
                for i, row in enumerate(values[1:], start=2):
                    if len(row) > ucol and row[ucol].strip().lower() == DEFAULT_ADMIN["username"].lower():
                        w.update_cell(i, rcol, "admin")
                        break

ensure_default_admin()

# =========================================================
# ADMIN password change
# =========================================================
def update_user_password(username: str, new_password_hash: str) -> bool:
    w = ws(SHEET_USERS)
    values = w.get_all_values()
    if not values:
        return False
    header = values[0]
    if "username" not in header or "password_hash" not in header:
        return False
    row_i = find_row_index_by_value(SHEET_USERS, "username", username)
    if row_i is None:
        return False
    col_pass = header.index("password_hash") + 1
    w.update_cell(row_i, col_pass, new_password_hash)
    return True

# =========================================================
# Cadastro requests
# =========================================================
def cadastro_has_pending(username: str) -> bool:
    df = read_df(SHEET_CAD)
    if df.empty:
        return False
    m = (df["username"].astype(str).str.lower() == username.strip().lower()) & (df["status"] == "Pendente")
    return m.any()

def submit_cadastro(name: str, email: str, lab: str, username: str, password: str) -> tuple[bool, str]:
    name, email, lab, username = name.strip(), email.strip(), lab.strip(), username.strip()

    if not name or not email or not lab or not username or not password:
        return False, "Preencha todos os campos."

    if username.lower() == DEFAULT_ADMIN["username"].lower():
        return False, "Usuário reservado. Escolha outro."

    if users_get(username):
        return False, "Esse usuário já foi aprovado e está cadastrado."

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
    m = (df["id"].astype(str) == str(req_id)) if not df.empty and "id" in df.columns else pd.Series([], dtype=bool)
    if df.empty or not m.any():
        return False, "Solicitação não encontrada."
    row = df[m].iloc[0].to_dict()
    if row.get("status") != "Pendente":
        return False, "Solicitação já analisada."

    username = row["username"]
    if users_get(username) is None:
        users_insert(username, row["name"], row["email"], "user", row["password_hash"])

    update_row_by_id(SHEET_CAD, req_id, {
        "status": "Aprovado",
        "reviewed_at": now_iso(),
        "reviewed_by": admin_user,
    })
    return True, f"Cadastro aprovado: {username}"

def cadastro_reject(req_id: str, admin_user: str) -> tuple[bool, str]:
    ok = update_row_by_id(SHEET_CAD, req_id, {
        "status": "Rejeitado",
        "reviewed_at": now_iso(),
        "reviewed_by": admin_user,
    })
    return (True, "Solicitação rejeitada.") if ok else (False, "Solicitação não encontrada.")

def cadastro_delete(req_id: str) -> tuple[bool, str]:
    ok = delete_row_by_id(SHEET_CAD, req_id)
    return (True, "Solicitação removida.") if ok else (False, "Solicitação não encontrada.")

# =========================================================
# Reservas
# =========================================================
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
        return False, "Indisponível: já existe reserva pendente/confirmada nesse slot."

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
    if df.empty or "id" not in df.columns:
        return False, "Reserva não encontrada."
    m = df["id"].astype(str) == str(res_id)
    if not m.any():
        return False, "Reserva não encontrada."

    row = df[m].iloc[0].to_dict()
    if row.get("status") != "Pendente":
        return False, "Reserva já analisada."

    # se já houver Confirmado no mesmo slot, rejeita esta
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
            "reviewed_by": admin_user,
        })
        return True, "Já havia Confirmado nesse slot. Esta foi Rejeitada."

    update_row_by_id(SHEET_RES, res_id, {
        "status": "Confirmado",
        "reviewed_at": now_iso(),
        "reviewed_by": admin_user,
    })
    return True, "Reserva Confirmada."

def reserva_reject(res_id: str, admin_user: str) -> tuple[bool, str]:
    ok = update_row_by_id(SHEET_RES, res_id, {
        "status": "Rejeitado",
        "reviewed_at": now_iso(),
        "reviewed_by": admin_user,
    })
    return (True, "Reserva Rejeitada.") if ok else (False, "Reserva não encontrada.")

def reserva_delete(res_id: str) -> tuple[bool, str]:
    ok = delete_row_by_id(SHEET_RES, res_id)
    return (True, "Reserva removida.") if ok else (False, "Reserva não encontrada.")

# =========================================================
# AUTH
# =========================================================
def authenticate_user(username: str, password: str):
    user = users_get(username.strip())
    if not user:
        return False, "Usuário ou senha inválidos."
    if verify_password(password, user["password_hash"]):
        return True, user
    return False, "Usuário ou senha inválidos."

# =========================================================
# SESSION STATE
# =========================================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = {}
if "selected_equipment" not in st.session_state:
    st.session_state.selected_equipment = "Equipamento 1"

# datas sincronizadas (topo x lateral)
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

# =========================================================
# CSS (UI bonita)
# =========================================================
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1400px; }
    .page-title { font-size: 56px; font-weight: 800; line-height: 1.05; margin-bottom: 8px; }
    .subtitle { font-size: 30px; font-weight: 400; margin-bottom: 10px; }

    div[data-baseweb="tabs"] button[role="tab"] {
        font-size: 34px !important;
        font-weight: 500 !important;
        padding: 0 !important;
        margin-right: 22px !important;
        color: #111 !important;
    }
    div[data-baseweb="tabs"] button[aria-selected="true"] { color: #e53935 !important; }
    div[data-baseweb="tab-highlight"] { background-color: #e53935 !important; height: 4px !important; }

    .field-label { font-size: 28px; font-weight: 400; margin-top: 16px; margin-bottom: 8px; color: #111; }

    div[data-testid="stTextInput"] input,
    div[data-testid="stTextInput"] input:focus,
    div[data-testid="stTextInput"] input:active {
        background: #d9d9d9 !important;
        border: 0px solid transparent !important;
        height: 54px !important;
        font-size: 18px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
    }
    div[data-testid="stTextInput"] label { display: none !important; }

    div[data-testid="stDateInput"] label { display:none !important; }
    div[data-testid="stDateInput"] input {
        background: #d9d9d9 !important;
        border: 0 !important;
        height: 54px !important;
        font-size: 18px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
    }

    div[data-testid="stSelectbox"] label { display:none !important; }
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div {
        background: #d9d9d9 !important;
        border: 0 !important;
        min-height: 54px !important;
        border-radius: 3px !important;
        box-shadow: none !important;
        font-size: 18px !important;
    }

    .top-label { font-size: 28px; font-weight: 400; }
    .status-box {
        padding: 10px 14px;
        border-radius: 2px;
        font-size: 28px;
        display:flex;
        align-items:center;
        justify-content:center;
        height: 56px;
        background: #b9f0b9;
    }
    .status-box.bad { background: #f7b3b3; }

    .equip-card {
        background: #d9d9d9;
        border: 5px solid transparent;
        border-radius: 2px;
        padding: 16px 14px;
        height: 210px;
        display:flex;
        flex-direction:column;
        justify-content:center;
        align-items:center;
        gap: 12px;
        user-select:none;
    }
    .equip-card.selected { border-color: #ff2b2b; }
    .equip-icon { font-size: 72px; line-height: 1; }
    .equip-name { font-size: 24px; font-weight: 400; margin-top: 4px; }

    .reserve-btn button {
        font-size: 30px !important;
        padding: 12px 22px !important;
        border-radius: 999px !important;
        border: 4px solid #111 !important;
        background: #fff !important;
        width: 100% !important;
    }

    .row-head {
        font-size: 28px;
        font-weight: 400;
        margin-top: 10px;
        margin-bottom: 6px;
    }

    .req-row {
        padding: 14px 14px;
        border-radius: 2px;
        margin: 10px 0;
    }

    .mini-btn button {
        padding: 8px 10px !important;
        border-radius: 8px !important;
        border: 2px solid #111 !important;
        background: #fff !important;
        font-size: 18px !important;
        width: 100% !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# =========================================================
# UI helpers
# =========================================================
def equipment_select_card(label: str, icon: str, selected: bool, key_btn: str):
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

def status_badge_style(status: str):
    s = (status or "").lower()
    if s in ("aprovado", "confirmado"):
        return "#2e7d32", "✅"
    if s == "pendente":
        return "#c77800", "⏳"
    if s == "rejeitado":
        return "#b71c1c", "⛔"
    return "#111", "•"

def row_html(bg: str, cells: list[str]) -> str:
    # cells are already HTML-safe simple strings
    inner = "".join([f'<div style="flex:{f}; {style}">{txt}</div>' for (f, style, txt) in cells])
    return f'<div class="req-row" style="background:{bg};"><div style="display:flex; gap:14px; align-items:center; justify-content:space-between;">{inner}</div></div>'

# =========================================================
# HEADER
# =========================================================
st.markdown('<div class="page-title">Sistema de gerenciamento de uso<br>do laboratório Multiusuário do ICB</div>', unsafe_allow_html=True)

# =========================================================
# LOGOUT (if logged)
# =========================================================
if st.session_state.logged_in:
    colA, colB = st.columns([1, 9])
    with colA:
        if st.button("Sair"):
            st.session_state.logged_in = False
            st.session_state.user = {}
            st.rerun()
    with colB:
        u = st.session_state.user
        st.markdown(f"<div class='subtitle'>Logado como <b>{u.get('name','')}</b> ({u.get('role','user')})</div>", unsafe_allow_html=True)

# =========================================================
# MAIN ROUTING
# =========================================================
if not st.session_state.logged_in:
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
                st.session_state.user = payload
                st.rerun()
            else:
                st.error(payload)

        st.caption("Admin padrão (primeiro acesso): usuário `admin` / senha `admin123` (troque no painel).")

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

    st.stop()

# =========================================================
# LOGGED: ADMIN vs USER
# =========================================================
role = str(st.session_state.user.get("role", "user")).lower()

# ---------------- ADMIN PANEL ----------------
if role == "admin":
    st.markdown('<div class="subtitle">Solicitações ao administrador</div>', unsafe_allow_html=True)

    topA, topB = st.columns([3, 2])
    with topA:
        show_only_pending = st.checkbox("Mostrar apenas pendentes", value=True, key="admin_only_pending")
    with topB:
        with st.expander("🔐 Trocar senha do administrador", expanded=False):
            p1 = st.text_input("Senha atual", type="password", key="admin_old_pass")
            p2 = st.text_input("Nova senha", type="password", key="admin_new_pass")
            p3 = st.text_input("Confirmar nova senha", type="password", key="admin_new_pass2")
            if st.button("Atualizar senha", key="btn_admin_change_pass"):
                user = users_get(st.session_state.user.get("username", ""))
                if not user:
                    st.error("Admin não encontrado.")
                elif not verify_password(p1, user["password_hash"]):
                    st.error("Senha atual incorreta.")
                elif len(p2) < 6:
                    st.error("A nova senha deve ter pelo menos 6 caracteres.")
                elif p2 != p3:
                    st.error("A confirmação não confere.")
                else:
                    okp = update_user_password(st.session_state.user["username"], hash_password(p2))
                    if okp:
                        st.success("Senha atualizada com sucesso.")
                    else:
                        st.error("Falha ao atualizar senha.")

    tab_cad, tab_res = st.tabs(["Cadastro", "Reservas"])

    def action_buttons(key_prefix: str, can_act: bool, approve_cb, reject_cb, delete_cb):
        b_ok, b_no, b_del = st.columns([0.9, 0.9, 0.6])
        with b_ok:
            if can_act:
                st.markdown('<div class="mini-btn">', unsafe_allow_html=True)
                if st.button("✅", key=f"{key_prefix}_ok"):
                    approve_cb()
                st.markdown('</div>', unsafe_allow_html=True)
        with b_no:
            if can_act:
                st.markdown('<div class="mini-btn">', unsafe_allow_html=True)
                if st.button("❌", key=f"{key_prefix}_no"):
                    reject_cb()
                st.markdown('</div>', unsafe_allow_html=True)
        with b_del:
            st.markdown('<div class="mini-btn">', unsafe_allow_html=True)
            if st.button("🗑️", key=f"{key_prefix}_del"):
                delete_cb()
            st.markdown('</div>', unsafe_allow_html=True)

    with tab_cad:
        st.markdown('<div class="row-head">Nome&nbsp;&nbsp;&nbsp;&nbsp;Laboratório&nbsp;&nbsp;&nbsp;&nbsp;Status</div>', unsafe_allow_html=True)
        df = cadastro_list()
        if df.empty:
            st.info("Nenhuma solicitação de cadastro.")
        else:
            df = df.sort_values("created_at", ascending=False)
            if show_only_pending and "status" in df.columns:
                df = df[df["status"] == "Pendente"]
            if df.empty:
                st.info("Nenhuma solicitação pendente.")
            else:
                colors = ["#6e84ad", "#b7c5de"]
                for i, r in enumerate(df.to_dict("records")):
                    req_id = r.get("id", "")
                    is_pending = (r.get("status") == "Pendente")
                    bg = colors[i % 2]
                    status_color, status_icon = status_badge_style(r.get("status", ""))

                    left, right = st.columns([7, 2])
                    with left:
                        txt_color = "#ffffff" if bg == "#6e84ad" else "#111111"
                        html = row_html(bg, [
                            (1.2, f"color:{txt_color}; font-size:24px;", r.get("name", "")),
                            (1.2, f"color:{txt_color}; font-size:24px;", r.get("lab", "")),
                            (0.6, f"color:{status_color}; font-size:24px; font-weight:700;", f"{status_icon} {r.get('status','')}"),
                        ])
                        st.markdown(html, unsafe_allow_html=True)

                    with right:
                        def _approve():
                            ok, msg = cadastro_approve(req_id, st.session_state.user["username"])
                            (st.success if ok else st.error)(msg)
                            st.rerun()

                        def _reject():
                            ok, msg = cadastro_reject(req_id, st.session_state.user["username"])
                            (st.success if ok else st.error)(msg)
                            st.rerun()

                        def _delete():
                            ok, msg = cadastro_delete(req_id)
                            (st.success if ok else st.error)(msg)
                            st.rerun()

                        action_buttons(f"cad_{req_id}", is_pending, _approve, _reject, _delete)

    with tab_res:
        st.markdown('<div class="row-head">Nome&nbsp;&nbsp;Equipamento&nbsp;&nbsp;Data&nbsp;&nbsp;Hora&nbsp;&nbsp;Status</div>', unsafe_allow_html=True)
        df = reservas_list()
        if df.empty:
            st.info("Nenhuma solicitação de reserva.")
        else:
            df = df.sort_values("created_at", ascending=False)
            if show_only_pending and "status" in df.columns:
                df = df[df["status"] == "Pendente"]
            if df.empty:
                st.info("Nenhuma solicitação pendente.")
            else:
                colors = ["#b7c5de", "#6e84ad"]
                for i, r in enumerate(df.to_dict("records")):
                    res_id = r.get("id", "")
                    is_pending = (r.get("status") == "Pendente")
                    bg = colors[i % 2]
                    status_color, status_icon = status_badge_style(r.get("status", ""))

                    left, right = st.columns([7, 2])
                    with left:
                        txt_color = "#ffffff" if bg == "#6e84ad" else "#111111"
                        html = row_html(bg, [
                            (1.1, f"color:{txt_color}; font-size:22px;", r.get("name", "")),
                            (1.2, f"color:{txt_color}; font-size:22px;", r.get("equipment", "")),
                            (0.8, f"color:{txt_color}; font-size:22px;", r.get("date", "")),
                            (0.6, f"color:{txt_color}; font-size:22px;", r.get("time", "")),
                            (0.6, f"color:{status_color}; font-size:22px; font-weight:700;", f"{status_icon} {r.get('status','')}"),
                        ])
                        st.markdown(html, unsafe_allow_html=True)

                    with right:
                        def _approve():
                            ok, msg = reserva_approve(res_id, st.session_state.user["username"])
                            (st.success if ok else st.error)(msg)
                            st.rerun()

                        def _reject():
                            ok, msg = reserva_reject(res_id, st.session_state.user["username"])
                            (st.success if ok else st.error)(msg)
                            st.rerun()

                        def _delete():
                            ok, msg = reserva_delete(res_id)
                            (st.success if ok else st.error)(msg)
                            st.rerun()

                        action_buttons(f"res_{res_id}", is_pending, _approve, _reject, _delete)

    st.stop()

# ---------------- USER SCREEN ----------------
# Top row: Data + Horario + Status
c1, c2, c3, c4, c5 = st.columns([1.1, 2.2, 1.1, 2.2, 2.4])

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
left, mid1, mid2, mid3, right = st.columns([1.7, 1.35, 1.35, 1.35, 2.5])

with left:
    st.caption("Calendário")
    st.date_input(" ", key="user_date_side", on_change=sync_side_to_top)

# recalcula após sync
date_str = st.session_state.user_date_top.strftime("%d/%m/%y")
equip = st.session_state.selected_equipment
available = slot_available(equip, date_str, picked_time)

with mid1:
    equipment_select_card("Equipamento 1", "🔬", equip == "Equipamento 1", "sel_eq1")
with mid2:
    equipment_select_card("Equipamento 2", "🧫", equip == "Equipamento 2", "sel_eq2")
with mid3:
    equipment_select_card("Equipamento 3", "🖨️", equip == "Equipamento 3", "sel_eq3")

with right:
    st.write(""); st.write("")
    st.markdown('<div class="reserve-btn">', unsafe_allow_html=True)
    clicked = st.button("Reservar →", key="btn_reservar")
    st.markdown("</div>", unsafe_allow_html=True)

    if clicked:
        ok, msg = reserva_submit(
            name=st.session_state.user.get("name", ""),
            username=st.session_state.user.get("username", ""),
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
    mine = allr[allr["username"].astype(str).str.lower() == st.session_state.user.get("username","").lower()].copy()
    if mine.empty:
        st.info("Você ainda não tem solicitações.")
    else:
        mine = mine.sort_values("created_at", ascending=False)
        st.dataframe(mine[["equipment", "date", "time", "status", "created_at"]], use_container_width=True, hide_index=True)
