import streamlit as st
import pandas as pd
from pathlib import Path
import os, base64, hashlib, hmac
from pandas.errors import EmptyDataError

# =========================
# CONFIG
# =========================
st.set_page_config(page_title="Laboratório Multiusuário ICB", layout="wide")

USERS_CSV = Path("users.csv")
RESERVAS_CSV = Path("reservas.csv")

USERS_COLUMNS = ["username", "name", "email", "role", "password_hash", "created_at"]
RES_COLUMNS = ["date", "time", "equipment", "username", "created_at"]

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
# CSV USERS
# =========================
def ensure_users_file():
    if not USERS_CSV.exists():
        pd.DataFrame(columns=USERS_COLUMNS).to_csv(USERS_CSV, index=False)
        return
    if USERS_CSV.stat().st_size == 0:
        pd.DataFrame(columns=USERS_COLUMNS).to_csv(USERS_CSV, index=False)
        return

    try:
        df = pd.read_csv(USERS_CSV, dtype=str).fillna("")
        changed = False
        for col in USERS_COLUMNS:
            if col not in df.columns:
                df[col] = "user" if col == "role" else ""
                changed = True
        df = df[USERS_COLUMNS]
        if changed:
            df.to_csv(USERS_CSV, index=False)
    except EmptyDataError:
        pd.DataFrame(columns=USERS_COLUMNS).to_csv(USERS_CSV, index=False)

def load_users() -> pd.DataFrame:
    ensure_users_file()
    try:
        df = pd.read_csv(USERS_CSV, dtype=str).fillna("")
    except EmptyDataError:
        df = pd.DataFrame(columns=USERS_COLUMNS)
        df.to_csv(USERS_CSV, index=False)

    if "role" in df.columns and not df.empty:
        df["role"] = df["role"].replace("", "user").str.lower()
        df.loc[~df["role"].isin(["admin", "user"]), "role"] = "user"
    return df

def save_users(df: pd.DataFrame):
    df.to_csv(USERS_CSV, index=False)


# =========================
# PRIMEIRO ADMIN (AUTO)
# =========================
def ensure_default_admin():
    df = load_users()
    has_admin = (df["role"] == "admin").any() if not df.empty else False
    if has_admin:
        return

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
def register_user(name: str, email: str, username: str, password: str) -> tuple[bool, str]:
    df = load_users()

    username = username.strip()
    email = email.strip()
    name = name.strip()

    if not username or not password or not email or not name:
        return False, "Preencha todos os campos."

    if username.lower() == DEFAULT_ADMIN_USERNAME.lower():
        return False, "Este usuário é reservado. Escolha outro nome de usuário."

    if (df["username"].str.lower() == username.lower()).any():
        return False, "Esse usuário já existe. Escolha outro."

    new_row = {
        "username": username,
        "name": name,
        "email": email,
        "role": "user",
        "password_hash": hash_password(password),
        "created_at": pd.Timestamp.now().isoformat(timespec="seconds"),
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    save_users(df)
    return True, "Cadastro realizado com sucesso!"

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
# CSV RESERVAS
# =========================
def ensure_reservas_file():
    if not RESERVAS_CSV.exists():
        pd.DataFrame(columns=RES_COLUMNS).to_csv(RESERVAS_CSV, index=False)
        return
    if RESERVAS_CSV.stat().st_size == 0:
        pd.DataFrame(columns=RES_COLUMNS).to_csv(RESERVAS_CSV, index=False)
        return

    try:
        df = pd.read_csv(RESERVAS_CSV, dtype=str).fillna("")
        changed = False
        for col in RES_COLUMNS:
            if col not in df.columns:
                df[col] = ""
                changed = True
        df = df[RES_COLUMNS]
        if changed:
            df.to_csv(RESERVAS_CSV, index=False)
    except EmptyDataError:
        pd.DataFrame(columns=RES_COLUMNS).to_csv(RESERVAS_CSV, index=False)

def load_reservas() -> pd.DataFrame:
    ensure_reservas_file()
    try:
        df = pd.read_csv(RESERVAS_CSV, dtype=str).fillna("")
    except EmptyDataError:
        df = pd.DataFrame(columns=RES_COLUMNS)
        df.to_csv(RESERVAS_CSV, index=False)
    return df

def save_reservas(df: pd.DataFrame):
    df.to_csv(RESERVAS_CSV, index=False)

def is_slot_available(date_str: str, time_str: str, equipment: str) -> bool:
    df = load_reservas()
    if df.empty:
        return True
    mask = (df["date"] == date_str) & (df["time"] == time_str) & (df["equipment"] == equipment)
    return not mask.any()

def reserve_slot(date_str: str, time_str: str, equipment: str, username: str) -> tuple[bool, str]:
    if not equipment:
        return False, "Selecione um equipamento."

    if not is_slot_available(date_str, time_str, equipment):
        return False, "Este horário já está reservado para este equipamento."

    df = load_reservas()
    new_row = {
        "date": date_str,
        "time": time_str,
        "equipment": equipment,
        "username": username,
        "created_at": pd.Timestamp.now().isoformat(timespec="seconds"),
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    save_reservas(df)
    return True, "Reserva realizada com sucesso!"


# =========================
# ADMIN ACTIONS
# =========================
def set_role(username_target: str, role: str) -> tuple[bool, str]:
    role = role.lower().strip()
    if role not in ["admin", "user"]:
        return False, "Perfil inválido."

    df = load_users()
    mask = df["username"].str.lower() == username_target.lower()
    if not mask.any():
        return False, "Usuário não encontrado."

    if username_target.lower() == st.session_state.username.lower() and role != "admin":
        return False, "Você não pode rebaixar a si mesmo."

    df.loc[mask, "role"] = role
    save_users(df)
    return True, f"Perfil de '{username_target}' atualizado para '{role}'."

def delete_user(username_to_delete: str) -> tuple[bool, str]:
    df = load_users()
    mask = df["username"].str.lower() == username_to_delete.lower()
    if not mask.any():
        return False, "Usuário não encontrado."

    if username_to_delete.lower() == st.session_state.username.lower():
        return False, "Você não pode excluir o próprio usuário."

    if (df.loc[mask, "role"].iloc[0] == "admin") and ((df["role"] == "admin").sum() <= 1):
        return False, "Não é possível excluir o único administrador."

    df = df[~mask].copy()
    save_users(df)
    return True, f"Usuário '{username_to_delete}' excluído."


# =========================
# CSS (LOGIN + USER SCREEN)
# =========================
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
    .page-title { font-size: 64px; font-weight: 800; line-height: 1.05; margin-bottom: 18px; }
    .content-wrap { max-width: 1200px; margin-left: 0; margin-right: auto; }

    div[data-baseweb="tabs"] button[role="tab"] {
        font-size: 40px !important;
        font-weight: 500 !important;
        padding: 0 !important;
        margin-right: 28px !important;
        color: #111 !important;
    }
    div[data-baseweb="tabs"] button[aria-selected="true"] { color: #e53935 !important; }
    div[data-baseweb="tab-highlight"] { background-color: #e53935 !important; height: 4px !important; }
    div[data-baseweb="tabs"] { margin-bottom: 28px; }

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

    div.stButton > button {
        font-size: 34px !important;
        padding: 10px 22px !important;
        border-radius: 999px !important;
        border: 4px solid #111 !important;
        background: #fff !important;
        color: #111 !important;
        margin-top: 18px !important;
    }
    div.stButton > button:hover { background: #f5f5f5 !important; }

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
    </style>
    """,
    unsafe_allow_html=True
)

# =========================
# INIT
# =========================
ensure_default_admin()
ensure_reservas_file()

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
# Só define valor inicial se ainda não existir
if "user_date_top" not in st.session_state:
    st.session_state.user_date_top = pd.Timestamp.today().date()
if "user_date_side" not in st.session_state:
    st.session_state.user_date_side = st.session_state.user_date_top

# =========================
# CALLBACKS de sync
# =========================
def sync_top_to_side():
    # roda quando topo muda
    if st.session_state.user_date_side != st.session_state.user_date_top:
        st.session_state.user_date_side = st.session_state.user_date_top

def sync_side_to_top():
    # roda quando lateral muda
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

# =========================
# PAGE
# =========================
st.markdown('<div class="content-wrap">', unsafe_allow_html=True)
st.markdown(
    '<div class="page-title">Sistema de gerenciamento de uso<br>'
    'do laboratório Multiusuário do ICB</div>',
    unsafe_allow_html=True
)

# =========================
# POST LOGIN
# =========================
if st.session_state.logged_in:
    colL, colR = st.columns([1, 5])
    with colL:
        if st.button("Sair (Logout)"):
            st.session_state.logged_in = False
            st.session_state.user_name = ""
            st.session_state.username = ""
            st.session_state.role = "user"
            st.rerun()

    # ADMIN
    if st.session_state.role == "admin":
        st.subheader("Painel do Administrador")

        dfu = load_users().copy()
        if not dfu.empty:
            st.dataframe(
                dfu[["username", "name", "email", "role", "created_at"]].sort_values("created_at", ascending=False),
                use_container_width=True,
                hide_index=True
            )

        st.markdown("### Promover/Rebaixar")
        u_target = st.text_input("Usuário alvo", key="admin_role_user")
        new_role = st.selectbox("Novo perfil", ["admin", "user"], index=1, key="admin_new_role")
        if st.button("Atualizar perfil", key="btn_update_role"):
            ok, msg = set_role(u_target, new_role)
            (st.success if ok else st.error)(msg)
            if ok:
                st.rerun()

        st.markdown("### Excluir usuário")
        username_del = st.text_input("Usuário a excluir", key="admin_del_user")
        if st.button("Excluir", key="btn_excluir_user"):
            ok, msg = delete_user(username_del)
            (st.success if ok else st.error)(msg)
            if ok:
                st.rerun()

        st.markdown("### Reservas")
        dfr = load_reservas()
        if dfr.empty:
            st.info("Ainda não há reservas.")
        else:
            st.dataframe(dfr.sort_values("created_at", ascending=False), use_container_width=True, hide_index=True)

        st.stop()

    # =========================
    # USER SCREEN (com sync)
    # =========================
    c1, c2, c3, c4, c5 = st.columns([1.1, 2.0, 1.2, 2.2, 3.5])

    with c1:
        st.markdown('<div class="top-label">Data</div>', unsafe_allow_html=True)
    with c2:
        picked_date_top = st.date_input(
            "Data",
            key="user_date_top",
            on_change=sync_top_to_side
        )
    with c3:
        st.markdown('<div class="top-label">Horário</div>', unsafe_allow_html=True)
    with c4:
        times = [f"{h:02d}:00" for h in range(8, 19)]
        picked_time = st.selectbox("Horário", times, index=2, key="user_time")
    with c5:
        st.markdown('<div class="top-label">Status</div>', unsafe_allow_html=True)

    # Data efetiva sempre a do topo (já sincroniza)
    date_str = picked_date_top.strftime("%d/%m/%y")
    equip = st.session_state.selected_equipment
    available = is_slot_available(date_str, picked_time, equip)

    st.markdown(
        '<div class="status-box">Disponível</div>' if available else '<div class="status-box bad">Indisponível</div>',
        unsafe_allow_html=True
    )

    st.write("")

    left, mid1, mid2, mid3, right = st.columns([1.6, 1.4, 1.4, 1.4, 2.4])

    with left:
        st.caption("Calendário")
        picked_date_side = st.date_input(
            " ",
            key="user_date_side",
            on_change=sync_side_to_top
        )

    # (Recalcula com a data sincronizada)
    date_str = st.session_state.user_date_top.strftime("%d/%m/%y")
    equip = st.session_state.selected_equipment
    available = is_slot_available(date_str, picked_time, equip)

    with mid1:
        equipment_block("Equipamento 1", "🔬", equip == "Equipamento 1", "sel_eq1")
    with mid2:
        equipment_block("Equipamento 2", "🧫", equip == "Equipamento 2", "sel_eq2")
    with mid3:
        equipment_block("Equipamento 3", "🖨️", equip == "Equipamento 3", "sel_eq3")

    with right:
        st.write("")
        st.write("")
        st.write("")
        st.markdown('<div class="reserve-btn">', unsafe_allow_html=True)
        clicked = st.button("Reservar →", key="btn_reservar")
        st.markdown("</div>", unsafe_allow_html=True)

        if clicked:
            ok, msg = reserve_slot(date_str, picked_time, st.session_state.selected_equipment, st.session_state.username)
            (st.success if ok else st.error)(msg)
            if ok:
                st.rerun()

    st.markdown("### Minhas reservas")
    dfr = load_reservas()
    mine = dfr[dfr["username"].str.lower() == st.session_state.username.lower()].copy() if not dfr.empty else pd.DataFrame()
    if mine.empty:
        st.info("Você ainda não tem reservas.")
    else:
        st.dataframe(mine.sort_values("created_at", ascending=False), use_container_width=True, hide_index=True)

    st.stop()

# =========================
# LOGIN / CADASTRO
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

    st.markdown('<div class="field-label">Usuário</div>', unsafe_allow_html=True)
    novo_usuario = st.text_input("Usuário", key="cad_usuario")

    st.markdown('<div class="field-label">Senha</div>', unsafe_allow_html=True)
    nova_senha = st.text_input("Senha", type="password", key="cad_senha")

    if st.button("Cadastrar →", key="btn_cadastrar"):
        ok, msg = register_user(nome, email, novo_usuario, nova_senha)
        (st.success if ok else st.error)(msg)

st.markdown("</div>", unsafe_allow_html=True)
