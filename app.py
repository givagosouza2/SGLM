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
COLUMNS = ["username", "name", "email", "role", "password_hash", "created_at"]

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
# CSV (carregar / salvar)
# =========================
def ensure_users_file():
    # Cria se não existir
    if not USERS_CSV.exists():
        pd.DataFrame(columns=COLUMNS).to_csv(USERS_CSV, index=False)
        return

    # Se existir vazio (0 bytes)
    if USERS_CSV.stat().st_size == 0:
        pd.DataFrame(columns=COLUMNS).to_csv(USERS_CSV, index=False)
        return

    # Migração simples: adiciona colunas faltantes (role default user)
    try:
        df = pd.read_csv(USERS_CSV, dtype=str).fillna("")
        changed = False
        for col in COLUMNS:
            if col not in df.columns:
                df[col] = "user" if col == "role" else ""
                changed = True
        df = df[COLUMNS]
        if changed:
            df.to_csv(USERS_CSV, index=False)
    except EmptyDataError:
        pd.DataFrame(columns=COLUMNS).to_csv(USERS_CSV, index=False)

def load_users() -> pd.DataFrame:
    ensure_users_file()
    try:
        df = pd.read_csv(USERS_CSV, dtype=str).fillna("")
    except EmptyDataError:
        df = pd.DataFrame(columns=COLUMNS)
        df.to_csv(USERS_CSV, index=False)

    # Normaliza role
    if "role" in df.columns:
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

    # Se já existir usuário 'admin' como user, promove. Senão cria do zero.
    mask_admin_user = (df["username"].str.lower() == DEFAULT_ADMIN_USERNAME.lower()) if not df.empty else pd.Series([], dtype=bool)
    if not df.empty and mask_admin_user.any():
        idx = df[mask_admin_user].index[0]
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

    # bloqueia cadastro com username 'admin' (reservado)
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

    # impede rebaixar a si mesmo (opcional)
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

    # impede apagar a si mesmo (opcional)
    if username_to_delete.lower() == st.session_state.username.lower():
        return False, "Você não pode excluir o próprio usuário."

    # impede apagar o admin padrão se for o único admin
    if (df.loc[mask, "role"].iloc[0] == "admin") and ((df["role"] == "admin").sum() <= 1):
        return False, "Não é possível excluir o único administrador."

    df = df[~mask].copy()
    save_users(df)
    return True, f"Usuário '{username_to_delete}' excluído."

# =========================
# CSS (layout)
# =========================
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
    .page-title { font-size: 64px; font-weight: 800; line-height: 1.05; margin-bottom: 40px; }
    .content-wrap { max-width: 980px; margin-left: 0; margin-right: auto; }

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
    </style>
    """,
    unsafe_allow_html=True
)

# =========================
# GARANTE ADMIN PADRÃO
# =========================
ensure_default_admin()

# =========================
# SESSÃO
# =========================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_name" not in st.session_state:
    st.session_state.user_name = ""
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = "user"

# =========================
# UI
# =========================
st.markdown('<div class="content-wrap">', unsafe_allow_html=True)

st.markdown(
    '<div class="page-title">Sistema de gerenciamento de uso<br>'
    'do laboratório Multiusuário do ICB</div>',
    unsafe_allow_html=True
)

# -------------------------
# PÓS-LOGIN
# -------------------------
if st.session_state.logged_in:
    st.success(f"Bem-vindo(a), {st.session_state.user_name}  •  Perfil: {st.session_state.role}")

    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("Sair (Logout)"):
            st.session_state.logged_in = False
            st.session_state.user_name = ""
            st.session_state.username = ""
            st.session_state.role = "user"
            st.rerun()

    if st.session_state.role == "admin":
        st.subheader("Painel do Administrador")

        st.warning(
            f"Admin padrão (se for o primeiro uso): usuário **{DEFAULT_ADMIN_USERNAME}** / senha **{DEFAULT_ADMIN_PASSWORD}**. "
            "Troque a senha assim que possível."
        )

        df = load_users().copy()
        if not df.empty:
            view = df[["username", "name", "email", "role", "created_at"]].sort_values("created_at", ascending=False)
            st.dataframe(view, use_container_width=True, hide_index=True)
        else:
            st.info("Ainda não há usuários cadastrados.")

        st.markdown("### Alterar perfil (promover/rebaixar)")
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

    else:
        st.subheader("Área do Usuário")
        st.info("Aqui entra o sistema para usuários (solicitar uso, ver agenda, registrar equipamento, etc.).")

    st.stop()

# -------------------------
# LOGIN / CADASTRO
# -------------------------
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
