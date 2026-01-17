import streamlit as st
import pandas as pd
from pathlib import Path
import os, base64, hashlib, hmac

# =========================
# CONFIG
# =========================
st.set_page_config(page_title="Laboratório Multiusuário PPGNBC", layout="wide")

USERS_CSV = Path("users.csv")  # pode trocar o caminho aqui

# =========================
# SEGURANÇA (hash de senha)
# =========================
def hash_password(password: str, salt: bytes | None = None, iterations: int = 200_000) -> str:
    """
    Retorna string no formato: pbkdf2_sha256$<iter>$<salt_b64>$<hash_b64>
    """
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
    if not USERS_CSV.exists():
        df = pd.DataFrame(columns=["username", "name", "email", "password_hash", "created_at"])
        df.to_csv(USERS_CSV, index=False)

def load_users() -> pd.DataFrame:
    ensure_users_file()
    df = pd.read_csv(USERS_CSV, dtype=str).fillna("")
    return df

def save_users(df: pd.DataFrame):
    df.to_csv(USERS_CSV, index=False)

def register_user(name: str, email: str, username: str, password: str) -> tuple[bool, str]:
    df = load_users()

    username = username.strip()
    email = email.strip()
    name = name.strip()

    if not username or not password or not email or not name:
        return False, "Preencha todos os campos."

    # checa duplicidade (por username)
    if (df["username"].str.lower() == username.lower()).any():
        return False, "Esse usuário já existe. Escolha outro."

    # adiciona novo registro
    new_row = {
        "username": username,
        "name": name,
        "email": email,
        "password_hash": hash_password(password),
        "created_at": pd.Timestamp.now().isoformat(timespec="seconds"),
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    save_users(df)
    return True, "Cadastro realizado com sucesso!"

def authenticate_user(username: str, password: str) -> tuple[bool, str]:
    df = load_users()
    username = username.strip()

    if not username or not password:
        return False, "Informe usuário e senha."

    # busca usuário (case-insensitive)
    mask = df["username"].str.lower() == username.lower()
    if not mask.any():
        return False, "Usuário ou senha inválidos."

    row = df[mask].iloc[0]
    if verify_password(password, row["password_hash"]):
        return True, row["name"]
    return False, "Usuário ou senha inválidos."

# =========================
# CSS (layout parecido com o print)
# =========================
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
    .page-title { font-size: 64px; font-weight: 800; line-height: 1.05; margin-bottom: 40px; }
    .content-wrap { max-width: 980px; margin-left: 0; margin-right: auto; }

    div[data-baseweb="tabs"] button[role="tab"] {
        font-size: 25px !important;
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
        font-size: 25px !important;
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
# SESSÃO
# =========================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_name" not in st.session_state:
    st.session_state.user_name = ""
if "username" not in st.session_state:
    st.session_state.username = ""

# =========================
# TELA
# =========================
st.markdown('<div class="content-wrap">', unsafe_allow_html=True)

st.markdown(
    '<div class="page-title">Sistema de gerenciamento de uso<br>'
    'do laboratório Multiusuário do ICB</div>',
    unsafe_allow_html=True
)

# Se já estiver logado, mostra painel simples
if st.session_state.logged_in:
    st.success(f"Bem-vindo(a), {st.session_state.user_name}!")
    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("Sair (Logout)"):
            st.session_state.logged_in = False
            st.session_state.user_name = ""
            st.session_state.username = ""
            st.rerun()

    st.info("Aqui entra o seu sistema (agendamentos, equipamentos, permissões, etc.).")
    st.stop()

tab_login, tab_cadastro = st.tabs(["Login", "Cadastro"])

with tab_login:
    st.markdown('<div class="field-label">Usuário</div>', unsafe_allow_html=True)
    usuario = st.text_input("Usuário", key="login_usuario")

    st.markdown('<div class="field-label">Senha</div>', unsafe_allow_html=True)
    senha = st.text_input("Senha", type="password", key="login_senha")

    if st.button("Entrar →", key="btn_entrar"):
        ok, msg = authenticate_user(usuario, senha)
        if ok:
            st.session_state.logged_in = True
            st.session_state.user_name = msg
            st.session_state.username = usuario
            st.rerun()
        else:
            st.error(msg)

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
        if ok:
            st.success(msg)
        else:
            st.error(msg)

st.markdown("</div>", unsafe_allow_html=True)
