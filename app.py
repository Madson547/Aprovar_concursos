"""
Aprova Militar — banco de questões comentadas do CFS PMMS.
ARQUIVO ÚNICO: suba no GitHub só este app.py e o requirements.txt.

No Streamlit Cloud, em Settings > Secrets, cole:
    DATABASE_URL = "postgresql://...-pooler.../neondb?sslmode=require"

Para rodar no próprio computador (opcional):
    pip install -r requirements.txt
    crie .streamlit/secrets.toml com a mesma linha DATABASE_URL
    streamlit run app.py
"""
import base64
import html
import json
import random
import re
import secrets
import string
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import bcrypt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


# ======================================================================
# DB
# ======================================================================
@st.cache_resource(show_spinner=False)
def _pool() -> ConnectionPool:
    return ConnectionPool(
        conninfo=st.secrets["DATABASE_URL"],
        min_size=1,
        max_size=5,
        kwargs={"autocommit": True, "row_factory": dict_row},
        check=ConnectionPool.check_connection,
        open=True,
    )


def consultar(sql: str, params=None) -> list[dict]:
    """SELECT que devolve várias linhas (lista de dicionários)."""
    with _pool().connection() as conn:
        return conn.execute(sql, params or ()).fetchall()


def um(sql: str, params=None) -> dict | None:
    """SELECT que devolve uma linha (ou None)."""
    with _pool().connection() as conn:
        return conn.execute(sql, params or ()).fetchone()


def executar(sql: str, params=None) -> None:
    """INSERT / UPDATE / DELETE."""
    with _pool().connection() as conn:
        conn.execute(sql, params or ())


def transacao(fn):
    """Roda fn(conn) numa transação só: ou grava tudo, ou nada."""
    with _pool().connection() as conn:
        with conn.transaction():
            return fn(conn)

db = SimpleNamespace(consultar=consultar, um=um, executar=executar, transacao=transacao)


# ======================================================================
# AUTH
# ======================================================================
MAX_TENTATIVAS = 5
MINUTOS_BLOQUEIO = 15
PERFIS = {"admin": "Administrador", "revisor": "Revisor", "aluno": "Aluno"}


# ------------------------------------------------------------------ senhas
def gerar_hash(senha: str) -> str:
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def confere(senha: str, hash_salvo: str | None) -> bool:
    if not hash_salvo:
        return False
    try:
        return bcrypt.checkpw(senha.encode("utf-8"), hash_salvo.encode("utf-8"))
    except ValueError:
        return False


def problema_na_senha(senha: str) -> str | None:
    """Devolve o motivo se a senha for fraca; None se estiver boa."""
    if len(senha) < 8:
        return "A senha precisa ter pelo menos 8 caracteres."
    if not re.search(r"[A-Za-z]", senha) or not re.search(r"\d", senha):
        return "A senha precisa ter letras e números."
    return None


def senha_provisoria() -> str:
    """Ex.: CFS-7k4m-29qx — fácil de ditar, difícil de adivinhar."""
    alfabeto = string.ascii_lowercase.replace("l", "").replace("o", "") + "23456789"
    bloco = lambda: "".join(secrets.choice(alfabeto) for _ in range(4))
    return f"CFS-{bloco()}-{bloco()}"


def normalizar_login(login: str) -> str:
    return login.strip().lower()


# ------------------------------------------------------------------ registro
def registrar(evento: str, usuario_id=None, login_tentado=None) -> None:
    db.executar(
        "INSERT INTO acesso_log (usuario_id, login_tentado, evento) VALUES (%s, %s, %s)",
        (usuario_id, login_tentado, evento),
    )


# ------------------------------------------------------------------ login
def existe_admin() -> bool:
    return db.um("SELECT 1 AS ok FROM usuario WHERE perfil = 'admin' AND ativo LIMIT 1") is not None


def autenticar(login: str, senha: str) -> tuple[dict | None, str | None]:
    """Devolve (usuario, None) se der certo ou (None, mensagem de erro)."""
    login = normalizar_login(login)
    u = db.um(
        """SELECT id, nome, login, perfil, ativo, trocar_senha, senha_hash, tentativas_falhas,
                  bloqueado_ate, (bloqueado_ate IS NOT NULL AND bloqueado_ate > now()) AS bloqueado,
                  CEIL(EXTRACT(EPOCH FROM (bloqueado_ate - now())) / 60) AS minutos_restantes
           FROM usuario WHERE lower(login) = %s""",
        (login,),
    )
    generico = "Usuário ou senha incorretos."
    if u is None:
        registrar("login_falha", login_tentado=login)
        return None, generico
    if not u["ativo"]:
        registrar("login_conta_inativa", u["id"], login)
        return None, "Esta conta está desativada. Fale com o administrador."
    if u["bloqueado"]:
        return None, f"Conta bloqueada por excesso de tentativas. Tente de novo em {int(u['minutos_restantes'])} min."

    if not confere(senha, u["senha_hash"]):
        tentativas = u["tentativas_falhas"] + 1
        if tentativas >= MAX_TENTATIVAS:
            db.executar(
                "UPDATE usuario SET tentativas_falhas = 0, bloqueado_ate = now() + make_interval(mins => %s) WHERE id = %s",
                (MINUTOS_BLOQUEIO, u["id"]),
            )
            registrar("bloqueio", u["id"], login)
            return None, f"Senha incorreta pela {MAX_TENTATIVAS}ª vez. Conta bloqueada por {MINUTOS_BLOQUEIO} minutos."
        db.executar("UPDATE usuario SET tentativas_falhas = %s WHERE id = %s", (tentativas, u["id"]))
        registrar("login_falha", u["id"], login)
        restantes = MAX_TENTATIVAS - tentativas
        return None, f"{generico} Restam {restantes} tentativa{'s' if restantes > 1 else ''} antes do bloqueio."

    db.executar(
        "UPDATE usuario SET tentativas_falhas = 0, bloqueado_ate = NULL, ultimo_acesso = now() WHERE id = %s",
        (u["id"],),
    )
    registrar("login_ok", u["id"], login)
    return _sessao(u), None


def _sessao(u: dict) -> dict:
    """Só o que a sessão precisa guardar (nunca o hash)."""
    return {k: u[k] for k in ("id", "nome", "login", "perfil", "trocar_senha")}


def recarregar(usuario_id: int) -> dict | None:
    u = db.um(
        "SELECT id, nome, login, perfil, trocar_senha, ativo FROM usuario WHERE id = %s", (usuario_id,)
    )
    return _sessao(u) if u and u["ativo"] else None


# ------------------------------------------------------------------ contas
def criar_usuario(nome: str, login: str, perfil: str, senha: str, trocar: bool = True) -> int:
    row = db.um(
        """INSERT INTO usuario (nome, login, perfil, senha_hash, trocar_senha, ativo)
           VALUES (%s, %s, %s, %s, %s, TRUE) RETURNING id""",
        (nome.strip(), normalizar_login(login), perfil, gerar_hash(senha), trocar),
    )
    return row["id"]


def login_existe(login: str) -> bool:
    return db.um("SELECT 1 AS ok FROM usuario WHERE lower(login) = %s", (normalizar_login(login),)) is not None


def definir_senha(usuario_id: int, senha: str, provisoria: bool) -> None:
    db.executar(
        """UPDATE usuario SET senha_hash = %s, trocar_senha = %s, tentativas_falhas = 0, bloqueado_ate = NULL
           WHERE id = %s""",
        (gerar_hash(senha), provisoria, usuario_id),
    )
    if provisoria:      # senha nova dada pelo administrador: derruba os logins salvos nos aparelhos
        db.executar("DELETE FROM sessao_login WHERE usuario_id = %s", (usuario_id,))
    registrar("senha_resetada" if provisoria else "senha_trocada", usuario_id)


def senha_atual_confere(usuario_id: int, senha: str) -> bool:
    u = db.um("SELECT senha_hash FROM usuario WHERE id = %s", (usuario_id,))
    return bool(u) and confere(senha, u["senha_hash"])

auth = SimpleNamespace(MAX_TENTATIVAS=MAX_TENTATIVAS, MINUTOS_BLOQUEIO=MINUTOS_BLOQUEIO, PERFIS=PERFIS, gerar_hash=gerar_hash, confere=confere, problema_na_senha=problema_na_senha, senha_provisoria=senha_provisoria, normalizar_login=normalizar_login, registrar=registrar, existe_admin=existe_admin, autenticar=autenticar, recarregar=recarregar, criar_usuario=criar_usuario, login_existe=login_existe, definir_senha=definir_senha, senha_atual_confere=senha_atual_confere)


# ======================================================================
# ESTILO
# ======================================================================
NOME_APP = "Aprova Militar"
SUBTITULO = "CFS PMMS · Banco de questões comentadas"

CSS = """
<style>
:root{--verde:#4B5A23;--verde-claro:#E2E7D2;--ok:#1F6B3A;--ok-bg:#DCEFE1;--erro:#A3322A;--erro-bg:#F6DEDB;
      --lei:#F2F1E8;--linha:#D4D9CE;--texto-suave:#5B6559;--bronze:#8A6A1F}
.cartao{position:relative;border:1px solid var(--linha);border-radius:10px;padding:18px 20px;margin:4px 0 12px;
        background-repeat:repeat;background-size:320px 120px;-webkit-user-select:none;user-select:none}
.cartao .topo{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px;font-size:.82rem;color:var(--texto-suave);margin-bottom:8px}
.cartao .cod{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--verde);font-weight:600}
.cartao .enun{font-size:1.05rem;font-weight:500;line-height:1.55;margin:0;white-space:pre-line}
.cartao .coment{white-space:pre-line}
.cartao .fonte{font-size:.78rem;color:var(--texto-suave);margin:0 0 6px}
.etq{display:inline-block;font-size:.72rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;border-radius:999px;padding:1px 8px;margin-left:6px}
.etq.lei{background:var(--verde-claro);color:var(--verde)} .etq.caso{background:#F5E8C8;color:#8A5A00}
.etq.rev{background:#E8E2F4;color:#4B3A7A} .etq.port{background:#DCEBF7;color:#1F4E79} .etq.prova{background:#FBE3E3;color:#8B1E1E} .etq.acervo{background:#ECE6DA;color:#6B5320}
.etq.ess{background:#FBF1D6;color:#8A6A1F}
.alt{border:1px solid var(--linha);border-radius:8px;padding:9px 12px;margin:6px 0;line-height:1.5}
.alt.certa{border-color:var(--ok);background:var(--ok-bg)} .alt.errada{border-color:var(--erro);background:var(--erro-bg)}
.alt .why{display:block;font-size:.88rem;color:var(--texto-suave);margin-top:4px}
.dica{background:var(--verde-claro);border-radius:6px;padding:8px 12px;margin:8px 0}
.lei-txt{background:var(--lei);border-radius:6px;padding:8px 12px;font-family:Georgia,'Times New Roman',serif;font-size:.93rem;margin:4px 0}
.lei-txt .ref{display:block;font-family:ui-monospace,Menlo,monospace;font-size:.72rem;color:var(--texto-suave)}
button[kind="primary"],button[kind="primaryFormSubmit"]{background:#4B5A23!important;border-color:#4B5A23!important;color:#fff!important}
.rotulo{font-size:.75rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--bronze);margin:10px 0 2px}
.mapa{display:flex;flex-wrap:wrap;gap:4px;margin:2px 0 10px}
.mq{min-width:28px;text-align:center;font-size:.74rem;border:1px solid var(--linha);border-radius:5px;padding:2px 0;color:var(--texto-suave)}
.mq.ok{background:var(--verde-claro);color:var(--verde);border-color:var(--verde);font-weight:600}
.mq.certa{background:var(--ok-bg);color:var(--ok);border-color:var(--ok);font-weight:600}
.mq.errada{background:var(--erro-bg);color:var(--erro);border-color:var(--erro);font-weight:600}
.mq.atual{outline:2px solid var(--bronze);outline-offset:1px;font-weight:700}
.rx-grupo{margin:10px 0 12px}
.rx-cab{display:flex;align-items:center;gap:7px;font-weight:700;font-size:.95rem;margin-bottom:5px}
.rx-pop{font-weight:400;color:var(--texto-suave);font-size:.85rem}
.rx-res{margin-left:auto;font-weight:600;font-size:.82rem;color:var(--texto-suave)}
.rx-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:6px}
.rx-chip{border-radius:8px;padding:6px 9px;border:1px solid var(--linha);display:flex;flex-direction:column;gap:2px;font-size:.8rem;line-height:1.3}
.rx-chip .rx-num{font-weight:700;font-size:.78rem}
.rx-num{color:var(--texto-suave);font-size:.8rem;margin-left:4px}
.rx-dot{display:inline-block;width:10px;height:10px;border-radius:50%;vertical-align:middle;flex:none}
.rx-leg{font-size:.75rem;color:var(--texto-suave);margin:4px 0 8px}
.rx-leg .rx-dot{margin:0 3px 0 6px}
.rx-chip.rx-vermelho{background:var(--erro-bg);border-color:var(--erro)} .rx-chip.rx-vermelho .rx-num{color:var(--erro)}
.rx-chip.rx-amarelo{background:#FBF1D6;border-color:#D9A21B} .rx-chip.rx-amarelo .rx-num{color:#8A6A1F}
.rx-chip.rx-verde{background:var(--ok-bg);border-color:var(--ok)} .rx-chip.rx-verde .rx-num{color:var(--ok)}
.rx-chip.rx-cinza{background:rgba(128,128,128,.08)} .rx-chip.rx-branco{opacity:.65}
.rx-dot.rx-vermelho{background:var(--erro)} .rx-dot.rx-amarelo{background:#D9A21B} .rx-dot.rx-verde{background:var(--ok)}
.rx-dot.rx-cinza{background:#9E9E9E} .rx-dot.rx-branco{background:transparent;border:1px solid #9E9E9E}
@media (prefers-color-scheme: dark){
 :root{--verde:#B5C77A;--verde-claro:#2A331C;--ok:#7FD39A;--ok-bg:#173222;--erro:#F19A90;--erro-bg:#3A1C19;--lei:#20261F;--linha:#2E372F;--texto-suave:#9AA597;--bronze:#D9B45E}
 .rx-chip.rx-amarelo{background:#352A12;border-color:#B98A1E} .rx-chip.rx-amarelo .rx-num{color:#E8C26A}
 .etq.caso{background:#352A12;color:#E8C26A} .etq.rev{background:#2B2540;color:#C9B8F2} .etq.port{background:#18304A;color:#A9CDEE} .etq.prova{background:#401C1C;color:#F0B4B4} .etq.acervo{background:#332B1C;color:#E0C995} .etq.ess{background:#352A12;color:#E8C26A}}
</style>
"""


def aplicar() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def marca_dagua(nome: str, login: str) -> str:
    """Imagem SVG repetida no fundo das questões com o nome e o login do usuário."""
    texto = html.escape(f"{nome} · {login}")
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="320" height="120">'
        '<text x="20" y="70" transform="rotate(-14 160 60)" font-family="Arial" font-size="14" '
        f'fill="#808080" fill-opacity="0.16">{texto}</text></svg>'
    )
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")


def aplicar_marca_dagua(nome: str, login: str) -> None:
    """Marca d'água em toda a área principal: qualquer print leva o nome de quem está logado."""
    url = marca_dagua(nome, login)
    st.markdown(
        f"""<style>[data-testid="stMain"]{{background-image:url('{url}');background-repeat:repeat;
            background-size:320px 120px}}</style>""",
        unsafe_allow_html=True,
    )


def esc(t) -> str:
    return html.escape(str(t or ""))


def grafico_barras(rotulos: list, valores: list, texto=None, maximo: float | None = None, cor: str = "var(--verde)"):
    """Gráfico de colunas em HTML puro (sem altair: no Streamlit Cloud com Python 3.14 o altair não carrega)."""
    if not valores:
        return
    texto = texto or (lambda v: f"{v:g}")
    topo = maximo or max(max(valores), 1)
    cols = "".join(
        f'<div style="flex:1;min-width:22px;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:3px">'
        f'<span style="font-size:.72rem;font-weight:600">{esc(texto(v))}</span>'
        f'<div style="width:70%;max-width:46px;height:{max(2, 120 * v / topo):.0f}px;background:{cor};border-radius:4px 4px 0 0"></div>'
        f'<span style="font-size:.7rem;color:var(--texto-suave);white-space:nowrap">{esc(r)}</span></div>'
        for r, v in zip(rotulos, valores))
    st.markdown(f'<div style="display:flex;gap:6px;align-items:flex-end;height:165px;padding:6px 2px;'
                f'border-bottom:1px solid var(--linha);overflow-x:auto">{cols}</div>', unsafe_allow_html=True)


# ======================================================================
# TELAS_ACESSO
# ======================================================================
LOGIN_OK = re.compile(r"^[a-z0-9._-]{3,30}$")
# Concurso que o aluno vai fazer (escolhido no cadastro e em Minha conta). Hoje o conteúdo é todo do CFS PMMS.
CONCURSOS = {"cfs": "CFS · Curso de Formação de Sargentos", "cfc": "CFC · Curso de Formação de Cabos",
             "cho": "CHO · Curso de Habilitação de Oficiais", "formacao": "Curso de Formação de Soldados",
             "provao": "Aluno do CFS 2026 · Provão de conclusão do curso"}
CONCURSOS_CURTO = {"cfs": "CFS", "cfc": "CFC", "cho": "CHO", "formacao": "Formação", "provao": "Provão CFS 2026"}
CONCURSOS_COM_CONTEUDO = {"cfs", "provao"}

# TRILHAS: cada trilha é um edital (tabela edital) com as suas matérias (edital_materia). O aluno vê só a trilha do
# concurso que escolheu; administrador e revisores trocam de trilha no menu lateral.
TRILHAS = {"cfs": {"concurso": "CFS-PMMS", "nome": "CFS PMMS 2026", "sub": "CFS PMMS · Banco de questões comentadas"},
           "provao": {"concurso": "PROVAO-CFS-PMMS", "nome": "Provão do CFS 2026",
                      "sub": "Provão de conclusão do CFS 2026 · Questões comentadas"}}


def trilha_de(concurso: str | None) -> str:
    return concurso if concurso in TRILHAS else "cfs"


def _trocou_trilha():
    """Ao trocar de trilha, os filtros e escolhas da trilha anterior deixam de valer."""
    st.session_state["trilha"] = st.session_state["trilha_sel"]
    for k in [k for k in st.session_state if k.startswith(("f_grupo", "f_sub_", "sim_grupos", "sim_assuntos", "rx_"))]:
        del st.session_state[k]
    st.session_state.pop("filtro_ativo", None)


def trilha_atual() -> str:
    return st.session_state.get("trilha", "cfs")


@st.cache_data(ttl=300, show_spinner=False)
def _edital_da_trilha(trilha: str) -> int | None:
    r = db.um("""SELECT e.id FROM edital e JOIN concurso c ON c.id = e.concurso_id WHERE c.sigla = %s
                 ORDER BY e.ano DESC, e.id DESC LIMIT 1""", (TRILHAS[trilha_de(trilha)]["concurso"],))
    return r["id"] if r else None


def edital_atual() -> int | None:
    return _edital_da_trilha(trilha_atual())


def filtro_trilha(q: str = "q") -> str:
    """Trecho SQL que deixa só as questões da trilha atual (edital + matérias do edital)."""
    ed = edital_atual()
    if ed is None:
        return " AND FALSE "
    ed = int(ed)
    return (f" AND EXISTS (SELECT 1 FROM questao_edital qe WHERE qe.questao_id = {q}.id AND qe.edital_id = {ed})"
            f" AND {q}.materia_id IN (SELECT em.materia_id FROM edital_materia em WHERE em.edital_id = {ed}) ")


@st.cache_resource(show_spinner=False)
def logo_app(tam: int = 256):
    """Logotipo desenhado no próprio código (escudo com ✓ sobre fundo verde-oliva): ícone da aba e da tela de entrada."""
    from PIL import Image, ImageDraw
    k = tam / 100
    img = Image.new("RGBA", (tam, tam), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, tam - 1, tam - 1], radius=int(22 * k), fill=(75, 90, 35, 255))
    escudo = [(50, 12), (82, 23), (80, 55), (68, 75), (50, 88), (32, 75), (20, 55), (18, 23)]
    d.polygon([(x * k, y * k) for x, y in escudo], fill=(242, 241, 232, 255))
    d.polygon([(x * k, y * k) for x, y in [(50, 19), (75, 28), (73.5, 54), (63.5, 70.5), (50, 81), (36.5, 70.5),
                                            (26.5, 54), (25, 28)]], fill=(138, 106, 31, 255))
    d.line([(35 * k, 50 * k), (46 * k, 62 * k), (67 * k, 37 * k)], fill=(255, 255, 255, 255), width=int(8 * k),
           joint="curve")
    return img


def _cabecalho():
    c1, c2 = st.columns([1, 7], vertical_alignment="center")
    c1.image(logo_app(), width=64)
    c2.title(NOME_APP)
    st.caption(SUBTITULO)


def tela_primeiro_acesso():
    """Aparece uma única vez: quando ainda não existe nenhum administrador."""
    _cabecalho()
    st.info("Primeiro acesso: crie a conta de **administrador**. Ela poderá cadastrar e controlar todos os outros usuários.")
    with st.form("criar_admin"):
        nome = st.text_input("Nome (como vai aparecer no app)", key="adm_nome")
        login = st.text_input("Usuário para entrar (letras minúsculas, números, ponto)", key="adm_login")
        s1 = st.text_input("Senha", type="password", key="adm_s1")
        s2 = st.text_input("Repita a senha", type="password", key="adm_s2")
        ok = st.form_submit_button("Criar administrador", type="primary")
    if ok:
        login_n = auth.normalizar_login(login)
        erro = (
            "Preencha o nome." if not nome.strip() else
            "Usuário inválido: use de 3 a 30 caracteres entre letras minúsculas, números, ponto, hífen ou sublinhado." if not LOGIN_OK.match(login_n) else
            auth.problema_na_senha(s1) or ("As senhas não conferem." if s1 != s2 else None)
        )
        if erro:
            st.error(erro)
        elif auth.existe_admin():
            st.error("Já existe um administrador. Recarregue a página e entre com login e senha.")
        else:
            uid = auth.criar_usuario(nome, login_n, "admin", s1, trocar=False)
            auth.registrar("admin_criado", uid)
            st.success("Administrador criado. Agora entre com o usuário e a senha.")
            st.rerun()


# ------------------------------------------------------------------ login que não cai
# O Streamlit guarda o login só na conexão aberta: celular que bloqueia a tela, troca de app, rede instável ou o app
# reiniciado (a cada atualização no GitHub) derrubam a conexão e o aluno tinha de entrar de novo. Ao entrar, o app cria um
# código secreto de sessão (válido por SESSAO_DIAS) e o guarda num COOKIE do navegador (antes ficava no endereço ?s=...,
# e quem copiasse o link entrava na conta). O código também fica preso ao navegador (hash do User-Agent): copiado para
# outro aparelho, não vale. Ao reconectar, o app lê o cookie e entra sozinho. "Sair" apaga o cookie e o código.
# No banco fica só o hash do código. Links antigos com ?s= ainda funcionam uma vez: o código é trocado por um novo, que
# vai para o cookie, e some do endereço.
SESSAO_DIAS = 7
SESSOES_POR_USUARIO = 3
COOKIE_SESSAO = "am_sessao"


def _hash_token(t: str) -> str:
    import hashlib
    return hashlib.sha256(t.encode()).hexdigest()


def _navegador_hash() -> str:
    try:
        ua = st.context.headers.get("User-Agent") or ""
    except Exception:
        ua = ""
    return _hash_token("ua:" + ua)


def _cookie_token() -> str | None:
    try:
        return st.context.cookies.get(COOKIE_SESSAO)
    except Exception:
        return None


def abrir_sessao(uid: int):
    token = secrets.token_urlsafe(24)
    db.executar("""INSERT INTO sessao_login (token_hash, usuario_id, expira_em, navegador)
                   VALUES (%s, %s, now() + make_interval(days => %s), %s)""",
                (_hash_token(token), uid, SESSAO_DIAS, _navegador_hash()))
    # no máximo SESSOES_POR_USUARIO aparelhos ao mesmo tempo (dificulta emprestar a conta)
    db.executar("""DELETE FROM sessao_login WHERE usuario_id = %s AND token_hash NOT IN (
                       SELECT token_hash FROM sessao_login WHERE usuario_id = %s ORDER BY ultimo_uso DESC LIMIT %s)""",
                (uid, uid, SESSOES_POR_USUARIO))
    st.session_state["_sessao_token"] = token
    st.session_state["_cookie_gravar"] = token
    st.query_params.pop("s", None)


def retomar_sessao() -> dict | None:
    via_link = False
    token = _cookie_token()
    if not token:
        token = st.query_params.get("s")
        via_link = bool(token)
    if not token:
        return None
    r = db.um("""UPDATE sessao_login SET ultimo_uso = now()
                 WHERE token_hash = %s AND expira_em > now() AND (navegador IS NULL OR navegador = %s)
                 RETURNING usuario_id""", (_hash_token(token), _navegador_hash()))
    st.query_params.pop("s", None)
    if not r:
        if not via_link:
            st.session_state["_cookie_apagar"] = True
        return None
    if via_link:
        # código antigo vindo do endereço: troca por um novo, guardado no cookie, e invalida o do link
        db.executar("DELETE FROM sessao_login WHERE token_hash = %s", (_hash_token(token),))
        abrir_sessao(r["usuario_id"])
    else:
        st.session_state["_sessao_token"] = token
    return auth.recarregar(r["usuario_id"])


def fechar_sessao(uid: int | None = None):
    token = st.session_state.get("_sessao_token") or _cookie_token() or st.query_params.get("s")
    if token:
        db.executar("DELETE FROM sessao_login WHERE token_hash = %s", (_hash_token(token),))
    st.query_params.pop("s", None)


def _apagar_cookie_depois():
    st.session_state["_cookie_apagar"] = True
    st.session_state.pop("_cookie_gravar", None)


def aplicar_cookie_sessao():
    """Grava ou apaga o cookie do login no navegador (roda no início de cada execução, antes da tela de entrada)."""
    gravar = st.session_state.pop("_cookie_gravar", None)
    apagar = st.session_state.pop("_cookie_apagar", None)
    if not gravar and not apagar:
        return
    if gravar:
        valor, idade = gravar, SESSAO_DIAS * 86400
    else:
        valor, idade = "", 0
    components.html(
        "<script>(function(){var w=window.parent||window;var seg=w.location.protocol==='https:'?'; Secure':'';"
        f"w.document.cookie='{COOKIE_SESSAO}={valor}; max-age={idade}; path=/; SameSite=Lax'+seg;}})();</script>",
        height=0)


def _sair(uid: int):
    auth.registrar("logout", uid)
    fechar_sessao()
    st.session_state.clear()
    _apagar_cookie_depois()


def tela_login():
    _cabecalho()
    aberto = config_app("cadastro_aberto", "1") == "1"
    if aberto:
        t_entrar, t_criar = st.tabs(["Entrar", "Criar conta"])
        with t_criar:
            _criar_conta()
        with t_entrar:
            _form_login()
    else:
        _form_login()


def _criar_conta():
    st.caption(f"Crie sua conta e use o app de graça por **{AVALIACAO_DIAS} dias**: questões comentadas, simulados e "
               "Raio-X do desempenho. Depois, é só adquirir o acesso pelo Pix.")
    with st.form("cadastro", clear_on_submit=False):
        nome = st.text_input("Nome e graduação (ex.: Cb PM João Silva)", key="cd_nome")
        concurso = _chave(CONCURSOS, st.selectbox("Qual concurso você vai fazer?", list(CONCURSOS.values()), key="cd_conc"))
        whatsapp = st.text_input("WhatsApp com DDD (ex.: 67 99999-0000)", key="cd_zap")
        login = st.text_input("Crie um usuário (letras minúsculas e números, ex.: joaosilva)", key="cd_login")
        s1 = st.text_input("Crie uma senha (mínimo 8 caracteres, com letras e números)", type="password", key="cd_s1")
        s2 = st.text_input("Repita a senha", type="password", key="cd_s2")
        aceite = st.checkbox("Entendo que o acesso é pessoal: compartilhar login, questões ou PDFs leva ao bloqueio da conta.",
                             key="cd_ok")
        ok = st.form_submit_button("Criar minha conta", type="primary", width="stretch")
    if not ok:
        return
    login_n = auth.normalizar_login(login)
    zap = re.sub(r"\D", "", whatsapp or "")
    if zap and not zap.startswith("55"):
        zap = "55" + zap
    erro = ("Preencha o nome e a graduação." if len((nome or "").strip()) < 5 else
            "Informe o WhatsApp com DDD." if not 12 <= len(zap) <= 13 else
            "Usuário inválido: de 3 a 30 caracteres entre letras minúsculas, números, ponto, hífen ou sublinhado."
            if not LOGIN_OK.match(login_n) else
            "Esse usuário já existe. Escolha outro." if auth.login_existe(login_n) else
            auth.problema_na_senha(s1 or "") or ("As senhas não conferem." if s1 != s2 else None) or
            ("Marque a caixa de concordância." if not aceite else None))
    if not erro and db.um("SELECT 1 AS ok FROM usuario WHERE whatsapp = %s", (zap,)):
        erro = "Já existe uma conta com esse WhatsApp. Se esqueceu a senha, fale com o administrador."
    if erro:
        st.error(erro)
        return
    uid = auth.criar_usuario(nome, login_n, "aluno", s1, trocar=False)
    db.executar("""UPDATE usuario SET whatsapp = %s, concurso = %s, acesso_tipo = 'avaliacao',
                   acesso_ate = now() + make_interval(days => %s), ultimo_acesso = now() WHERE id = %s""",
                (zap, concurso, AVALIACAO_DIAS, uid))
    auth.registrar("cadastro_proprio", uid, login_n)
    st.session_state["usuario"] = auth.recarregar(uid)
    abrir_sessao(uid)
    st.session_state["boas_vindas"] = True
    st.rerun()


def _form_login():
    with st.form("login"):
        login = st.text_input("Usuário", key="lg_login")
        senha = st.text_input("Senha", type="password", key="lg_senha")
        ok = st.form_submit_button("Entrar", type="primary", width="stretch")
    if ok:
        if not login or not senha:
            st.error("Informe usuário e senha.")
            return
        usuario, erro = auth.autenticar(login, senha)
        if erro:
            st.error(erro)
        else:
            st.session_state["usuario"] = usuario
            abrir_sessao(usuario["id"])
            st.rerun()
    st.caption("Esqueceu a senha? Peça ao administrador uma senha provisória.")


def tela_trocar_senha(usuario: dict, obrigatoria: bool):
    if obrigatoria:
        _cabecalho()
        st.warning(f"Olá, {usuario['nome']}. Antes de começar, troque a senha provisória por uma senha só sua.")
    with st.form("trocar_senha"):
        atual = None if obrigatoria else st.text_input("Senha atual", type="password", key="ts_atual")
        s1 = st.text_input("Nova senha (mínimo 8 caracteres, com letras e números)", type="password", key="ts_s1")
        s2 = st.text_input("Repita a nova senha", type="password", key="ts_s2")
        ok = st.form_submit_button("Salvar nova senha", type="primary")
    if ok:
        if not obrigatoria and not auth.senha_atual_confere(usuario["id"], atual or ""):
            st.error("A senha atual não confere.")
            return
        erro = auth.problema_na_senha(s1) or ("As senhas não conferem." if s1 != s2 else None)
        if erro:
            st.error(erro)
            return
        auth.definir_senha(usuario["id"], s1, provisoria=False)
        st.session_state["usuario"]["trocar_senha"] = False
        st.success("Senha alterada.")
        if obrigatoria:
            st.rerun()


# ======================================================================
# TELAS_QUESTOES
# ======================================================================
DIF = {1: "Fácil", 2: "Média", 3: "Difícil"}
TIPOS = {"": "Todos os tipos", "lei_seca": "Só lei seca", "caso_pratico": "Só casos práticos", "portugues": "Só Português",
         "teoria": "Só conteúdo do curso"}
ROTULO_TIPO = {"lei_seca": ("lei", "Lei seca"), "caso_pratico": ("caso", "Caso prático"), "portugues": ("port", "Português"),
               "teoria": ("rev", "Conteúdo do curso")}
# "" (padrão) = questões próprias do app. O acervo (questões antigas de materiais de apoio) só aparece se escolhido.
ORIGENS = {"": "Inéditas e provas anteriores", "inedita": "Só inéditas", "prova_anterior": "Só provas anteriores",
           "material": "Questões antigas (acervo)", "todas": "Todas, incluindo o acervo"}
FILTRO_ORIGEM = """(%(orig)s = 'todas' OR (%(orig)s = '' AND q.origem::text <> 'material') OR q.origem::text = %(orig)s)"""
# Avaliação grátis: o aluno só enxerga a AMOSTRA (questões essenciais + as marcadas como amostra), nunca o banco inteiro.
FILTRO_AMOSTRA = " AND (q.essencial OR q.amostra) "


def _so_amostra() -> bool:
    return bool(st.session_state.get("so_amostra"))


def _filtro_origem() -> str:
    return FILTRO_ORIGEM + (FILTRO_AMOSTRA if _so_amostra() else "") + filtro_trilha()
SITUACOES = {"todas": "Todas", "nao_respondidas": "Ainda não respondidas", "erradas": "Errei na última tentativa",
             "essenciais": "⭐ Só as essenciais"}
# Ordem dos itens principais do filtro (o que não está aqui vem depois, na ordem do edital)
ORDEM_GRUPOS = ["Língua Portuguesa", "LC 053/90", "CPM", "CPPM",
                "Direito Penal", "Direito Penal Militar", "Diversidade, Gênero e Combate à Discriminação", "Povos Indígenas de MS",
                "Atendimento à Pessoa com TEA", "Direito Processual Penal", "Técnicas de Policiamento Ostensivo",
                "Uso Diferenciado da Força", "Atendimento Pré-Hospitalar (APH)", "Inteligência de Segurança Pública",
                "Leis Penais Extravagantes e Segurança Pública (Abuso de Autoridade e Maria da Penha)", "Direitos Humanos",
                "Processos e Procedimentos Administrativos", "Policiamento de Choque", "Legislação Policial-Militar",
                "Policiamento de Trânsito", "Instrumentos de Menor Potencial Ofensivo", "Policiamento em Eventos",
                "Legislação Ambiental", "Comunicação Social e Imagem Institucional", "Armamento e Munição I", "Ordem Unida"]


def _chave(dicionario: dict, rotulo):
    """Devolve a chave a partir do rótulo exibido (ou None)."""
    return next((k for k, v in dicionario.items() if v == rotulo), None)


def _base_rotulo(r: str) -> str:
    """'3 – CPM · Código Penal Militar (95)' -> 'CPM · Código Penal Militar' (sem número e sem contador)."""
    return re.sub(r"^[\d.]+ – | \(\d+\)$", "", r)


def _remapeia(chave: str, opcoes: list[str]):
    """Mantém a escolha do filtro quando só a numeração ou o contador do rótulo mudou (ex.: ao trocar o banco)."""
    v = st.session_state.get(chave)
    if v is None or (v in opcoes if isinstance(v, str) else all(x in opcoes for x in v)):
        return
    if isinstance(v, str):
        novo = next((o for o in opcoes if _base_rotulo(o) == _base_rotulo(v)), None)
        if novo is None:
            del st.session_state[chave]
        else:
            st.session_state[chave] = novo
    else:
        bases = {_base_rotulo(x) for x in v}
        st.session_state[chave] = [o for o in opcoes if _base_rotulo(o) in bases]


def status_visiveis(perfil: str, incluir_revisao: bool) -> list[str]:
    if perfil == "aluno":
        return ["aprovada"]
    return ["aprovada", "em_revisao"] if incluir_revisao else ["aprovada"]


def _arvore(status: list[str], origem: str = "") -> list[dict]:
    """Itens principais (lei ou matéria) com seus subitens (assuntos), numerados 1, 1.1, 1.2...
    Só entram assuntos que têm questão visível para o usuário."""
    linhas = db.consultar(
        """SELECT a.id, a.nome, a.ordem, COUNT(DISTINCT q.id) AS n,
                  COALESCE(d.sigla, m.nome) AS grupo, d.nome_popular, COALESCE(d.id, 0) AS ordem_grupo
           FROM assunto a
           JOIN materia m ON m.id = a.materia_id
           LEFT JOIN diploma d ON d.id = a.diploma_id
           JOIN questao_assunto qa ON qa.assunto_id = a.id
           JOIN questao q ON q.id = qa.questao_id
           WHERE q.status::text = ANY(%(st)s) AND """ + _filtro_origem() + """
           GROUP BY a.id, a.nome, a.ordem, d.sigla, m.nome, d.nome_popular, d.id""",
        {"st": status, "orig": origem},
    )
    grupos: dict[str, dict] = {}
    for l in linhas:
        g = grupos.setdefault(l["grupo"], {"sigla": l["grupo"], "popular": l["nome_popular"],
                                           "ordem": l["ordem_grupo"], "subs": []})
        g["subs"].append(l)
    pos = {nome: i for i, nome in enumerate(ORDEM_GRUPOS)}
    lista = sorted(grupos.values(), key=lambda g: (pos.get(g["sigla"], len(pos)), g["ordem"], g["sigla"]))
    for i, g in enumerate(lista, start=1):
        g["subs"].sort(key=lambda a: (a["ordem"], a["nome"]))
        popular = f" · {g['popular']}" if g["popular"] and g["popular"] != g["sigla"] else ""
        g["rotulo"] = f"{i} – {g['sigla']}{popular} ({sum(a['n'] for a in g['subs'])})"
        for j, a in enumerate(g["subs"], start=1):
            a["rotulo"] = f"{i}.{j} – {a['nome']} ({a['n']})"
    return lista


def _questoes(uid: int, status: list[str], assuntos, tipo: str, origem: str, situacao: str) -> list[dict]:
    return db.consultar(
        """SELECT q.id, q.codigo, q.tipo, q.dificuldade, q.enunciado, q.texto_apoio, q.comentario, q.dica,
                  q.status::text AS status, q.origem::text AS origem, q.fonte, q.essencial, q.amostra,
                  (SELECT string_agg(a.nome, ' · ') FROM questao_assunto qa JOIN assunto a ON a.id = qa.assunto_id
                    WHERE qa.questao_id = q.id) AS assuntos
           FROM questao q
           WHERE q.status::text = ANY(%(st)s)
             AND (%(ass)s::int[] IS NULL OR EXISTS (SELECT 1 FROM questao_assunto qa WHERE qa.questao_id = q.id AND qa.assunto_id = ANY(%(ass)s::int[])))
             AND (%(tipo)s = '' OR q.tipo = %(tipo)s)
             AND """ + _filtro_origem() + """
             AND (%(sit)s = 'todas' OR (%(sit)s = 'essenciais' AND q.essencial)
                  OR (%(sit)s = 'nao_respondidas' AND NOT EXISTS (SELECT 1 FROM resposta r WHERE r.questao_id = q.id AND r.usuario_id = %(u)s))
                  OR (%(sit)s = 'erradas' AND (SELECT r.acertou FROM resposta r WHERE r.questao_id = q.id AND r.usuario_id = %(u)s
                                               ORDER BY r.respondida_em DESC LIMIT 1) = FALSE))
           ORDER BY q.codigo""",
        {"st": status, "ass": assuntos, "tipo": tipo, "orig": origem, "sit": situacao, "u": uid},
    )


def _alternativas(qid: int) -> list[dict]:
    return db.consultar(
        "SELECT id, letra, texto, correta, comentario FROM alternativa WHERE questao_id = %s ORDER BY letra", (qid,)
    )


def _lei(qid: int) -> list[dict]:
    return db.consultar(
        """SELECT d.referencia, d.texto FROM questao_dispositivo qd JOIN dispositivo d ON d.id = qd.dispositivo_id
           WHERE qd.questao_id = %s ORDER BY d.id""",
        (qid,),
    )


def _pareceres(qid: int) -> list[dict]:
    return db.consultar(
        """SELECT p.usuario_id, u.nome, p.voto, p.nota, p.atualizado_em
           FROM parecer p JOIN usuario u ON u.id = p.usuario_id WHERE p.questao_id = %s ORDER BY p.atualizado_em""",
        (qid,),
    )


POR_PAGINA = [1, 5, 10]


def tela_questoes(usuario: dict):
    st.header("Resolver questões")
    uid, perfil = usuario["id"], usuario["perfil"]

    incluir = True
    if perfil != "aluno":
        incluir = st.toggle("Incluir questões ainda em revisão", value=True, key="f_rev",
                            help="Alunos só veem as questões aprovadas.")
    status = status_visiveis(perfil, incluir)

    origem = _chave(ORIGENS, st.selectbox("Banco de questões", list(ORIGENS.values()), key="f_orig",
                                          help="As questões antigas (acervo) vêm de simulados e materiais de apoio. "
                                               "Elas ficam separadas das questões próprias do app."))
    if origem == "material":
        st.caption("📚 Acervo: questões antigas de simulados e materiais de apoio. O comentário de cada uma diz se o "
                   "gabarito já foi conferido com o texto oficial da lei.")

    # Nível 1: lei/matéria · Nível 2: subitens (vazio = todos os subitens do item escolhido)
    arvore = _arvore(status, origem)
    g1, g2 = st.columns([1, 1.4])
    principais = {"Todas as matérias e leis": None} | {g["rotulo"]: g for g in arvore}
    _remapeia("f_grupo", list(principais))
    grupo = principais[g1.selectbox("Matéria / lei", list(principais), key="f_grupo")]
    if grupo is None:
        assuntos = None
        g2.selectbox("Subitens", ["Escolha primeiro uma matéria ou lei"], disabled=True, key="f_sub_off")
    else:
        subs = {a["rotulo"]: a["id"] for a in grupo["subs"]}
        _remapeia(f"f_sub_{grupo['sigla']}", list(subs))
        marcados = g2.multiselect("Subitens", list(subs), key=f"f_sub_{grupo['sigla']}",
                                  placeholder="Todos os subitens (marque para escolher só alguns)")
        assuntos = [subs[m] for m in marcados] or list(subs.values())

    c1, c3, c4 = st.columns([1.2, 1.2, 0.8])
    fora = "portugues" if trilha_atual() == "provao" else "teoria"
    tipo = _chave(TIPOS, c1.selectbox("Tipo", [v for k, v in TIPOS.items() if k != fora], key="f_tipo"))
    situacao = _chave(SITUACOES, c3.selectbox("Situação", list(SITUACOES.values()), key="f_sit"))
    por_pagina = c4.selectbox("Por página", POR_PAGINA, index=1, key="f_pp")

    filtro = (tuple(status), tuple(assuntos) if assuntos else None, tipo, origem, situacao, por_pagina, _so_amostra(),
              trilha_atual())
    if st.session_state.get("filtro_ativo") != filtro:
        st.session_state["filtro_ativo"] = filtro
        st.session_state["pagina"] = 0
        st.session_state["lista_q"] = _questoes(uid, status, assuntos, tipo, origem, situacao)
    lista = st.session_state["lista_q"]

    if not lista:
        st.info("Nenhuma questão com esses filtros. Troque o banco de questões, a matéria, os subitens, o tipo ou a situação.")
        return

    total_pag = (len(lista) + por_pagina - 1) // por_pagina
    pag = min(st.session_state.get("pagina", 0), total_pag - 1)
    inicio = pag * por_pagina
    da_pagina = lista[inicio:inicio + por_pagina]

    _navegacao(pag, total_pag, inicio, len(da_pagina), len(lista), "topo")
    for i, q in enumerate(da_pagina):
        if i:
            st.divider()
        if por_pagina > 1:
            st.markdown(f"**Questão {inicio + i + 1}**")
        _questao(q, usuario)
    st.divider()
    _navegacao(pag, total_pag, inicio, len(da_pagina), len(lista), "base")


def _navegacao(pag: int, total_pag: int, inicio: int, qtd: int, total: int, onde: str):
    a, b, c = st.columns([1, 2, 1])
    if a.button("◀ Anterior", disabled=pag == 0, width="stretch", key=f"ant_{onde}"):
        st.session_state["pagina"] = pag - 1
        st.rerun()
    if qtd == 1:
        texto = f"Questão <b>{inicio + 1}</b> de {total}"
    else:
        texto = f"Questões <b>{inicio + 1}–{inicio + qtd}</b> de {total} · página {pag + 1}/{total_pag}"
    b.markdown(f"<div style='text-align:center;padding-top:6px'>{texto}</div>", unsafe_allow_html=True)
    if c.button("Próxima ▶", disabled=pag >= total_pag - 1, width="stretch", key=f"prox_{onde}"):
        st.session_state["pagina"] = pag + 1
        st.rerun()


def _texto_apoio(q: dict, expandido: bool = False):
    if q.get("texto_apoio"):
        rotulo = ("📄 Texto para as questões de Português (toque para ler)" if q["tipo"] == "portugues"
                  else "📄 Texto de apoio (toque para ler)")
        with st.expander(rotulo, expanded=expandido):
            st.markdown("".join(f"<p>{esc(p)}</p>" for p in q["texto_apoio"].split("\n\n")), unsafe_allow_html=True)


def _cartao(q: dict, cabecalho: str | None = None):
    """Enunciado da questão. Com `cabecalho`, troca código/assunto/etiquetas por um título neutro (modo prova)."""
    if cabecalho is not None:
        topo = f'<span><b>{esc(cabecalho)}</b></span>'
    else:
        classe, nome_tipo = ROTULO_TIPO.get(q["tipo"], ("lei", q["tipo"]))
        etq_tipo = f'<span class="etq {classe}">{nome_tipo}</span>'
        etq_rev = '<span class="etq rev">Em revisão</span>' if q["status"] == "em_revisao" else ""
        etq_prova = f'<span class="etq prova">{esc(q["fonte"])}</span>' if q["origem"] == "prova_anterior" else ""
        etq_acervo = '<span class="etq acervo">Acervo</span>' if q["origem"] == "material" else ""
        etq_ess = '<span class="etq ess">⭐ Essencial</span>' if q.get("essencial") else ""
        topo = (f'<span><span class="cod">{esc(q["codigo"])}</span> · {esc(q["assuntos"])}</span>'
                f'<span>{DIF.get(q["dificuldade"], "")}{etq_ess}{etq_tipo}{etq_prova}{etq_acervo}{etq_rev}</span>')
    st.markdown(
        f"""<div class="cartao">
              <div class="topo">{topo}</div>
              <p class="enun">{esc(q['enunciado'])}</p></div>""",
        unsafe_allow_html=True,
    )


def _marcar_essencial(q: dict):
    novo = bool(st.session_state.get(f"ess_{q['id']}"))
    db.executar("UPDATE questao SET essencial = %s WHERE id = %s", (novo, q["id"]))
    q["essencial"] = novo


def _marcar_amostra(q: dict):
    novo = bool(st.session_state.get(f"amo_{q['id']}"))
    db.executar("UPDATE questao SET amostra = %s WHERE id = %s", (novo, q["id"]))
    q["amostra"] = novo


def _questao(q: dict, usuario: dict):
    fundo = marca_dagua(usuario["nome"], usuario["login"])
    _texto_apoio(q)
    _cartao(q)
    if usuario["perfil"] in ("admin", "revisor"):
        e1, e2 = st.columns(2)
        e1.toggle("⭐ Essencial (entra em \"Questões essenciais\" da lei)", value=bool(q.get("essencial")),
                  key=f"ess_{q['id']}", on_change=_marcar_essencial, args=(q,))
        e2.toggle("🎁 Amostra grátis (aparece na avaliação)", value=bool(q.get("amostra") or q.get("essencial")),
                  disabled=bool(q.get("essencial")), key=f"amo_{q['id']}", on_change=_marcar_amostra, args=(q,),
                  help="Toda essencial já entra na avaliação grátis.")

    alts = _alternativas(q["id"])
    respondidas = st.session_state.setdefault("respondidas", {})
    escolha_id = respondidas.get(q["id"])

    if escolha_id is None:
        rotulos = {f"{a['letra']}) {a['texto']}": a["id"] for a in alts}
        escolha = rotulos.get(st.radio("Escolha uma alternativa", list(rotulos), index=None,
                                       key=f"radio_{q['id']}", label_visibility="collapsed"))
        if st.button("Responder", type="primary", key=f"resp_{q['id']}"):
            if escolha is None:
                st.warning("Marque uma alternativa antes de responder.")
                return
            certa = next(a for a in alts if a["id"] == escolha)["correta"]
            db.executar(
                "INSERT INTO resposta (usuario_id, questao_id, alternativa_id, acertou) VALUES (%s, %s, %s, %s)",
                (usuario["id"], q["id"], escolha, certa),
            )
            respondidas[q["id"]] = escolha
            st.rerun()
        return

    _correcao(q, alts, escolha_id, fundo)
    _estatistica_turma(q["id"])
    b1, b2 = st.columns([1, 1.4])
    if b1.button("Refazer esta questão", key=f"refazer_{q['id']}"):
        respondidas.pop(q["id"], None)
        st.session_state.pop(f"radio_{q['id']}", None)
        st.rerun()
    _reportar(q, usuario, b2)
    if usuario["perfil"] in ("admin", "revisor"):
        _parecer(q, usuario)


def _estatistica_turma(qid: int):
    """Percentual de acerto de todos que responderam (1ª resposta de cada pessoa) e a alternativa mais marcada."""
    e = db.um(
        """WITH primeira AS (
               SELECT DISTINCT ON (r.usuario_id) r.usuario_id, r.acertou, a.letra
               FROM resposta r JOIN alternativa a ON a.id = r.alternativa_id
               WHERE r.questao_id = %s ORDER BY r.usuario_id, r.respondida_em)
           SELECT COUNT(*) AS n, ROUND(100.0 * AVG(acertou::int)) AS pct,
                  (SELECT letra FROM primeira GROUP BY letra ORDER BY COUNT(*) DESC, letra LIMIT 1) AS mais
           FROM primeira""", (qid,))
    if e and e["n"] >= 3:
        st.caption(f"📊 {int(e['pct'])}% acertaram de primeira ({e['n']} pessoas) · alternativa mais marcada: {e['mais']}")


def _reportar(q: dict, usuario: dict, onde):
    with onde.popover("⚠️ Achei um erro nesta questão", width="stretch"):
        with st.form(f"rep_{q['id']}", clear_on_submit=True):
            txt = st.text_area("O que está errado?", placeholder="Ex.: a alternativa C também está correta, porque...",
                               key=f"rep_txt_{q['id']}")
            if st.form_submit_button("Enviar para a equipe"):
                if len(txt.strip()) < 10:
                    st.warning("Explique um pouco melhor (pelo menos uma frase).")
                else:
                    db.executar("INSERT INTO reporte_erro (usuario_id, questao_id, descricao) VALUES (%s, %s, %s)",
                                (usuario["id"], q["id"], txt.strip()))
                    st.success("Obrigado! A equipe vai conferir.")


def _correcao(q: dict, alts: list[dict], escolha_id: int | None, fundo: str):
    certa = next(a for a in alts if a["correta"])
    if escolha_id is None:
        st.warning(f"Você deixou em branco. Gabarito: {certa['letra']}")
    elif escolha_id == certa["id"]:
        st.success(f"Você acertou. Gabarito: {certa['letra']}")
    else:
        marcada = next(a for a in alts if a["id"] == escolha_id)
        st.error(f"Você marcou {marcada['letra']}. Gabarito: {certa['letra']}")

    dica = f'<div class="dica"><b>Para memorizar:</b> {esc(q["dica"])}</div>' if q.get("dica") else ""
    partes = []
    for a in alts:
        cls = "certa" if a["correta"] else ("errada" if a["id"] == escolha_id else "")
        partes.append(f'<div class="alt {cls}"><b>{a["letra"]})</b> {esc(a["texto"])}'
                      + (f'<span class="why">{esc(a["comentario"])}</span>' if a["comentario"] else "") + '</div>')
    st.markdown(
        f"""<div class="cartao">{''.join(partes)}
            <div class="rotulo">Comentário</div><p class="coment">{esc(q['comentario'])}</p>
            {dica}</div>""",
        unsafe_allow_html=True,
    )
    lei = _lei(q["id"])
    if lei:
        with st.expander(f"Texto literal da lei ({len(lei)} dispositivos)"):
            st.markdown(
                "".join(f'<div class="lei-txt"><span class="ref">{esc(_ref(d["referencia"]))}</span>'
                        f'{esc(d["texto"])}</div>' for d in lei),
                unsafe_allow_html=True,
            )


def _ref(referencia: str) -> str:
    """Tira a marca interna de linha ('[L123]') da referência do artigo."""
    return re.sub(r" \[(?:[A-Z]+-)?L\d+\]$", "", referencia)


def _parecer(q: dict, usuario: dict):
    st.markdown('<div class="rotulo">Parecer da equipe</div>', unsafe_allow_html=True)
    todos = _pareceres(q["id"])
    meu = next((p for p in todos if p["usuario_id"] == usuario["id"]), None)
    aprov = sum(p["voto"] == "aprovar" for p in todos)
    ajust = sum(p["voto"] == "ajustar" for p in todos)
    st.caption(f"{aprov} aprovaram · {ajust} pediram ajuste" if todos else "Ainda sem pareceres nesta questão.")
    for p in todos:
        icone = "✅" if p["voto"] == "aprovar" else "✏️"
        quem = p["nome"] + (" (você)" if p["usuario_id"] == usuario["id"] else "")
        st.markdown(f"{icone} **{esc(quem)}** {esc(p['nota'] or '')}")

    with st.form(f"parecer_{q['id']}"):
        opcoes = {"aprovar": "Aprovar", "ajustar": "Precisa de ajuste"}
        voto = _chave(opcoes, st.radio("Seu voto", list(opcoes.values()), horizontal=True,
                                       index=list(opcoes).index(meu["voto"]) if meu else None, key=f"voto_{q['id']}"))
        nota = st.text_area("Observação (o que ajustar e por quê)", value=(meu or {}).get("nota") or "",
                            key=f"nota_{q['id']}")
        if st.form_submit_button("Salvar parecer"):
            if voto is None:
                st.warning("Escolha Aprovar ou Precisa de ajuste.")
            elif voto == "ajustar" and not nota.strip():
                st.warning("Explique o ajuste na observação. Sem isso, não dá para corrigir a questão.")
            else:
                db.executar(
                    """INSERT INTO parecer (questao_id, usuario_id, voto, nota) VALUES (%s, %s, %s, %s)
                       ON CONFLICT (questao_id, usuario_id)
                       DO UPDATE SET voto = EXCLUDED.voto, nota = EXCLUDED.nota, atualizado_em = now()""",
                    (q["id"], usuario["id"], voto, nota.strip() or None),
                )
                st.success("Parecer salvo.")
                st.rerun()


# ======================================================================
# TELAS_SIMULADO
# ======================================================================
# Prova CFS-31/QPPM/2026 (Edital n. 1/2026): 50 questões de 4 alternativas = 20 de Português + 30 de Legislação.
# A Legislação segue a distribuição da prova de 21/06/2026. As 2 questões da Portaria 167 (fora do edital)
# foram trocadas por 1 da CE/MS e 1 do Dec. 10.769/02, que estão no edital e não caíram em 2026.
CFS_PORTUGUES = 20
CFS_PORT_TEXTO = 15        # na prova, 15 das 20 de Português saíram do texto-base
CFS_LEGISLACAO = {"Lei 13.869/19": 3, "LC 053/90": 3, "CPM": 3, "Lei 11.340/06": 3,
                  "Dec. 1.261/81": 2, "Lei 10.826/03": 2, "LC 127/08": 2, "Lei 11.343/06": 2,
                  "Dec. 1.093/81": 2, "RDPMMS": 2, "CF/88": 1, "CPPM": 1, "LC 190/14": 1,
                  "Lei 9.455/97": 1, "CE/MS": 1, "Dec. 10.769/02": 1}
CFS_MINUTOS = 180          # tempo padrão do simulado modelo (o aluno pode mudar na tela)
PROVAO_QUESTOES = 100      # o provão de conclusão do CFS 2026 terá 100 questões de todas as matérias
PROVAO_MINUTOS = 240
PORTUGUES = "Língua Portuguesa"
FOLGA_SEG = 30             # tolerância para a última marcação chegar depois do fim do tempo
REVISAO_POR_PAGINA = 5
FUSO = ZoneInfo("America/Campo_Grande")


def _local(dt):
    return dt.astimezone(FUSO) if dt is not None else None


def _fmt_tempo(seg) -> str:
    if seg is None:
        return "—"
    seg = int(seg)
    h, m = divmod(seg // 60, 60)
    return f"{h}h{m:02d}" if h else f"{m} min" if m else f"{seg} s"


def _nota_txt(acertos: int, total: int) -> str:
    return f"{10 * acertos / total:.1f}".replace(".", ",") if total else "—"


# ------------------------------------------------------------------ banco e sorteio
def _banco_simulado(uid: int, status: list[str], so_ineditas: bool, nao_repetir: bool) -> list[dict]:
    """Questões que podem entrar no simulado (uma linha por questão, com a lei/matéria e os assuntos)."""
    return db.consultar(
        """SELECT q.id, m.nome AS materia, md5(q.texto_apoio) AS texto,
                  MIN(COALESCE(d.sigla, m.nome)) AS grupo, MIN(COALESCE(d.id, 0)) AS ordem_grupo,
                  array_agg(DISTINCT qa.assunto_id) AS assuntos
           FROM questao q
           JOIN materia m ON m.id = q.materia_id
           JOIN questao_assunto qa ON qa.questao_id = q.id
           JOIN assunto a ON a.id = qa.assunto_id
           LEFT JOIN diploma d ON d.id = a.diploma_id
           WHERE q.status::text = ANY(%(st)s) AND """ + _filtro_origem() + """
             AND (NOT %(nr)s OR (
                  NOT EXISTS (SELECT 1 FROM resposta r WHERE r.usuario_id = %(u)s AND r.questao_id = q.id)
                  AND NOT EXISTS (SELECT 1 FROM simulado_questao sq JOIN simulado s ON s.id = sq.simulado_id
                                  WHERE s.usuario_id = %(u)s AND s.status = 'finalizado' AND sq.questao_id = q.id)))
           GROUP BY q.id, m.nome""",
        {"st": status, "orig": "inedita" if so_ineditas else "", "nr": nao_repetir, "u": uid},
    )


def _ordem_prova(lista: list[dict]) -> list[dict]:
    """Português primeiro (questões do mesmo texto juntas), depois Legislação lei por lei, como na prova."""
    pos = {nome: i for i, nome in enumerate(ORDEM_GRUPOS)}
    for q in lista:
        q.setdefault("_r", random.random())
    return sorted(lista, key=lambda q: (q["materia"] != PORTUGUES, pos.get(q["grupo"], len(pos)), q["ordem_grupo"],
                                        q["grupo"], q["texto"] is None, q["texto"] or "", q["_r"]))


def _sortear_cfs(banco: list[dict]) -> tuple[list[dict], list[str]]:
    avisos, escolhidas = [], []
    port = [q for q in banco if q["materia"] == PORTUGUES]
    random.shuffle(port)
    blocos: dict[str, list] = {}
    for q in port:
        if q["texto"]:
            blocos.setdefault(q["texto"], []).append(q)
    textos = list(blocos.values())
    random.shuffle(textos)
    for b in textos:                                   # questões de texto, um texto de cada vez
        falta = CFS_PORT_TEXTO - len(escolhidas)
        if falta <= 0:
            break
        escolhidas += b[:falta]
    usados = {q["id"] for q in escolhidas}
    resto_port = [q for q in port if q["id"] not in usados]
    resto_port.sort(key=lambda q: q["texto"] is not None)   # primeiro as sem texto, depois o que sobrar
    escolhidas += resto_port[:CFS_PORTUGUES - len(escolhidas)]
    if len(escolhidas) < CFS_PORTUGUES:
        avisos.append(f"Português: só havia {len(escolhidas)} questões disponíveis (o modelo pede {CFS_PORTUGUES}).")

    usados = {q["id"] for q in escolhidas}
    leg = [q for q in banco if q["materia"] != PORTUGUES and q["id"] not in usados]
    random.shuffle(leg)
    faltou = []
    for sigla, k in CFS_LEGISLACAO.items():
        cands = [q for q in leg if q["grupo"] == sigla and q["id"] not in usados][:k]
        escolhidas += cands
        usados |= {q["id"] for q in cands}
        if len(cands) < k:
            faltou.append(f"{sigla} ({len(cands)} de {k})")
    meta = CFS_PORTUGUES + sum(CFS_LEGISLACAO.values())
    n_leg_meta = sum(CFS_LEGISLACAO.values())
    n_leg = sum(q["materia"] != PORTUGUES for q in escolhidas)
    if n_leg < n_leg_meta:                              # completa com outras leis
        extra = [q for q in leg if q["id"] not in usados][:n_leg_meta - n_leg]
        escolhidas += extra
    if faltou:
        avisos.append("Sem questões suficientes em " + ", ".join(faltou) + ": completei com outras leis do edital.")
    if len(escolhidas) < meta:
        avisos.append(f"O simulado ficou com {len(escolhidas)} questões (o modelo tem {meta}).")
    return _ordem_prova(escolhidas), avisos


def _sortear_personalizado(banco: list[dict], grupos: list[str], assuntos: set[int], n: int) -> tuple[list[dict], int]:
    """Distribui igualmente entre as matérias/leis escolhidas (o que faltar numa, completa com as outras)."""
    cands = [q for q in banco if (not grupos or q["grupo"] in grupos) and (not assuntos or set(q["assuntos"]) & assuntos)]
    baldes: dict[str, list] = {}
    for q in cands:
        baldes.setdefault(q["grupo"], []).append(q)
    for b in baldes.values():
        random.shuffle(b)
    ordem = list(baldes)
    random.shuffle(ordem)
    escolhidas: list[dict] = []
    while len(escolhidas) < n and any(baldes.values()):
        for g in ordem:
            if baldes[g] and len(escolhidas) < n:
                escolhidas.append(baldes[g].pop())
    return _ordem_prova(escolhidas), len(cands)


# ------------------------------------------------------------------ gravação
def _criar_simulado(uid: int, modelo: str, titulo: str, questoes: list[dict], minutos: int | None, config: dict) -> int | None:
    if _so_amostra() and _simulados_feitos(uid) >= AVALIACAO_SIMULADOS:
        st.session_state["sim_erro"] = "O simulado da avaliação grátis já foi usado."
        return None

    def fn(conn):
        sid = conn.execute(
            """INSERT INTO simulado (usuario_id, edital_id, modelo, titulo, duracao_min, config, total)
               VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s)
               RETURNING id""",
            (uid, edital_atual(), modelo, titulo, minutos, json.dumps(config, ensure_ascii=False), len(questoes)),
        ).fetchone()["id"]
        with conn.cursor() as cur:
            cur.executemany("INSERT INTO simulado_questao (simulado_id, ordem, questao_id) VALUES (%s, %s, %s)",
                            [(sid, i, q["id"]) for i, q in enumerate(questoes, start=1)])
        return sid
    return db.transacao(fn)


def _simulado_aberto(uid: int) -> dict | None:
    return db.um(
        """SELECT id, modelo, titulo, duracao_min, total, EXTRACT(EPOCH FROM now() - iniciado_em)::int AS decorrido
           FROM simulado WHERE usuario_id = %s AND status = 'em_andamento' ORDER BY id DESC LIMIT 1""", (uid,))


def _questoes_simulado(sid: int) -> list[dict]:
    return db.consultar(
        """SELECT sq.ordem, sq.alternativa_id, sq.acertou, q.id, q.codigo, q.tipo, q.dificuldade, q.enunciado,
                  q.texto_apoio, q.comentario, q.dica, q.status::text AS status, q.origem::text AS origem, q.fonte,
                  m.nome AS materia,
                  (SELECT string_agg(a.nome, ' · ') FROM questao_assunto qa JOIN assunto a ON a.id = qa.assunto_id
                    WHERE qa.questao_id = q.id) AS assuntos
           FROM simulado_questao sq JOIN questao q ON q.id = sq.questao_id JOIN materia m ON m.id = q.materia_id
           WHERE sq.simulado_id = %s ORDER BY sq.ordem""", (sid,))


def _marcar(sid: int, qid: int, chave: str, opcoes: dict):
    """Salva a marcação na hora (callback do botão de opção). Depois do fim do tempo, não grava mais."""
    rotulo = st.session_state.get(chave)
    alt = opcoes.get(rotulo) if rotulo else None
    db.executar(
        """UPDATE simulado_questao sq SET alternativa_id = %s, marcada_em = now()
           FROM simulado s
           WHERE s.id = sq.simulado_id AND sq.simulado_id = %s AND sq.questao_id = %s AND s.status = 'em_andamento'
             AND (s.duracao_min IS NULL OR now() <= s.iniciado_em + make_interval(mins => s.duracao_min) + make_interval(secs => %s))""",
        (alt, sid, qid, FOLGA_SEG))


def _em_branco(sid: int, qid: int, chave: str):
    st.session_state[chave] = None
    _marcar(sid, qid, chave, {})


def _entregar(sid: int, uid: int, por_tempo: bool = False) -> bool:
    """Fecha o simulado, corrige e lança as respostas no desempenho do aluno. Só funciona uma vez."""
    def fn(conn):
        ok = conn.execute(
            """UPDATE simulado SET status = 'finalizado', finalizado_em = now(), por_tempo = %s,
                      tempo_seg = LEAST(EXTRACT(EPOCH FROM now() - iniciado_em)::int, COALESCE(duracao_min * 60, 2147483647))
               WHERE id = %s AND usuario_id = %s AND status = 'em_andamento' RETURNING id""",
            (por_tempo, sid, uid)).fetchone()
        if not ok:
            return False
        conn.execute("""UPDATE simulado_questao sq SET acertou = a.correta FROM alternativa a
                        WHERE sq.simulado_id = %s AND a.id = sq.alternativa_id""", (sid,))
        conn.execute("""INSERT INTO resposta (usuario_id, questao_id, alternativa_id, acertou, simulado_id, respondida_em)
                        SELECT %s, sq.questao_id, sq.alternativa_id, sq.acertou, %s, COALESCE(sq.marcada_em, now())
                        FROM simulado_questao sq WHERE sq.simulado_id = %s AND sq.alternativa_id IS NOT NULL""",
                     (uid, sid, sid))
        conn.execute("""UPDATE simulado SET
                            acertos = (SELECT COUNT(*) FROM simulado_questao WHERE simulado_id = %s AND acertou),
                            total   = (SELECT COUNT(*) FROM simulado_questao WHERE simulado_id = %s)
                        WHERE id = %s""", (sid, sid, sid))
        return True
    return db.transacao(fn)


def _depois_de_entregar(sid: int):
    st.session_state["sim_ver"] = sid
    st.session_state.pop("filtro_ativo", None)          # a lista de "Resolver questões" passa a ver as novas respostas
    for k in [k for k in st.session_state if str(k).startswith(f"sim_{sid}_")]:
        del st.session_state[k]


# ------------------------------------------------------------------ prova
def _cronometro(restante: int | None, decorrido: int):
    """Relógio que corre no navegador (não recarrega a página). Fica vermelho nos 5 minutos finais."""
    rest = "null" if restante is None else int(restante)
    components.html(
        f"""<style>body{{margin:0;font:600 1.2rem ui-monospace,Menlo,Consolas,monospace;color:#4B5A23}}
        @media (prefers-color-scheme: dark){{body{{color:#B5C77A}}}}</style>
        <div id="c">⏱</div>
        <script>
        const ini = Date.now(), rest = {rest}, dec = {int(decorrido)}, el = document.getElementById('c');
        function f(s){{s = Math.max(0, Math.floor(s)); const h = Math.floor(s/3600), m = Math.floor(s%3600/60), x = s%60;
          return (h ? h + ':' + String(m).padStart(2,'0') : m) + ':' + String(x).padStart(2,'0');}}
        function tick(){{ const p = (Date.now() - ini) / 1000;
          if (rest === null) {{ el.textContent = '⏱ ' + f(dec + p) + ' (sem limite de tempo)'; return; }}
          const r = rest - p;
          el.textContent = r > 0 ? '⏱ Faltam ' + f(r) : '⏱ Tempo esgotado: entregando...';
          el.style.color = r <= 300 ? '#C0392B' : ''; }}
        tick(); setInterval(tick, 1000);
        </script>""",
        height=36,
    )


@st.fragment(run_every=10)
def _vigia_tempo(fim_epoch: float):
    """A cada 10 s confere se o tempo acabou; se acabou, recarrega a tela, que entrega o simulado sozinha."""
    if time.time() >= fim_epoch:
        st.rerun()


def _mapa(qs: list[dict], atual: int | None = None, corrigido: bool = False):
    cel = []
    for i, q in enumerate(qs):
        if corrigido:
            cls = "branco" if q["alternativa_id"] is None else ("certa" if q["acertou"] else "errada")
        else:
            cls = "ok" if q["alternativa_id"] else ""
        if i == atual:
            cls += " atual"
        cel.append(f'<span class="mq {cls}">{i + 1}</span>')
    st.markdown(f'<div class="mapa">{"".join(cel)}</div>', unsafe_allow_html=True)


def _ir(chave: str, valor: int):
    st.session_state[chave] = valor


def _clique_entregar(sid: int, uid: int):
    _entregar(sid, uid)
    _depois_de_entregar(sid)


def _clique_descartar(sid: int, uid: int):
    db.executar("UPDATE simulado SET status = 'descartado', finalizado_em = now() "
                "WHERE id = %s AND usuario_id = %s AND status = 'em_andamento'", (sid, uid))
    for k in [k for k in st.session_state if str(k).startswith(f"sim_{sid}_")]:
        del st.session_state[k]


def _prova(sim: dict, usuario: dict) -> bool:
    """Tela da prova. Devolve False se o tempo tinha acabado (aí o simulado é entregue e o resultado aparece)."""
    sid, uid = sim["id"], usuario["id"]
    restante = None if sim["duracao_min"] is None else sim["duracao_min"] * 60 - sim["decorrido"]
    if restante is not None and restante <= 0:
        _entregar(sid, uid, por_tempo=True)
        _depois_de_entregar(sid)
        st.session_state["sim_msg"] = "O tempo acabou e o simulado foi entregue automaticamente."
        return False

    for aviso in st.session_state.pop("sim_avisos", []):
        st.info(aviso)
    qs = _questoes_simulado(sid)
    n = len(qs)
    feitas = sum(q["alternativa_id"] is not None for q in qs)

    st.subheader(sim["titulo"])
    c1, c2 = st.columns([1.2, 1])
    with c1:
        _cronometro(restante, sim["decorrido"])
    c2.progress(feitas / n if n else 0, text=f"Respondidas: {feitas} de {n}")
    if restante is not None:
        _vigia_tempo(time.time() + restante)
    st.caption("Gabarito e comentários só aparecem quando você entregar. Cada marcação fica salva na hora: "
               "se a internet cair, é só entrar de novo que o simulado continua de onde parou.")

    chave_pos = f"sim_{sid}_pos"
    if st.session_state.get(chave_pos) not in range(n):
        st.session_state[chave_pos] = 0
    _mapa(qs, st.session_state[chave_pos])
    # Rótulo fixo de propósito: se ele mudasse ao responder, o Streamlit perderia a posição e voltaria para a 1.
    # Quem mostra o que já foi respondido é o mapa acima.
    pos = st.selectbox("Ir para a questão", list(range(n)), key=chave_pos,
                       format_func=lambda i: f"Questão {i + 1} · {qs[i]['materia']}")
    q = qs[pos]

    if q["texto_apoio"]:
        mesmo = [i for i, x in enumerate(qs) if x["texto_apoio"] == q["texto_apoio"]]
        _texto_apoio(q, expandido=pos == mesmo[0])
        if len(mesmo) > 1:
            st.caption(f"Este texto vale para as questões {mesmo[0] + 1} a {mesmo[-1] + 1}.")
    _cartao(q, cabecalho=f"Questão {pos + 1} de {n} · {q['materia']}")

    alts = _alternativas(q["id"])
    opcoes = {f"{a['letra']}) {a['texto']}": a["id"] for a in alts}
    chave = f"sim_{sid}_q{q['id']}"
    if chave not in st.session_state:
        st.session_state[chave] = next((r for r, i in opcoes.items() if i == q["alternativa_id"]), None)
    st.radio("Sua resposta", list(opcoes), key=chave, on_change=_marcar, args=(sid, q["id"], chave, opcoes),
             label_visibility="collapsed")

    b1, b2, b3 = st.columns(3)
    b1.button("◀ Anterior", disabled=pos == 0, width="stretch", key=f"sim_{sid}_ant",
              on_click=_ir, args=(chave_pos, pos - 1))
    b2.button("Deixar em branco", disabled=q["alternativa_id"] is None, width="stretch", key=f"sim_{sid}_branco",
              on_click=_em_branco, args=(sid, q["id"], chave))
    b3.button("Próxima ▶", disabled=pos >= n - 1, width="stretch", key=f"sim_{sid}_prox",
              on_click=_ir, args=(chave_pos, pos + 1))

    st.divider()
    brancos = n - feitas
    with st.container(border=True):
        st.markdown("**Entregar o simulado**")
        pode = True
        if brancos:
            pode = st.checkbox(f"Entregar mesmo com {brancos} questão(ões) em branco", key=f"sim_{sid}_conf")
        st.button("Entregar e ver o resultado", type="primary", disabled=not pode, key=f"sim_{sid}_entregar",
                  on_click=_clique_entregar, args=(sid, uid))
    with st.expander("Desistir deste simulado"):
        st.caption("O simulado é descartado: nada entra no seu desempenho e as questões continuam como não feitas.")
        if st.toggle("Quero descartar este simulado", key=f"sim_{sid}_desistir"):
            st.button("Descartar simulado", key=f"sim_{sid}_descartar", on_click=_clique_descartar, args=(sid, uid))
    return True


# ------------------------------------------------------------------ resultado
def _resultado(sid: int, usuario: dict):
    s = db.um("""SELECT id, modelo, titulo, iniciado_em, tempo_seg, por_tempo, duracao_min, status
                 FROM simulado WHERE id = %s AND usuario_id = %s""", (sid, usuario["id"]))
    if not s or s["status"] != "finalizado":
        st.info("Simulado não encontrado.")
        return
    msg = st.session_state.pop("sim_msg", None)
    if msg:
        st.warning(msg)
    qs = _questoes_simulado(sid)
    total = len(qs)
    acertos = sum(bool(q["acertou"]) for q in qs)
    brancos = sum(q["alternativa_id"] is None for q in qs)
    pct = 100 * acertos / total if total else 0

    st.subheader(f"Resultado · {s['titulo']}")
    extra = " · entregue automaticamente quando o tempo acabou" if s["por_tempo"] else ""
    st.caption(f"Feito em {_local(s['iniciado_em']):%d/%m/%Y às %H:%M} · tempo usado: {_fmt_tempo(s['tempo_seg'])}"
               + (f" de {_fmt_tempo(s['duracao_min'] * 60)}" if s["duracao_min"] else "") + extra)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Nota (0 a 10)", _nota_txt(acertos, total))
    c2.metric("Acertos", f"{acertos} de {total} ({pct:.0f}%)")
    c3.metric("Erros", total - acertos - brancos)
    c4.metric("Em branco", brancos)

    df = pd.DataFrame([{"materia": q["materia"], "acertou": bool(q["acertou"])} for q in qs])
    por_mat = df.groupby("materia")["acertou"].agg(["sum", "count"]).reset_index()
    if s["modelo"] == "cfs":
        ed = db.um("SELECT nota_minima_pct FROM edital WHERE id = %s", (_edital_da_trilha("cfs"),))
        minimo = float(ed["nota_minima_pct"]) if ed and ed["nota_minima_pct"] is not None else 50.0
        zerou = por_mat[por_mat["sum"] == 0]["materia"].tolist()
        partes = " · ".join(f"{r.materia}: {int(r.sum)} de {int(r.count)}" for r in por_mat.itertuples())
        if pct >= minimo and not zerou:
            st.success(f"Pela regra do edital (pelo menos {minimo:.0f}% e sem zerar matéria) você estaria aprovado. {partes}")
        else:
            motivo = f"zerou {', '.join(zerou)}" if zerou else f"ficou abaixo de {minimo:.0f}%"
            st.error(f"Pela regra do edital você ainda não passaria: {motivo}. {partes}")

    ass = db.consultar(
        """SELECT COALESCE(d.sigla, m.nome) AS grupo, a.nome AS assunto, COUNT(*) AS questoes,
                  COUNT(*) FILTER (WHERE sq.acertou) AS acertos
           FROM simulado_questao sq JOIN questao_assunto qa ON qa.questao_id = sq.questao_id
           JOIN assunto a ON a.id = qa.assunto_id JOIN materia m ON m.id = a.materia_id
           LEFT JOIN diploma d ON d.id = a.diploma_id
           WHERE sq.simulado_id = %s GROUP BY 1, 2""", (sid,))
    da = pd.DataFrame(ass)
    if not da.empty:
        da["pct"] = (100 * da["acertos"] / da["questoes"]).round(0)
        dg = da.groupby("grupo")[["questoes", "acertos"]].sum().reset_index()
        dg["pct"] = (100 * dg["acertos"] / dg["questoes"]).round(0)
        barra = st.column_config.ProgressColumn("% de acerto", min_value=0, max_value=100, format="%d%%")
        st.markdown("**Desempenho por matéria / lei**")
        st.dataframe(dg.sort_values(["pct", "questoes"], ascending=[True, False]).rename(
            columns={"grupo": "Matéria / lei", "questoes": "Questões", "acertos": "Acertos"}),
            hide_index=True, width="stretch", column_config={"pct": barra})
        st.markdown("**Desempenho por assunto** (do mais fraco para o mais forte)")
        st.dataframe(da.sort_values(["pct", "questoes"], ascending=[True, False]).rename(
            columns={"grupo": "Lei", "assunto": "Assunto", "questoes": "Questões", "acertos": "Acertos"}),
            hide_index=True, width="stretch", column_config={"pct": barra})

    st.subheader("Revisão com gabarito e comentários")
    _mapa(qs, corrigido=True)
    st.caption("Verde: acertou · vermelho: errou · cinza: em branco.")
    filtros = {"Todas": lambda q: True,
               "Só as que errei": lambda q: q["alternativa_id"] is not None and not q["acertou"],
               "Só as em branco": lambda q: q["alternativa_id"] is None,
               "Só as que acertei": lambda q: bool(q["acertou"])}
    f = st.radio("Mostrar", list(filtros), horizontal=True, key=f"simrev_{sid}_f")
    sel = [i for i, q in enumerate(qs) if filtros[f](q)]
    if not sel:
        st.info("Nenhuma questão nesse filtro.")
        return
    chave_p = f"simrev_{sid}_p"
    if st.session_state.get(f"simrev_{sid}_fant") != f:
        st.session_state[f"simrev_{sid}_fant"] = f
        st.session_state[chave_p] = 0
    total_pag = (len(sel) + REVISAO_POR_PAGINA - 1) // REVISAO_POR_PAGINA
    pag = min(st.session_state.get(chave_p, 0), total_pag - 1)
    fundo = marca_dagua(usuario["nome"], usuario["login"])
    for i in sel[pag * REVISAO_POR_PAGINA:(pag + 1) * REVISAO_POR_PAGINA]:
        q = qs[i]
        st.divider()
        st.markdown(f"**Questão {i + 1}** · {esc(q['materia'])}")
        _texto_apoio(q)
        _cartao(q)
        _correcao(q, _alternativas(q["id"]), q["alternativa_id"], fundo)
        _estatistica_turma(q["id"])
        _reportar(q, usuario, st)
    st.divider()
    a, b, c = st.columns([1, 2, 1])
    a.button("◀ Anteriores", disabled=pag == 0, width="stretch", key=f"simrev_{sid}_ant", on_click=_ir, args=(chave_p, pag - 1))
    b.markdown(f"<div style='text-align:center;padding-top:6px'>Página {pag + 1} de {total_pag} · {len(sel)} questões</div>",
               unsafe_allow_html=True)
    c.button("Próximas ▶", disabled=pag >= total_pag - 1, width="stretch", key=f"simrev_{sid}_prox",
             on_click=_ir, args=(chave_p, pag + 1))


# ------------------------------------------------------------------ montagem
def _limpa_escolha(chave: str, validas):
    v = st.session_state.get(chave)
    if isinstance(v, list):
        st.session_state[chave] = [x for x in v if x in validas]


def _montagem(usuario: dict):
    uid, perfil = usuario["id"], usuario["perfil"]
    if _so_amostra() and _simulados_feitos(uid) >= AVALIACAO_SIMULADOS:
        st.info(f"Na avaliação grátis você pode fazer {AVALIACAO_SIMULADOS} simulado, e ele já foi feito (o resultado está "
                "em **Meu desempenho**). Adquira o acesso para fazer quantos simulados quiser, com as mais de 2.000 questões.")
        with st.popover("💳 Adquirir acesso"):
            _bloco_pagamento(usuario)
        return
    if _so_amostra():
        st.caption(f"🎁 Avaliação grátis: {AVALIACAO_SIMULADOS} simulado, montado com as questões da avaliação.")
    lei_aviso = st.session_state.pop("sim_aviso_lei", None)
    if lei_aviso:
        st.info(f"Simulado da lei **{lei_aviso}** já marcado na aba **🛠️ Montar meu simulado**, só com inéditas. "
                "Confira a quantidade e o tempo e comece.")
    if st.session_state.pop("sim_aviso_rx", False):
        st.info("Seus pontos fracos do Raio-X já estão marcados na aba **🛠️ Montar meu simulado**. "
                "Confira a quantidade e o tempo e comece.")
    st.caption("Prova com cronômetro e sem gabarito durante a resolução. No fim: nota, desempenho por assunto e "
               "revisão com os comentários. Tudo fica guardado em **Meu desempenho**.")
    incluir = True
    if perfil != "aluno":
        incluir = st.toggle("Incluir questões ainda em revisão", value=True, key="sim_rev",
                            help="Alunos só recebem questões aprovadas.")
    status = status_visiveis(perfil, incluir)
    c1, c2 = st.columns(2)
    so_ined = c1.toggle("Só questões inéditas", key="sim_ined", help="Deixa de fora as questões de provas anteriores.")
    nao_rep = c2.toggle("Não repetir questões que já fiz", key="sim_nrep",
                        help="Deixa de fora tudo o que você já respondeu, no app ou em simulados entregues.")
    banco = _banco_simulado(uid, status, so_ined, nao_rep)
    st.caption(f"{len(banco)} questões disponíveis com essas opções.")
    if not banco:
        st.info("Não há questões disponíveis com essas opções. Desmarque \"Não repetir\" ou \"Só inéditas\".")
        return
    config = {"so_ineditas": so_ined, "nao_repetir": nao_rep, "status": status}

    provao = trilha_atual() == "provao"
    t1, t2 = st.tabs(["🎯 Simulado modelo Provão" if provao else "🎯 Simulado modelo CFS", "🛠️ Montar meu simulado"])
    with t1:
        if provao:
            _aba_modelo_provao(uid, banco, config)
        else:
            _aba_modelo_cfs(uid, banco, config)
    with t2:
        _aba_personalizado(uid, banco, config, status, so_ined)


def _aba_modelo_provao(uid: int, banco: list[dict], config: dict):
    st.markdown(f"**{PROVAO_QUESTOES} questões de todas as matérias do curso**, divididas igualmente entre elas "
                "(a coordenação não informou quantas cairão de cada matéria). O que faltar numa matéria é completado "
                "com as outras.")
    st.number_input("Tempo de prova (minutos)", 10, 360, PROVAO_MINUTOS, step=10, key="sim_prov_min")
    st.button("Começar simulado modelo Provão", type="primary", key="sim_prov_ir",
              on_click=_comecar_provao, args=(uid, banco, config))


def _aba_modelo_cfs(uid: int, banco: list[dict], config: dict):
    n_leg = sum(CFS_LEGISLACAO.values())
    st.markdown(f"**{CFS_PORTUGUES + n_leg} questões, como na prova do CFS 2026:** {CFS_PORTUGUES} de Língua "
                f"Portuguesa ({CFS_PORT_TEXTO} a partir de textos) e {n_leg} de Legislação, na mesma "
                "distribuição de leis da prova.")
    with st.expander("Ver quantas questões de cada lei"):
        st.dataframe(pd.DataFrame([{"Lei": k, "Questões": v} for k, v in CFS_LEGISLACAO.items()]),
                     hide_index=True, width="stretch")
        st.caption("As 2 questões da Portaria 167 (fora do edital) viraram 1 da CE/MS e 1 do Dec. 10.769/02.")
    st.number_input("Tempo de prova (minutos)", 10, 360, CFS_MINUTOS, step=10, key="sim_cfs_min")
    st.button("Começar simulado modelo CFS", type="primary", key="sim_cfs_ir",
              on_click=_comecar_cfs, args=(uid, banco, config))


def _aba_personalizado(uid: int, banco: list[dict], config: dict, status: list[str], so_ined: bool):
    arvore =[g for g in _arvore(status, "inedita" if so_ined else "")]
    cont_g: dict[str, int] = {}
    cont_a: dict[int, int] = {}
    for q in banco:
        cont_g[q["grupo"]] = cont_g.get(q["grupo"], 0) + 1
        for a in q["assuntos"]:
            cont_a[a] = cont_a.get(a, 0) + 1
    grupos_ok = {g["sigla"]: g for g in arvore if cont_g.get(g["sigla"])}
    # Rótulos sem contagem: se a contagem mudasse (ex.: ao ligar "não repetir"), o Streamlit perderia a escolha.
    _limpa_escolha("sim_grupos", grupos_ok)
    grupos = st.multiselect(
        "Matérias / leis", list(grupos_ok), key="sim_grupos", placeholder="Todas (marque para escolher só algumas)",
        format_func=lambda s: s + (f" · {grupos_ok[s]['popular']}" if grupos_ok[s]["popular"]
                                   and grupos_ok[s]["popular"] != s else ""))
    subs = {a["id"]: (g["sigla"], a["nome"]) for s in grupos for g in [grupos_ok[s]] for a in g["subs"]
            if cont_a.get(a["id"])}
    _limpa_escolha("sim_assuntos", subs)
    assuntos = st.multiselect(
        "Assuntos (opcional)", list(subs), key="sim_assuntos", disabled=not grupos,
        placeholder="Todos os assuntos das leis escolhidas" if grupos else "Escolha primeiro as matérias/leis",
        format_func=lambda i: f"{subs[i][0]} › {subs[i][1]}")
    n_escolha = sum(1 for q in banco if (not grupos or q["grupo"] in grupos)
                    and (not assuntos or set(q["assuntos"]) & set(assuntos)))
    st.caption(f"{n_escolha} questões disponíveis nessa escolha.")
    c1, c2, c3 = st.columns([1, 1, 1])
    qtd = c1.number_input("Quantidade de questões", 5, 100, 20, step=5, key="sim_qtd")
    cron = c2.toggle("Com cronômetro", value=True, key="sim_cron")
    c3.number_input("Tempo (minutos)", 5, 360, 60, step=5, key="sim_min", disabled=not cron)
    ritmo = CFS_MINUTOS / (CFS_PORTUGUES + sum(CFS_LEGISLACAO.values()))
    st.caption(f"No ritmo do simulado modelo ({ritmo:.1f} min por questão), {qtd} questões pedem cerca de "
               f"{round(qtd * ritmo)} min. As questões são divididas igualmente entre as matérias/leis escolhidas.")
    st.button("Começar meu simulado", type="primary", key="sim_pers_ir",
              on_click=_comecar_personalizado, args=(uid, banco, config))


# Os botões de começar rodam como callback: o simulado já nasce antes de a tela ser desenhada de novo.
def _comecar_cfs(uid: int, banco: list[dict], config: dict):
    qs, avisos = _sortear_cfs(banco)
    if len(qs) < 10:
        st.session_state["sim_erro"] = "Poucas questões disponíveis para montar o simulado modelo. Desmarque alguma opção acima."
        return
    _criar_simulado(uid, "cfs", "Simulado modelo CFS", qs, int(st.session_state.get("sim_cfs_min", CFS_MINUTOS)), config)
    st.session_state["sim_avisos"] = avisos


def _comecar_provao(uid: int, banco: list[dict], config: dict):
    qs, _ = _sortear_personalizado(banco, [], set(), PROVAO_QUESTOES)
    if len(qs) < 5:
        st.session_state["sim_erro"] = "Poucas questões disponíveis para montar o simulado modelo. Desmarque alguma opção acima."
        return
    _criar_simulado(uid, "provao", "Simulado modelo Provão", qs, int(st.session_state.get("sim_prov_min", PROVAO_MINUTOS)),
                    config)
    st.session_state["sim_avisos"] = ([f"Por enquanto o banco do Provão tem {len(qs)} questões disponíveis com essas opções: "
                                       f"o simulado ficou com {len(qs)} (o modelo tem {PROVAO_QUESTOES})."]
                                      if len(qs) < PROVAO_QUESTOES else [])


def _comecar_personalizado(uid: int, banco: list[dict], config: dict):
    ss = st.session_state
    grupos, assuntos, qtd = ss.get("sim_grupos") or [], ss.get("sim_assuntos") or [], int(ss.get("sim_qtd", 20))
    qs, disponiveis = _sortear_personalizado(banco, grupos, set(assuntos), qtd)
    if not qs:
        ss["sim_erro"] = "Nenhuma questão com essas escolhas."
        return
    nome = (", ".join(grupos[:3]) + ("…" if len(grupos) > 3 else "")) if grupos else "todas as matérias"
    minutos = int(ss.get("sim_min", 60)) if ss.get("sim_cron", True) else None
    _criar_simulado(uid, "personalizado", f"Simulado personalizado · {nome}", qs, minutos,
                    config | {"grupos": grupos, "assuntos": assuntos, "quantidade": qtd})
    ss["sim_avisos"] = [f"Só havia {disponiveis} questões com essas escolhas: o simulado ficou com {len(qs)}."] \
        if len(qs) < qtd else []


def tela_simulados(usuario: dict):
    st.header("Simulados")
    if not st.session_state.get("sim_ver"):
        aberto = _simulado_aberto(usuario["id"])
        if aberto and _prova(aberto, usuario):
            return
    ver = st.session_state.get("sim_ver")
    if ver:
        st.button("◀ Voltar para os simulados", key="sim_voltar", on_click=lambda: st.session_state.pop("sim_ver", None))
        _resultado(ver, usuario)
        return
    erro = st.session_state.pop("sim_erro", None)
    if erro:
        st.error(erro)
    _montagem(usuario)


def _abrir_resultado(chave: str):
    st.session_state["sim_ver"] = st.session_state[chave]
    st.session_state["menu"] = "Simulados"


def _historico_simulados(usuario: dict):
    sims = db.consultar(
        """SELECT id, modelo, titulo, iniciado_em, total, acertos, tempo_seg, por_tempo
           FROM simulado WHERE usuario_id = %s AND status = 'finalizado'
             AND COALESCE(edital_id, %s) = %s ORDER BY iniciado_em DESC""",
        (usuario["id"], _edital_da_trilha("cfs"), edital_atual()))
    st.subheader("Meus simulados")
    if not sims:
        st.caption("Você ainda não entregou nenhum simulado. Vá em **Simulados** para fazer o primeiro.")
        return
    linhas = [{"Data": f"{_local(s['iniciado_em']):%d/%m/%Y %H:%M}",
               "Simulado": {"cfs": "Modelo CFS", "provao": "Modelo Provão"}.get(s["modelo"]) or
                           s["titulo"].replace("Simulado personalizado · ", ""),
               "Questões": s["total"], "Acertos": s["acertos"], "Nota": _nota_txt(s["acertos"] or 0, s["total"] or 0),
               "% de acerto": round(100 * (s["acertos"] or 0) / s["total"]) if s["total"] else 0,
               "Tempo": _fmt_tempo(s["tempo_seg"]) + (" (esgotou)" if s["por_tempo"] else "")} for s in sims]
    st.dataframe(pd.DataFrame(linhas), hide_index=True, width="stretch",
                 column_config={"% de acerto": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d%%")})
    if len(sims) >= 2:
        evol = list(reversed(linhas))[-15:]
        st.caption("Evolução do % de acerto (do primeiro para o último simulado)")
        grafico_barras([f"{i + 1}º" for i in range(len(evol))], [l["% de acerto"] for l in evol],
                       texto=lambda v: f"{v:.0f}%", maximo=100)
    rot = {s["id"]: f"{l['Data']} · {l['Simulado']} · nota {l['Nota']}" for s, l in zip(sims, linhas)}
    c1, c2 = st.columns([2, 1])
    c1.selectbox("Abrir um simulado", list(rot), format_func=rot.get, key="hist_sim", label_visibility="collapsed")
    c2.button("Ver resultado e revisão", key="hist_abrir", width="stretch", on_click=_abrir_resultado, args=("hist_sim",))


# ======================================================================
# TELAS_MATERIAIS
# ======================================================================
# Resumos e mapas mentais em PDF. O arquivo fica "limpo" no banco; na hora do download o app carimba
# em todas as páginas o nome, o usuário, a data e um código único (registrado em material_download).
TIPOS_MATERIAL = {"lei": "Lei seca comentada", "resumo": "Resumo em PDF", "mapa": "Mapa mental",
                  "relatorio": "Relatório de revisão", "bizu": "Ficha de bizu", "video": "Vídeo"}
ORDEM_TIPO_SQL = ("CASE tipo WHEN 'video' THEN 0 WHEN 'bizu' THEN 1 WHEN 'lei' THEN 2 WHEN 'resumo' THEN 3 "
                  "WHEN 'mapa' THEN 4 ELSE 5 END")
LIMITE_MATERIAL_MB = 15


@st.cache_resource(show_spinner=False)
def _garante_materiais() -> bool:
    db.executar(
        """CREATE TABLE IF NOT EXISTS material_estudo (
               id SERIAL PRIMARY KEY, titulo TEXT NOT NULL UNIQUE, lei TEXT NOT NULL,
               tipo TEXT NOT NULL, descricao TEXT, arquivo BYTEA NOT NULL,
               tamanho INT NOT NULL, paginas INT, publicado BOOLEAN NOT NULL DEFAULT FALSE, ordem INT NOT NULL DEFAULT 0,
               enviado_por INT REFERENCES usuario(id), criado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
               atualizado_em TIMESTAMPTZ NOT NULL DEFAULT now())""")
    db.executar(
        """CREATE TABLE IF NOT EXISTS material_download (
               id BIGSERIAL PRIMARY KEY, material_id INT NOT NULL REFERENCES material_estudo(id) ON DELETE CASCADE,
               usuario_id INT NOT NULL REFERENCES usuario(id), codigo TEXT NOT NULL UNIQUE,
               baixado_em TIMESTAMPTZ NOT NULL DEFAULT now())""")
    # tipos aceitos (inclui 'lei' = lei seca comentada); refaz a regra caso a tabela venha da versão anterior
    db.executar("ALTER TABLE material_estudo DROP CONSTRAINT IF EXISTS material_estudo_tipo_check")
    db.executar("ALTER TABLE material_estudo ADD CONSTRAINT material_estudo_tipo_check "
                "CHECK (tipo IN ('lei', 'resumo', 'mapa', 'relatorio', 'bizu', 'video'))")
    # vídeo = link (YouTube não listado); não guarda arquivo no banco
    db.executar("ALTER TABLE material_estudo ADD COLUMN IF NOT EXISTS url TEXT")
    db.executar("ALTER TABLE material_estudo ALTER COLUMN arquivo DROP NOT NULL")
    db.executar("""CREATE TABLE IF NOT EXISTS material_favorito (
                       usuario_id INT NOT NULL REFERENCES usuario(id) ON DELETE CASCADE, lei TEXT NOT NULL,
                       criado_em TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (usuario_id, lei))""")
    # trilha do material: 'cfs', 'provao' ou 'todas' (os materiais antigos ficam no CFS)
    db.executar("ALTER TABLE material_estudo ADD COLUMN IF NOT EXISTS trilha TEXT NOT NULL DEFAULT 'cfs'")
    # uso do material: cada linha de material_download é uma cópia carimbada (um código) aberta pelo aluno.
    # modo 'legado' = cópias da versão antiga (só existia "baixar"); 'estudo' = abertas no leitor do app.
    db.executar("ALTER TABLE material_download ADD COLUMN IF NOT EXISTS modo TEXT NOT NULL DEFAULT 'legado'")
    db.executar("ALTER TABLE material_download ADD COLUMN IF NOT EXISTS downloads INT NOT NULL DEFAULT 0")
    db.executar("ALTER TABLE material_download ADD COLUMN IF NOT EXISTS baixou_em TIMESTAMPTZ")
    db.executar("ALTER TABLE material_download ADD COLUMN IF NOT EXISTS maior_pagina INT")
    db.executar("ALTER TABLE material_download ADD COLUMN IF NOT EXISTS lido_em TIMESTAMPTZ")
    db.executar("CREATE INDEX IF NOT EXISTS ix_material_download_usuario ON material_download (usuario_id, material_id)")
    return True


# downloads do MESMO PDF pela mesma pessoa a partir dos quais o painel acende o alerta (não bloqueia nada)
ALERTA_DOWNLOADS_PDF = 3
# baixados por cópia: as cópias antigas (legado) contam como 1 download cada
SQL_DL = "(CASE WHEN d.modo = 'legado' THEN 1 ELSE d.downloads END)"


def _pagina_marca(largura: float, altura: float, nome: str, login: str, codigo: str, quando: str):
    """Uma página transparente com a marca-d'água (texto diagonal repetido) e a faixa de licença no topo."""
    from io import BytesIO
    from pypdf import PdfReader
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=(largura, altura))
    texto = f"{nome} · {login} · {codigo}"
    c.saveState()
    c.setFillColorRGB(0.35, 0.35, 0.35)
    c.setFillAlpha(0.075)
    c.setFont("Helvetica-Bold", 17)
    c.translate(largura / 2, altura / 2)
    c.rotate(32)
    passo_x, passo_y = c.stringWidth(texto, "Helvetica-Bold", 17) + 70, 120
    diag = (largura ** 2 + altura ** 2) ** 0.5
    y = -diag / 2
    linha = 0
    while y < diag / 2:
        x = -diag / 2 - (passo_x / 2 if linha % 2 else 0)
        while x < diag / 2:
            c.drawString(x, y, texto)
            x += passo_x
        y += passo_y
        linha += 1
    c.restoreState()
    c.setFillColorRGB(0.29, 0.35, 0.14)
    c.setFillAlpha(0.9)
    c.setFont("Helvetica", 6.5)
    c.drawCentredString(largura / 2, altura - 12,
                        f"Licenciado para {nome} ({login}) em {quando} · código {codigo} · "
                        "uso pessoal: proibido compartilhar ou reproduzir")
    c.save()
    return PdfReader(BytesIO(buf.getvalue())).pages[0]


def carimbar_pdf(dados: bytes, titulo: str, nome: str, login: str, codigo: str, quando: str) -> bytes:
    from io import BytesIO
    from pypdf import PdfReader, PdfWriter

    leitor = PdfReader(BytesIO(dados))
    escritor = PdfWriter()
    marcas = {}
    for pag in leitor.pages:
        w, h = float(pag.mediabox.width), float(pag.mediabox.height)
        chave = (round(w), round(h))
        if chave not in marcas:
            marcas[chave] = _pagina_marca(w, h, nome, login, codigo, quando)
        pag.merge_page(marcas[chave])
        escritor.add_page(pag)
    for pag in escritor.pages:
        pag.compress_content_streams()
    escritor.compress_identical_objects(remove_identicals=True, remove_orphans=True)
    escritor.add_metadata({"/Title": titulo, "/Author": NOME_APP,
                           "/Subject": f"Licenciado para {nome} ({login}) · código {codigo}"})
    saida = BytesIO()
    escritor.write(saida)
    return saida.getvalue()


def _nome_arquivo(titulo: str, login: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", titulo.lower().translate(str.maketrans("áàâãéêíóôõúüç", "aaaaeeiooouuc"))).strip("-")
    return f"{base}-{login}.pdf"


def _preparar_material(m: dict, usuario: dict):
    """Gera a cópia carimbada (nome, login e código único) e registra a abertura. Na mesma sessão a cópia é reaproveitada."""
    if st.session_state.get(f"mat_pdf_{m['id']}"):
        return
    arq = db.um("SELECT arquivo FROM material_estudo WHERE id = %s", (m["id"],))
    codigo = secrets.token_hex(3).upper()
    while db.um("SELECT 1 AS ok FROM material_download WHERE codigo = %s", (codigo,)):
        codigo = secrets.token_hex(3).upper()
    quando = f"{_local(pd.Timestamp.now(tz='UTC').to_pydatetime()):%d/%m/%Y %H:%M}"
    pdf = carimbar_pdf(bytes(arq["arquivo"]), m["titulo"], usuario["nome"], usuario["login"], codigo, quando)
    db.executar("INSERT INTO material_download (material_id, usuario_id, codigo, modo, lido_em) VALUES (%s, %s, %s, 'estudo', now())",
                (m["id"], usuario["id"], codigo))
    st.session_state[f"mat_pdf_{m['id']}"] = (pdf, codigo)


def _registrar_download(codigo: str):
    db.executar("UPDATE material_download SET downloads = downloads + 1, baixou_em = now() WHERE codigo = %s", (codigo,))


def _registrar_pagina(codigo: str, pagina: int):
    db.executar("""UPDATE material_download SET maior_pagina = GREATEST(COALESCE(maior_pagina, 0), %s), lido_em = now()
                   WHERE codigo = %s""", (pagina, codigo))


def _paginas_pdf(pdf: bytes) -> int:
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(pdf)
    try:
        return len(doc)
    finally:
        doc.close()


def _pagina_jpg(pdf: bytes, i: int) -> bytes:
    """Página i (0..n-1) da cópia carimbada como imagem: abre em qualquer celular, sem leitor de PDF."""
    from io import BytesIO
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(pdf)
    try:
        pg = doc[i]
        escala = max(1.0, min(2.0, 1300 / max(pg.get_width(), 1)))   # ~1300 px de largura: dá para ampliar no celular
        img = pg.render(scale=escala).to_pil().convert("RGB")
    finally:
        doc.close()
    buf = BytesIO()
    img.save(buf, "JPEG", quality=78, optimize=True)
    return buf.getvalue()


def _ir_pagina(mid: int, pagina: int):
    st.session_state[f"mat_pg_{mid}"] = pagina


@st.dialog("📖 Estudar", width="large")
def _leitor_material(m: dict, usuario: dict):
    """Leitor dentro do app: o aluno estuda página por página; baixar o PDF é a segunda opção, no fim."""
    _preparar_material(m, usuario)
    pdf, codigo = st.session_state[f"mat_pdf_{m['id']}"]
    chave_n = f"mat_np_{m['id']}"
    if chave_n not in st.session_state:
        st.session_state[chave_n] = _paginas_pdf(pdf)
    n = st.session_state[chave_n]
    pg = min(max(1, st.session_state.get(f"mat_pg_{m['id']}", 1)), n)
    st.markdown(f"**{esc(m['titulo'])}**", unsafe_allow_html=True)

    def navegacao(onde: str):
        # numa linha só, também no celular (st.columns empilharia os botões)
        with st.container(horizontal=True, horizontal_alignment="distribute", vertical_alignment="center"):
            st.button("◀", key=f"mat_ant_{onde}_{m['id']}", disabled=pg <= 1, help="Página anterior",
                      on_click=_ir_pagina, args=(m["id"], pg - 1))
            st.markdown(f"Página **{pg}** de {n}", width="content")
            st.button("Próxima ▶", key=f"mat_prox_{onde}_{m['id']}", disabled=pg >= n, type="primary",
                      on_click=_ir_pagina, args=(m["id"], pg + 1))

    navegacao("topo")
    cache = st.session_state.setdefault("mat_img_cache", {})
    chave = (m["id"], pg)
    if chave not in cache:
        with st.spinner("Abrindo a página..."):
            cache[chave] = _pagina_jpg(pdf, pg - 1)
        while len(cache) > 8:                       # guarda só as últimas páginas abertas
            cache.pop(next(iter(cache)))
    vistas = st.session_state.setdefault("mat_pg_vistas", set())
    if (codigo, pg) not in vistas:
        _registrar_pagina(codigo, pg)
        vistas.add((codigo, pg))
    # <img> com largura 100%: o st.image(width="stretch") dentro do diálogo nasce com 16 px até a tela redesenhar
    b64 = base64.b64encode(cache[chave]).decode()
    st.markdown(f'<img src="data:image/jpeg;base64,{b64}" alt="Página {pg}" '
                'style="width:100%;height:auto;border:1px solid rgba(128,128,128,.25);border-radius:6px">',
                unsafe_allow_html=True)
    if n > 1:
        navegacao("base")
    if n > 3:
        st.select_slider("Ir para a página", options=list(range(1, n + 1)), value=pg, key=f"mat_ir_{m['id']}_{pg}",
                         on_change=lambda: _ir_pagina(m["id"], st.session_state[f"mat_ir_{m['id']}_{pg}"]))
    st.divider()
    st.caption(f"Cópia licenciada para você · código **{codigo}**. Prefere estudar fora do app? Baixe o PDF "
               "(ele sai com o seu nome e esse código em todas as páginas).")
    st.download_button("📥 Baixar o PDF", data=pdf, file_name=_nome_arquivo(m["titulo"], usuario["login"]),
                       mime="application/pdf", key=f"mat_dl_{m['id']}", on_click=_registrar_download, args=(codigo,))


@st.cache_resource
def _garante_extras() -> bool:
    """Colunas novas que o app cria sozinho se o SQL ainda não tiver sido rodado no banco."""
    db.executar("ALTER TABLE questao ADD COLUMN IF NOT EXISTS essencial BOOLEAN NOT NULL DEFAULT FALSE")
    db.executar("ALTER TABLE usuario ADD COLUMN IF NOT EXISTS acesso_ate TIMESTAMPTZ")
    db.executar("ALTER TABLE usuario ADD COLUMN IF NOT EXISTS acesso_tipo TEXT")
    db.executar("ALTER TABLE questao ADD COLUMN IF NOT EXISTS amostra BOOLEAN NOT NULL DEFAULT FALSE")
    db.executar("ALTER TABLE usuario ADD COLUMN IF NOT EXISTS whatsapp TEXT")
    db.executar("ALTER TABLE usuario ADD COLUMN IF NOT EXISTS concurso TEXT NOT NULL DEFAULT 'cfs'")
    db.executar("ALTER TABLE questao DROP CONSTRAINT IF EXISTS questao_tipo_check")
    db.executar("ALTER TABLE questao ADD CONSTRAINT questao_tipo_check CHECK (tipo IN ('lei_seca', 'caso_pratico', 'portugues', 'teoria'))")
    db.executar("ALTER TABLE simulado DROP CONSTRAINT IF EXISTS simulado_modelo_check")
    db.executar("ALTER TABLE simulado ADD CONSTRAINT simulado_modelo_check CHECK (modelo IN ('cfs', 'personalizado', 'provao'))")
    db.executar("CREATE TABLE IF NOT EXISTS app_config (chave TEXT PRIMARY KEY, valor TEXT NOT NULL)")
    db.executar("""CREATE TABLE IF NOT EXISTS sessao_login (
                       token_hash TEXT PRIMARY KEY, usuario_id INT NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
                       criado_em TIMESTAMPTZ NOT NULL DEFAULT now(), expira_em TIMESTAMPTZ NOT NULL,
                       ultimo_uso TIMESTAMPTZ NOT NULL DEFAULT now())""")
    db.executar("ALTER TABLE sessao_login ADD COLUMN IF NOT EXISTS navegador TEXT")
    db.executar("""CREATE TABLE IF NOT EXISTS pagamento (
                       id SERIAL PRIMARY KEY, usuario_id INT NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
                       valor NUMERIC(10,2) NOT NULL CHECK (valor > 0), pago_em TIMESTAMPTZ NOT NULL DEFAULT now(),
                       acesso_ate TIMESTAMPTZ, descricao TEXT, registrado_por INT REFERENCES usuario(id))""")
    db.executar("""CREATE TABLE IF NOT EXISTS satisfacao (
                       id SERIAL PRIMARY KEY, usuario_id INT NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
                       nota SMALLINT CHECK (nota BETWEEN 0 AND 10), comentario TEXT, trilha TEXT NOT NULL DEFAULT 'cfs',
                       acesso_tipo TEXT, criado_em TIMESTAMPTZ NOT NULL DEFAULT now())""")
    db.executar("CREATE INDEX IF NOT EXISTS ix_satisfacao_usuario ON satisfacao (usuario_id, criado_em DESC)")
    return True


def config_app(chave: str, padrao: str) -> str:
    r = db.um("SELECT valor FROM app_config WHERE chave = %s", (chave,))
    return r["valor"] if r else padrao


def definir_config(chave: str, valor: str):
    db.executar("INSERT INTO app_config (chave, valor) VALUES (%s, %s) ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor",
                (chave, valor))


TURMA_MIN_RESP = 30      # respostas de um assunto para entrar em "onde a turma mais erra"
TURMA_MIN_ALUNOS = 5     # pessoas diferentes respondendo esse assunto


def _turma_erra(sigla: str, status: list[str]) -> list[dict]:
    """Assuntos da lei em que a turma mais erra (última resposta de cada pessoa em cada questão)."""
    return db.consultar(
        """WITH ult AS (
               SELECT DISTINCT ON (r.usuario_id, r.questao_id) r.usuario_id, r.questao_id, r.acertou
               FROM resposta r JOIN questao q ON q.id = r.questao_id
               WHERE q.status::text = ANY(%(st)s)""" + filtro_trilha() + """
               ORDER BY r.usuario_id, r.questao_id, r.respondida_em DESC)
           SELECT a.id, a.nome, COUNT(*) AS n, COUNT(DISTINCT u.usuario_id) AS pessoas,
                  ROUND(100.0 * AVG(u.acertou::int)) AS pct
           FROM ult u JOIN questao_assunto qa ON qa.questao_id = u.questao_id JOIN assunto a ON a.id = qa.assunto_id
           JOIN materia m ON m.id = a.materia_id LEFT JOIN diploma d ON d.id = a.diploma_id
           WHERE COALESCE(d.sigla, m.nome) = %(g)s
           GROUP BY a.id, a.nome
           HAVING COUNT(*) >= %(mr)s AND COUNT(DISTINCT u.usuario_id) >= %(ma)s
           ORDER BY pct, n DESC LIMIT 3""",
        {"st": status, "g": sigla, "mr": TURMA_MIN_RESP, "ma": TURMA_MIN_ALUNOS})


def _ir_essenciais(sigla: str, perfil: str):
    """Abre Resolver questões só com as essenciais da lei."""
    arv = _arvore(status_visiveis(perfil, True), "")
    g = next((x for x in arv if x["sigla"] == sigla), None)
    if g is None:
        return
    st.session_state["f_orig"] = ORIGENS[""]
    st.session_state["f_grupo"] = g["rotulo"]
    st.session_state[f"f_sub_{sigla}"] = []
    st.session_state["f_sit"] = SITUACOES["essenciais"]
    st.session_state.pop("filtro_ativo", None)
    st.session_state["menu"] = "Resolver questões"


def _ir_simulado_lei(sigla: str, qtd: int):
    """Abre Simulados com a lei marcada, só inéditas."""
    st.session_state["sim_grupos"] = [sigla]
    st.session_state["sim_assuntos"] = []
    st.session_state["sim_qtd"] = qtd
    st.session_state["sim_ined"] = True
    st.session_state.pop("sim_ver", None)
    st.session_state["sim_aviso_lei"] = sigla
    st.session_state["menu"] = "Simulados"


def _revisao_lei(sigla: str, usuario: dict):
    """Bloco "Revisão da lei" na aba Materiais: essenciais, simulado da lei e onde a turma mais erra."""
    status = status_visiveis(usuario["perfil"], True)
    c = db.um(
        """SELECT COUNT(DISTINCT q.id) FILTER (WHERE q.essencial) AS ess,
                  COUNT(DISTINCT q.id) FILTER (WHERE q.origem::text = 'inedita') AS ined
           FROM questao q JOIN questao_assunto qa ON qa.questao_id = q.id JOIN assunto a ON a.id = qa.assunto_id
           JOIN materia m ON m.id = a.materia_id LEFT JOIN diploma d ON d.id = a.diploma_id
           WHERE q.status::text = ANY(%s) AND COALESCE(d.sigla, m.nome) = %s""" + (FILTRO_AMOSTRA if _so_amostra() else "")
        + filtro_trilha(),
        (status, sigla))
    if not c or not (c["ess"] or c["ined"]):
        return
    with st.container(border=True):
        st.markdown("**🎯 Revisão da lei**")
        b1, b2 = st.columns(2)
        b1.button(f"⭐ Questões essenciais ({c['ess']})", key=f"rv_ess_{sigla}", width="stretch",
                  disabled=not c["ess"], on_click=_ir_essenciais, args=(sigla, usuario["perfil"]),
                  help="As questões que a equipe separou como indispensáveis para a prova.")
        qtd = max(5, min(20, (c["ined"] // 5) * 5))
        b2.button(f"📝 Simulado da lei ({qtd} inéditas)", key=f"rv_sim_{sigla}", width="stretch",
                  disabled=c["ined"] < 5, on_click=_ir_simulado_lei, args=(sigla, qtd))
        turma = _turma_erra(sigla, status)
        if turma:
            st.markdown("Onde a turma mais erra nesta lei: " + " · ".join(
                f"<b>{esc(t['nome'])}</b> ({int(t['pct'])}% de acerto)" for t in turma), unsafe_allow_html=True)
        else:
            st.caption("\"Onde a turma mais erra\" aparece aqui quando houver respostas suficientes nesta lei.")


MATERIA_BIZUS = "Bizus de Prova"     # matéria especial: vídeos-bizu e fichas de bizu de todas as matérias
ICONE_TIPO = {"video": "🎬", "bizu": "🎯", "lei": "📜", "resumo": "📄", "mapa": "🧠", "relatorio": "📊"}


def _ancora_lei(lei: str) -> str:
    """'Ordem Unida' → 'mat-ordem-unida' (chave estável de cada matéria na tela de Materiais)."""
    t = unicodedata.normalize("NFKD", lei).encode("ascii", "ignore").decode().lower()
    return "mat-" + (re.sub(r"[^a-z0-9]+", "-", t).strip("-") or "geral")


def _favoritas(uid: int) -> set[str]:
    return {r["lei"] for r in db.consultar("SELECT lei FROM material_favorito WHERE usuario_id = %s", (uid,))}


def _alternar_favorita(uid: int, lei: str):
    if db.um("SELECT 1 AS ok FROM material_favorito WHERE usuario_id = %s AND lei = %s", (uid, lei)):
        db.executar("DELETE FROM material_favorito WHERE usuario_id = %s AND lei = %s", (uid, lei))
    else:
        db.executar("INSERT INTO material_favorito (usuario_id, lei) VALUES (%s, %s) ON CONFLICT DO NOTHING", (uid, lei))


def _abrir_materia(lei: str | None):
    if lei is None:
        st.session_state.pop("mat_materia", None)
    else:
        st.session_state["mat_materia"] = lei


def _contagem(itens: list) -> str:
    v = sum(1 for m in itens if m["tipo"] == "video")
    p = len(itens) - v
    partes = ([f"{p} PDF" + ("s" if p != 1 else "")] if p else []) + ([f"{v} vídeo" + ("s" if v != 1 else "")] if v else [])
    return " · ".join(partes)


def tela_materiais(usuario: dict):
    _garante_materiais()
    equipe = usuario["perfil"] in ("admin", "revisor")
    mats = db.consultar(
        "SELECT id, titulo, lei, tipo, descricao, tamanho, paginas, publicado, trilha, url, atualizado_em FROM material_estudo "
        f"WHERE (publicado OR %s) AND trilha IN (%s, 'todas') ORDER BY ordem, lei, {ORDEM_TIPO_SQL}, titulo",
        (equipe, trilha_atual()))
    abertos = {r["material_id"]: r["pg"] for r in db.consultar(
        "SELECT material_id, MAX(COALESCE(maior_pagina, 0)) AS pg FROM material_download WHERE usuario_id = %s "
        "GROUP BY material_id", (usuario["id"],))}
    lei_aberta = st.session_state.get("mat_materia")
    if lei_aberta and any(m["lei"] == lei_aberta for m in mats):
        _tela_materia(lei_aberta, [m for m in mats if m["lei"] == lei_aberta], abertos, usuario)
        return

    st.header("Materiais")
    st.caption("Escolha a matéria: lá dentro estão os vídeos e os PDFs (lei seca comentada, resumos, mapas mentais, "
               "fichas de bizu e relatórios). Os PDFs abrem direto no app, com o **seu nome e um código** em todas as "
               "páginas: é para seu estudo, não compartilhe.")
    if usuario["perfil"] == "admin":
        with st.expander("⚙️ Gerenciar materiais (só administrador)"):
            _gerenciar_materiais(usuario)
    if em_avaliacao(usuario):
        with st.container(border=True):
            st.markdown("**Você está na avaliação grátis.** Os vídeos estão liberados e você pode abrir **1 PDF** (um "
                        "resumo, mapa mental ou ficha de bizu, da matéria que escolher). O resto é liberado na aquisição.")
            with st.popover("💳 Adquirir acesso"):
                _bloco_pagamento(usuario)
    if not mats:
        st.info("Ainda não há materiais publicados. Eles vão aparecer aqui.")
        return

    favs = _favoritas(usuario["id"])
    pos = {nome: i for i, nome in enumerate(ORDEM_GRUPOS)}
    leis = sorted({m["lei"] for m in mats},
                  key=lambda s: (s not in favs, s != MATERIA_BIZUS, pos.get(s, len(pos)), s))
    n_v = sum(1 for m in mats if m["tipo"] == "video")
    st.markdown(f"📚 **{len(leis)} matérias** · {_contagem(mats)}"
                + (" · ⭐ suas favoritas aparecem primeiro" if favs else " · toque na ☆ para favoritar uma matéria"))
    busca = st.text_input("Buscar matéria", key="mat_busca", placeholder="ex.: CPPM, Choque, Maria da Penha",
                          label_visibility="collapsed")
    if busca.strip():
        alvo = unicodedata.normalize("NFKD", busca.lower()).encode("ascii", "ignore").decode()
        leis = [l for l in leis if alvo in unicodedata.normalize("NFKD", l.lower()).encode("ascii", "ignore").decode()]
        if not leis:
            st.caption("Nenhuma matéria com esse nome.")
    for i in range(0, len(leis), 3):
        cols = st.columns(3)
        for col, lei in zip(cols, leis[i:i + 3]):
            itens = [m for m in mats if m["lei"] == lei]
            feitos = sum(1 for m in itens if m["id"] in abertos)
            pct = feitos / len(itens) if itens else 0
            ult = max(m["atualizado_em"] for m in itens)
            rasc = sum(1 for m in itens if not m["publicado"])
            with col.container(border=True):
                topo = st.container(horizontal=True, vertical_alignment="top")
                topo.markdown(f"<span style='color:#b8862b;font-size:.78rem;font-weight:700;letter-spacing:.04em'>"
                              f"{'🎯 NOVIDADE' if lei == MATERIA_BIZUS else esc(_contagem(itens).upper())}</span>",
                              unsafe_allow_html=True, width="stretch")
                topo.button("★" if lei in favs else "☆", key=f"mat_fav_{_ancora_lei(lei)}", type="tertiary",
                            help="Tirar das favoritas" if lei in favs else "Favoritar (aparece primeiro)",
                            on_click=_alternar_favorita, args=(usuario["id"], lei))
                st.markdown(f"<div style='font-weight:700;font-size:1.02rem;line-height:1.3;min-height:2.6em'>{esc(lei)}</div>",
                            unsafe_allow_html=True)
                st.caption((_contagem(itens) + " · " if lei == MATERIA_BIZUS else "")
                           + f"Atualizado em {_local(ult):%d/%m/%Y}" + (f" · 🔒 {rasc} rascunho(s)" if rasc else ""))
                st.progress(pct, text=f"{round(pct * 100)}% estudado ({feitos} de {len(itens)})")
                st.button("Abrir matéria", key=f"mat_abrir_{_ancora_lei(lei)}", type="primary", width="stretch",
                          on_click=_abrir_materia, args=(lei,))


def _tela_materia(lei: str, itens: list, abertos: dict, usuario: dict):
    """Página da matéria: vídeos primeiro, depois os PDFs, com o progresso do aluno."""
    st.button("← Todas as matérias", key="mat_voltar", type="tertiary", on_click=_abrir_materia, args=(None,))
    favs = _favoritas(usuario["id"])
    with st.container(horizontal=True, vertical_alignment="center"):
        st.header(lei, width="stretch")
        st.button("★ Favorita" if lei in favs else "☆ Favoritar", key="mat_fav_pag", on_click=_alternar_favorita,
                  args=(usuario["id"], lei))
    feitos = sum(1 for m in itens if m["id"] in abertos)
    st.progress(feitos / len(itens), text=f"Você já abriu {feitos} de {len(itens)} ({_contagem(itens)})")
    _revisao_lei(lei, usuario)
    avaliacao = em_avaliacao(usuario)
    baixados = _pdfs_baixados(usuario["id"]) if avaliacao else set()
    if avaliacao:
        st.caption("Você está na avaliação grátis: vídeos liberados e **1 PDF** (resumo, mapa mental ou ficha de bizu).")
    videos = [m for m in itens if m["tipo"] == "video"]
    pdfs = [m for m in itens if m["tipo"] != "video"]
    if videos:
        st.subheader("🎬 Vídeos")
        for m in videos:
            with st.container(border=True):
                _cabecalho_item(m, abertos)
                if usuario["perfil"] == "admin":
                    _acoes_material(m, usuario)
                if st.button("▶ Assistir", key=f"mat_ver_{m['id']}", type="primary"):
                    _registrar_video(m, usuario)
                    _player_video(m)
    if pdfs:
        st.subheader("📄 PDFs")
        for m in pdfs:
            with st.container(border=True):
                _cabecalho_item(m, abertos)
                if usuario["perfil"] == "admin":
                    _acoes_material(m, usuario)
                if avaliacao:
                    if m["tipo"] not in AVALIACAO_TIPOS_PDF:
                        st.caption("🔒 A lei seca comentada e o relatório de revisão são liberados na aquisição do acesso.")
                        continue
                    if baixados and m["id"] not in baixados and len(baixados) >= AVALIACAO_PDFS:
                        st.caption("🔒 Você já usou o seu PDF grátis da avaliação. Os demais são liberados na aquisição.")
                        continue
                    st.caption("🎁 Na avaliação você pode abrir **1** resumo, mapa mental ou ficha de bizu.")
                if st.button("📖 Estudar agora", key=f"mat_prep_{m['id']}", type="primary"):
                    with st.spinner("Preparando sua cópia..."):
                        _preparar_material(m, usuario)
                    _leitor_material(m, usuario)
                pronto = st.session_state.get(f"mat_pdf_{m['id']}")
                if pronto:
                    st.caption(f"Código da sua cópia: **{pronto[1]}**.")


def _cabecalho_item(m: dict, abertos: dict):
    rasc = "" if m["publicado"] else " · 🔒 rascunho (alunos ainda não veem)"
    feito = " · ✅ já abriu" if m["id"] in abertos else ""
    if m["tipo"] != "video" and abertos.get(m["id"]):
        feito = f" · ✅ leu até a pág. {abertos[m['id']]}"
    st.markdown(f"{ICONE_TIPO.get(m['tipo'], '📄')} **{esc(m['titulo'])}**", unsafe_allow_html=True)
    info = TIPOS_MATERIAL.get(m["tipo"], m["tipo"])
    if m["tipo"] != "video":
        info += f" · {m['paginas'] or '?'} página(s)"
    st.caption(info + feito + rasc)
    if m["descricao"]:
        st.write(m["descricao"])


def _registrar_video(m: dict, usuario: dict):
    """Abrir um vídeo conta no progresso (uma vez por sessão)."""
    if st.session_state.get(f"mat_vid_{m['id']}"):
        return
    codigo = "V" + secrets.token_hex(4).upper()
    db.executar("INSERT INTO material_download (material_id, usuario_id, codigo, modo, lido_em) VALUES (%s, %s, %s, 'video', now())",
                (m["id"], usuario["id"], codigo))
    st.session_state[f"mat_vid_{m['id']}"] = codigo


@st.dialog("🎬 Assistir", width="large")
def _player_video(m: dict):
    st.markdown(f"**{esc(m['titulo'])}**", unsafe_allow_html=True)
    if m.get("url"):
        st.video(m["url"])
    else:
        st.warning("Este vídeo ainda está sem link.")


PREFIXOS_MATERIAL = {"lc190": "LC 190/14", "abuso": "Lei 13.869/19", "lc053": "LC 053/90", "mariadapenha": "Lei 11.340/06",
                     "rdpmms": "RDPMMS", "cppm": "CPPM", "cpm": "CPM", "drogas": "Lei 11.343/06",
                     "desarmamento": "Lei 10.826/03", "tortura": "Lei 9.455/97", "cf": "CF/88", "ce": "CE/MS",
                     "lc127": "LC 127/08", "dec1261": "Dec. 1.261/81", "dec1093": "Dec. 1.093/81",
                     "dec10769": "Dec. 10.769/02", "portugues": "Língua Portuguesa",
                     "penal": "Direito Penal", "codigopenal": "Direito Penal",
                     "diversidade": "Diversidade, Gênero e Combate à Discriminação", "genero": "Diversidade, Gênero e Combate à Discriminação",
                     "racismo": "Diversidade, Gênero e Combate à Discriminação", "indigenas": "Povos Indígenas de MS",
                     "tea": "Atendimento à Pessoa com TEA", "autismo": "Atendimento à Pessoa com TEA",
                     "choque": "Policiamento de Choque", "ostensivo": "Técnicas de Policiamento Ostensivo",
                     "tpo": "Técnicas de Policiamento Ostensivo", "processual": "Direito Processual Penal",
                     "processo": "Direito Processual Penal", "forca": "Uso Diferenciado da Força",
                     "aph": "Atendimento Pré-Hospitalar (APH)", "inteligencia": "Inteligência de Segurança Pública",
                     "topicos": "Leis Penais Extravagantes e Segurança Pública (Abuso de Autoridade e Maria da Penha)",
                     "direitoshumanos": "Direitos Humanos", "dh": "Direitos Humanos",
                     "processos": "Processos e Procedimentos Administrativos", "p187": "Processos e Procedimentos Administrativos",
                     "bravura": "Processos e Procedimentos Administrativos", "dec2426": "Processos e Procedimentos Administrativos",
                     "dpm": "Direito Penal Militar", "penalmilitar": "Direito Penal Militar",
                     "legpm": "Legislação Policial-Militar", "legislacaopm": "Legislação Policial-Militar",
                     "transito": "Policiamento de Trânsito", "contran": "Policiamento de Trânsito",
                     "impo": "Instrumentos de Menor Potencial Ofensivo", "eventos": "Policiamento em Eventos",
                     "ambiental": "Legislação Ambiental", "comunicacao": "Comunicação Social e Imagem Institucional",
                     "armamento": "Armamento e Munição I", "ordemunida": "Ordem Unida", "cp": "Direito Penal"}
TRILHA_MATERIAL = {"cfs": "Só CFS", "provao": "Só Provão CFS 2026", "todas": "As duas trilhas"}
TITULO_TIPO = {"lei": "Lei seca comentada", "resumo": "Resumo esquematizado", "mapa": "Mapa mental",
               "relatorio": "Relatório de revisão", "bizu": "Ficha de bizu", "video": "Vídeo"}


def _leis_material() -> list[str]:
    materias = [m["nome"] for m in db.consultar("SELECT nome FROM materia WHERE nome <> 'Legislação' ORDER BY id")]
    return [MATERIA_BIZUS] + materias + [d["sigla"] for d in db.consultar("SELECT sigla FROM diploma ORDER BY id")] + ["Geral"]


def _adivinhar_material(nome_arquivo: str, leis: list[str]) -> tuple[str, str, str]:
    """'lc190_resumo.pdf' → ('LC 190/14 · Resumo esquematizado', 'LC 190/14', 'resumo'). O que não reconhecer vai como 'Geral'."""
    base = re.sub(r"\s*\(\d+\)$", "", re.sub(r"\.pdf$", "", nome_arquivo.strip().lower()))
    partes = re.split(r"[_\-\s]+", base)
    tipo = next((t for t in ("bizu", "relatorio", "resumo", "mapa", "lei") if t in partes), "resumo")
    lei = MATERIA_BIZUS if tipo == "bizu" else next((PREFIXOS_MATERIAL[p] for p in partes if p in PREFIXOS_MATERIAL), "Geral")
    if lei not in leis:
        lei = "Geral"
    if tipo == "bizu":
        resto = " ".join(p for p in partes if p != "bizu").strip() or "tema"
        return f"Bizu · {resto.capitalize()}", lei, tipo
    titulo = f"{lei} · {TITULO_TIPO[tipo]}" if lei != "Geral" else nome_arquivo.rsplit(".", 1)[0]
    return titulo, lei, tipo


def _ler_pdf(dados: bytes) -> int | None:
    from io import BytesIO
    from pypdf import PdfReader
    try:
        return len(PdfReader(BytesIO(dados)).pages)
    except Exception:
        return None


def _guardar_material(titulo, lei, tipo, descricao, dados, paginas, publicar, uid):
    db.executar(
        """INSERT INTO material_estudo (titulo, lei, tipo, descricao, arquivo, tamanho, paginas, publicado, enviado_por, trilha)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (titulo) DO UPDATE SET lei = EXCLUDED.lei, tipo = EXCLUDED.tipo, trilha = EXCLUDED.trilha,
               descricao = COALESCE(EXCLUDED.descricao, material_estudo.descricao), arquivo = EXCLUDED.arquivo,
               tamanho = EXCLUDED.tamanho, paginas = EXCLUDED.paginas, publicado = EXCLUDED.publicado,
               atualizado_em = now()""",
        (titulo, lei, tipo, descricao, dados, len(dados), paginas, publicar, uid, trilha_atual()))


def _acoes_material(m: dict, usuario: dict):
    """Botões do administrador em cada material: publicar/tirar do ar, editar (renomear, trocar o PDF) e excluir."""
    mid = m["id"]
    c1, c2, c3 = st.columns(3)
    if m["publicado"]:
        if c1.button("Tirar do ar (voltar a rascunho)", key=f"mat_off_{mid}", width="stretch"):
            db.executar("UPDATE material_estudo SET publicado = FALSE, atualizado_em = now() WHERE id = %s", (mid,))
            st.rerun()
    elif c1.button("Publicar para os alunos", key=f"mat_on_{mid}", type="primary", width="stretch"):
        db.executar("UPDATE material_estudo SET publicado = TRUE, atualizado_em = now() WHERE id = %s", (mid,))
        st.rerun()
    with c2.popover("✏️ Editar", width="stretch"):
        leis = _leis_material()
        with st.form(f"mat_ed_{mid}"):
            titulo = st.text_input("Título", value=m["titulo"], key=f"mat_ed_tit_{mid}")
            lei = st.selectbox("Lei / matéria", leis, index=leis.index(m["lei"]) if m["lei"] in leis else len(leis) - 1,
                               key=f"mat_ed_lei_{mid}")
            tipos = ["video"] if m["tipo"] == "video" else [t for t in TIPOS_MATERIAL if t != "video"]
            tipo = st.selectbox("Tipo", tipos, index=tipos.index(m["tipo"]) if m["tipo"] in tipos else 0,
                                format_func=TIPOS_MATERIAL.get, key=f"mat_ed_tipo_{mid}")
            trilhas = list(TRILHA_MATERIAL)
            trilha = st.selectbox("Trilha", trilhas, index=trilhas.index(m.get("trilha") or "cfs"),
                                  format_func=TRILHA_MATERIAL.get, key=f"mat_ed_tri_{mid}",
                                  help="Em qual trilha o material aparece para os alunos.")
            desc = st.text_area("Descrição curta (opcional)", value=m["descricao"] or "", height=68, key=f"mat_ed_desc_{mid}")
            if m["tipo"] == "video":
                url = st.text_input("Link do vídeo (YouTube)", value=m.get("url") or "", key=f"mat_ed_url_{mid}")
                arq = None
            else:
                url = None
                arq = st.file_uploader("Trocar o PDF (opcional)", type=["pdf"], key=f"mat_ed_arq_{mid}")
            salvar = st.form_submit_button("Salvar alterações", type="primary")
        if salvar:
            titulo = titulo.strip()
            outro = db.um("SELECT id FROM material_estudo WHERE titulo = %s AND id <> %s", (titulo, mid))
            if not titulo or outro:
                st.error("Título vazio ou já usado por outro material.")
            else:
                db.executar("""UPDATE material_estudo SET titulo = %s, lei = %s, tipo = %s, descricao = %s, trilha = %s,
                               atualizado_em = now() WHERE id = %s""", (titulo, lei, tipo, desc.strip() or None, trilha, mid))
                if url is not None:
                    db.executar("UPDATE material_estudo SET url = %s WHERE id = %s", (url.strip() or None, mid))
                if arq is not None:
                    dados = arq.getvalue()
                    pag = _ler_pdf(dados)
                    if pag is None or len(dados) > LIMITE_MATERIAL_MB * 1048576:
                        st.error("O PDF novo não foi aceito (inválido ou grande demais); o resto foi salvo.")
                        return
                    db.executar("UPDATE material_estudo SET arquivo = %s, tamanho = %s, paginas = %s WHERE id = %s",
                                (dados, len(dados), pag, mid))
                st.session_state.pop(f"mat_pdf_{mid}", None)
                st.rerun()
    with c3.popover("🗑️ Excluir", width="stretch"):
        st.markdown(f"Excluir **{esc(m['titulo'])}**? Some para os alunos e apaga o registro dos downloads.",
                    unsafe_allow_html=True)
        if st.button("Apagar definitivamente", key=f"mat_apagar_{mid}", type="primary", width="stretch"):
            db.executar("DELETE FROM material_estudo WHERE id = %s", (mid,))
            st.session_state.pop(f"mat_pdf_{mid}", None)
            st.rerun()


def _form_video(leis: list, usuario: dict):
    """Vídeo entra como link (YouTube "não listado"): o arquivo fica no YouTube, o app só guarda o endereço."""
    st.markdown("**Adicionar vídeo** (link do YouTube)")
    with st.form("mat_video", clear_on_submit=True):
        c1, c2 = st.columns([1.4, 1])
        titulo = c1.text_input("Título", placeholder="ex.: Bizu · Flagrante tem prazo?")
        lei = c2.selectbox("Matéria", leis, index=0)
        url = st.text_input("Link do vídeo", placeholder="https://youtu.be/...")
        desc = st.text_input("Descrição curta (opcional)")
        publicar = st.checkbox("Publicar já para os alunos", value=True)
        ok = st.form_submit_button("Guardar vídeo", type="primary")
    if ok:
        titulo, url = titulo.strip(), url.strip()
        if not titulo or not re.match(r"https?://", url):
            st.error("Preencha o título e um link que comece com http.")
        elif db.um("SELECT 1 AS ok FROM material_estudo WHERE titulo = %s", (titulo,)):
            st.error("Já existe um material com esse título.")
        else:
            db.executar("""INSERT INTO material_estudo (titulo, lei, tipo, descricao, arquivo, tamanho, paginas, publicado,
                                                        enviado_por, trilha, url)
                           VALUES (%s, %s, 'video', %s, NULL, 0, NULL, %s, %s, %s, %s)""",
                        (titulo, lei, desc.strip() or None, publicar, usuario["id"], trilha_atual(), url))
            st.success(f"Vídeo \"{titulo}\" guardado em {lei}.")


def _gerenciar_materiais(usuario: dict):
    """Envio em lote: escolhe vários PDFs de uma vez; o app sugere título, lei e tipo pelo nome do arquivo
    (ex.: lc190_resumo.pdf) e você confere/renomeia na tabela antes de guardar. Título igual substitui o PDF antigo."""
    leis = _leis_material()
    st.markdown("**Enviar materiais** (pode escolher vários PDFs de uma vez)")
    st.caption(f"Os PDFs enviados aqui entram na trilha **{TRILHAS[trilha_atual()]['nome']}** (troque a trilha no menu "
               "lateral). Depois dá para mudar em ✏️ Editar.")
    rodada = st.session_state.setdefault("mat_lote_n", 0)
    arqs = st.file_uploader("PDFs sem marca-d'água (o app coloca na hora do download)", type=["pdf"],
                            accept_multiple_files=True, key=f"mat_lote_{rodada}")
    if arqs:
        linhas = []
        for a in arqs:
            titulo, lei, tipo = _adivinhar_material(a.name, leis)
            linhas.append({"Arquivo": a.name, "Título": titulo, "Lei": lei, "Tipo": TIPOS_MATERIAL[tipo], "Publicar": True})
        st.caption("Confira e, se quiser, mude o título, a lei e o tipo direto na tabela. Material com o mesmo título de "
                   "um que já existe tem o PDF substituído (bom para atualizar).")
        tabela = st.data_editor(
            pd.DataFrame(linhas), hide_index=True, width="stretch", key=f"mat_lote_tab_{rodada}",
            column_config={"Arquivo": st.column_config.TextColumn(disabled=True),
                           "Lei": st.column_config.SelectboxColumn(options=leis, required=True),
                           "Tipo": st.column_config.SelectboxColumn(options=[v for k, v in TIPOS_MATERIAL.items() if k != "video"],
                                                                   required=True),
                           "Publicar": st.column_config.CheckboxColumn()})
        if st.button(f"Guardar {len(arqs)} material(is)", type="primary", key=f"mat_lote_ok_{rodada}"):
            titulos = [str(t).strip() for t in tabela["Título"]]
            if any(not t for t in titulos) or len(set(titulos)) != len(titulos):
                st.error("Há título vazio ou repetido na tabela. Ajuste antes de guardar.")
                return
            erros, ok = [], 0
            por_nome = {a.name: a for a in arqs}
            for _, r in tabela.iterrows():
                dados = por_nome[r["Arquivo"]].getvalue()
                pag = _ler_pdf(dados)
                if pag is None:
                    erros.append(f"{r['Arquivo']}: não parece ser um PDF válido")
                elif len(dados) > LIMITE_MATERIAL_MB * 1048576:
                    erros.append(f"{r['Arquivo']}: grande demais (limite de {LIMITE_MATERIAL_MB} MB)")
                else:
                    _guardar_material(str(r["Título"]).strip(), r["Lei"], _chave(TIPOS_MATERIAL, r["Tipo"]), None, dados,
                                      pag, bool(r["Publicar"]), usuario["id"])
                    ok += 1
            st.session_state["mat_lote_msg"] = (ok, erros)
            st.session_state["mat_lote_n"] = rodada + 1
            st.rerun()
    msg = st.session_state.pop("mat_lote_msg", None)
    if msg:
        st.success(f"{msg[0]} material(is) guardado(s).")
        for e in msg[1]:
            st.error(e)
    _form_video(leis, usuario)
    st.caption("Para renomear, trocar o PDF ou o link, publicar ou excluir, abra a matéria e use os botões de cada material.")

    lista = db.consultar(
        f"""SELECT m.id, m.titulo, m.lei, m.tipo, m.publicado, m.paginas, m.trilha,
                  COUNT(d.id) AS aberturas, COALESCE(SUM({SQL_DL}), 0) AS downloads,
                  COUNT(DISTINCT d.usuario_id) AS pessoas
           FROM material_estudo m LEFT JOIN material_download d ON d.material_id = m.id
           GROUP BY m.id ORDER BY m.trilha, m.ordem, m.lei, m.titulo""")
    if lista:
        st.dataframe(pd.DataFrame([{"Título": m["titulo"], "Trilha": TRILHA_MATERIAL.get(m["trilha"], m["trilha"]),
                                    "Lei": m["lei"], "Tipo": TIPOS_MATERIAL.get(m["tipo"]),
                                    "Situação": "Publicado" if m["publicado"] else "Rascunho", "Páginas": m["paginas"],
                                    "Aberturas": m["aberturas"], "Downloads": m["downloads"], "Pessoas": m["pessoas"]}
                                   for m in lista]),
                     hide_index=True, width="stretch")
        st.caption("Aberturas = cópias carimbadas abertas para estudo (uma por sessão do aluno). Downloads = vezes em que "
                   "o PDF foi baixado; as cópias da versão antiga do app contam como 1 download cada.")

    st.markdown("**Rastrear um PDF que vazou**")
    cod = st.text_input("Código impresso no topo das páginas", key="mat_rastro", max_chars=6,
                        placeholder="ex.: A3F09C").strip().upper()
    if cod:
        r = db.um("""SELECT u.nome, u.login, m.titulo, d.baixado_em FROM material_download d
                     JOIN usuario u ON u.id = d.usuario_id JOIN material_estudo m ON m.id = d.material_id
                     WHERE d.codigo = %s""", (cod,))
        if r:
            st.warning(f"Código {cod}: **{esc(r['nome'])}** ({r['login']}) baixou \"{esc(r['titulo'])}\" "
                       f"em {_local(r['baixado_em']):%d/%m/%Y às %H:%M}.")
        else:
            st.info("Nenhum download com esse código.")


# ======================================================================
# TELAS_GESTAO
# ======================================================================
STATUS = {"em_revisao": "Em revisão", "aprovada": "Aprovada", "desatualizada": "Desatualizada",
          "anulada": "Anulada", "rascunho": "Rascunho"}


# ======================================================================= REVISÃO
def tela_revisao(usuario: dict):
    st.header("Revisão da equipe")
    n_rep = db.um("SELECT COUNT(*) AS n FROM reporte_erro WHERE status = 'aberto'")["n"]
    abas = ["Pareceres", "Erros reportados" + (f" ({n_rep})" if n_rep else ""), "Qualidade das questões"]
    if usuario["perfil"] == "admin":
        abas.insert(1, "Aprovar por lote")
    t = dict(zip(abas, st.tabs(abas)))
    with t["Pareceres"]:
        _revisao_pareceres(usuario)
    if "Aprovar por lote" in t:
        with t["Aprovar por lote"]:
            _aprovar_lote(usuario)
    with t[abas[-2]]:
        _erros_reportados(usuario)
    with t["Qualidade das questões"]:
        _qualidade(usuario)


# Lote = conjunto de questões com a mesma fonte (cada lote gerado tem a sua); o acervo forma um lote só.
LOTE_SQL = "CASE WHEN q.origem::text = 'material' THEN 'Acervo (questões antigas)' ELSE COALESCE(q.fonte, '(sem fonte)') END"
SEM_PENDENCIA = """NOT EXISTS (SELECT 1 FROM parecer p WHERE p.questao_id = q.id AND p.voto = 'ajustar')
                   AND NOT EXISTS (SELECT 1 FROM reporte_erro e WHERE e.questao_id = q.id AND e.status = 'aberto')"""


def _aprovar_lote(usuario: dict):
    st.caption("Confira uma amostra sorteada do lote. Se estiver boa, aprove o lote inteiro de uma vez. "
               "Questões com pedido de ajuste ou erro reportado em aberto ficam de fora.")
    lotes = db.consultar(
        f"""SELECT {LOTE_SQL} AS lote, COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE q.status = 'em_revisao') AS revisao,
                   COUNT(*) FILTER (WHERE q.status = 'em_revisao' AND {SEM_PENDENCIA}) AS livres,
                   COUNT(*) FILTER (WHERE q.status = 'aprovada') AS aprovadas, MIN(q.codigo) AS primeiro
            FROM questao q GROUP BY 1 ORDER BY primeiro""")
    df = pd.DataFrame(lotes)
    st.dataframe(df[["lote", "total", "aprovadas", "revisao"]].rename(
        columns={"lote": "Lote", "total": "Questões", "aprovadas": "Aprovadas", "revisao": "Em revisão"}),
        hide_index=True, width="stretch")
    pendentes = [l for l in lotes if l["revisao"]]
    if not pendentes:
        st.success("Nenhum lote com questões em revisão.")
        return
    rot = {f"{l['lote']} — {l['revisao']} em revisão": l for l in pendentes}
    lote = rot[st.selectbox("Lote", list(rot), key="lote_sel")]
    chave = f"amostra::{lote['lote']}"
    qtd = st.slider("Tamanho da amostra", 5, 20, 10, key="lote_qtd")
    if st.button("🎲 Sortear amostra", key="lote_sortear") or chave not in st.session_state:
        st.session_state[chave] = [r["id"] for r in db.consultar(
            f"SELECT q.id FROM questao q WHERE {LOTE_SQL} = %s AND q.status = 'em_revisao' ORDER BY random() LIMIT %s",
            (lote["lote"], qtd))]
    for i, qid in enumerate(st.session_state[chave], start=1):
        q = db.um("SELECT codigo, enunciado, comentario, texto_apoio FROM questao WHERE id = %s", (qid,))
        with st.expander(f"{i}. {q['codigo']} — {q['enunciado'][:90]}…"):
            if q["texto_apoio"]:
                st.caption("(questão com texto de apoio)")
            st.markdown(f"**{esc(q['enunciado'])}**", unsafe_allow_html=True)
            for a in _alternativas(qid):
                marca = "✅" if a["correta"] else "▫️"
                st.markdown(f"{marca} **{a['letra']})** {esc(a['texto'])}  \n<small>{esc(a['comentario'] or '')}</small>",
                            unsafe_allow_html=True)
            st.markdown(f"<small><b>Comentário:</b> {esc(q['comentario'])}</small>", unsafe_allow_html=True)
    st.divider()
    fora = lote["revisao"] - lote["livres"]
    if fora:
        st.warning(f"{fora} questão(ões) deste lote têm pedido de ajuste ou erro reportado e não serão aprovadas agora.")
    ok = st.checkbox(f"Conferi a amostra e quero aprovar as {lote['livres']} questões em revisão deste lote",
                     key=f"lote_ok::{lote['lote']}")
    if st.button("Aprovar o lote", type="primary", disabled=not ok or not lote["livres"], key="lote_aprovar"):
        db.executar(f"""UPDATE questao q SET status = 'aprovada', revisado_por = %s, revisado_em = now()
                        WHERE {LOTE_SQL} = %s AND q.status = 'em_revisao' AND {SEM_PENDENCIA}""",
                    (usuario["nome"], lote["lote"]))
        st.session_state.pop("filtro_ativo", None)
        st.session_state.pop(chave, None)
        st.success(f"{lote['livres']} questões aprovadas. Os alunos já podem vê-las.")
        st.rerun()


def _erros_reportados(usuario: dict):
    linhas = db.consultar(
        """SELECT e.id, e.descricao, e.criado_em, q.id AS qid, q.codigo, q.status::text AS status, u.nome
           FROM reporte_erro e JOIN questao q ON q.id = e.questao_id LEFT JOIN usuario u ON u.id = e.usuario_id
           WHERE e.status = 'aberto' ORDER BY e.criado_em""")
    if not linhas:
        st.success("Nenhum erro reportado em aberto.")
        return
    st.caption("Enquanto houver erro em aberto, a questão não entra na aprovação por lote.")
    for e in linhas:
        with st.container(border=True):
            st.markdown(f"**{e['codigo']}** · {STATUS.get(e['status'], e['status'])} · por {esc(e['nome'] or '—')} "
                        f"em {e['criado_em']:%d/%m %H:%M}")
            st.write(e["descricao"])
            with st.expander("Ver a questão e o gabarito"):
                for a in _alternativas(e["qid"]):
                    st.markdown(f"{'✅' if a['correta'] else '▫️'} **{a['letra']})** {esc(a['texto'])}",
                                unsafe_allow_html=True)
            if usuario["perfil"] != "admin":
                continue
            c1, c2, c3 = st.columns(3)
            if c1.button("Procedente: tirar do ar", key=f"rep_proc_{e['id']}",
                         help="A questão volta para 'Em revisão' e some para os alunos até ser corrigida."):
                db.executar("UPDATE questao SET status = 'em_revisao' WHERE id = %s", (e["qid"],))
                db.executar("UPDATE reporte_erro SET status = 'procedente' WHERE id = %s", (e["id"],))
                st.session_state.pop("filtro_ativo", None)
                st.rerun()
            if c2.button("Procedente: já corrigi", key=f"rep_corr_{e['id']}"):
                db.executar("UPDATE reporte_erro SET status = 'procedente' WHERE id = %s", (e["id"],))
                st.rerun()
            if c3.button("Improcedente", key=f"rep_imp_{e['id']}"):
                db.executar("UPDATE reporte_erro SET status = 'improcedente' WHERE id = %s", (e["id"],))
                st.rerun()


def _dif_observada(pct: float) -> int:
    return 1 if pct >= 75 else (3 if pct < 40 else 2)


def _qualidade(usuario: dict):
    st.caption("Conta só a 1ª resposta de cada pessoa em cada questão. Use para achar questões fáceis demais, "
               "difíceis demais ou com possível erro de gabarito.")
    minimo = st.slider("Mínimo de pessoas que responderam", 3, 50, 10, key="qual_min")
    linhas = db.consultar(
        f"""WITH primeira AS (
                SELECT DISTINCT ON (r.usuario_id, r.questao_id) r.questao_id, r.acertou, a.letra
                FROM resposta r JOIN alternativa a ON a.id = r.alternativa_id
                ORDER BY r.usuario_id, r.questao_id, r.respondida_em),
            por_letra AS (
                SELECT questao_id, letra, COUNT(*) AS n, BOOL_OR(acertou) AS certa FROM primeira GROUP BY 1, 2),
            errada_top AS (
                SELECT DISTINCT ON (questao_id) questao_id, letra, n FROM por_letra WHERE NOT certa
                ORDER BY questao_id, n DESC)
            SELECT q.id, q.codigo, q.dificuldade, {LOTE_SQL} AS lote, COUNT(p.*) AS n,
                   ROUND(100.0 * AVG(p.acertou::int)) AS pct, et.letra AS errada, et.n AS n_errada
            FROM questao q JOIN primeira p ON p.questao_id = q.id
            LEFT JOIN errada_top et ON et.questao_id = q.id
            WHERE q.status::text <> 'anulada'
            GROUP BY q.id, et.letra, et.n HAVING COUNT(p.*) >= %s""", (minimo,))

    # Equilíbrio da dificuldade declarada (não depende de respostas)
    dist = db.consultar(
        """SELECT COALESCE(d.sigla, m.nome) AS grupo, q.dificuldade, COUNT(DISTINCT q.id) AS n
           FROM questao q JOIN materia m ON m.id = q.materia_id
           LEFT JOIN questao_assunto qa ON qa.questao_id = q.id LEFT JOIN assunto a ON a.id = qa.assunto_id
           LEFT JOIN diploma d ON d.id = a.diploma_id
           WHERE q.status::text <> 'anulada' AND q.origem::text <> 'material' GROUP BY 1, 2""")
    with st.expander("Equilíbrio de dificuldade por matéria/lei (dificuldade declarada)"):
        dd = pd.DataFrame(dist)
        if not dd.empty:
            tab = dd.pivot_table(index="grupo", columns="dificuldade", values="n", fill_value=0, aggfunc="sum")
            tab = tab.rename(columns=DIF)
            tab["% difíceis"] = (100 * tab.get("Difícil", 0) / tab.sum(axis=1)).round(0)
            st.dataframe(tab.sort_values("% difíceis"), width="stretch")
            st.caption("Referência: algo perto de 30% fáceis, 45% médias e 25% difíceis.")

    if not linhas:
        st.info(f"Ainda não há questões com pelo menos {minimo} pessoas respondendo. "
                "Os números aparecem conforme os alunos usam o app.")
        return
    df = pd.DataFrame(linhas)
    df["observada"] = df["pct"].astype(float).map(_dif_observada)
    df["suspeita"] = (df["pct"].astype(float) < 35) & (df["n_errada"].fillna(0) >= 0.5 * df["n"])
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Com estatística", len(df))
    c2.metric("Fáceis demais (≥ 90%)", int((df["pct"] >= 90).sum()))
    c3.metric("Difíceis demais (< 25%)", int((df["pct"] < 25).sum()))
    c4.metric("Suspeita de gabarito", int(df["suspeita"].sum()))
    filtro = st.radio("Mostrar", ["Suspeita de gabarito", "Fáceis demais", "Difíceis demais",
                                  "Dificuldade declarada diferente da observada", "Todas"], horizontal=True, key="qual_f")
    vis = {"Suspeita de gabarito": df[df["suspeita"]], "Fáceis demais": df[df["pct"] >= 90],
           "Difíceis demais": df[df["pct"] < 25],
           "Dificuldade declarada diferente da observada": df[df["dificuldade"] != df["observada"]],
           "Todas": df}[filtro]
    st.dataframe(vis.assign(dificuldade=vis["dificuldade"].map(DIF), observada=vis["observada"].map(DIF))
                 [["codigo", "lote", "n", "pct", "errada", "n_errada", "dificuldade", "observada"]]
                 .rename(columns={"codigo": "Código", "lote": "Lote", "n": "Pessoas", "pct": "% acerto",
                                  "errada": "Errada mais marcada", "n_errada": "Marcaram",
                                  "dificuldade": "Declarada", "observada": "Observada"})
                 .sort_values("% acerto"), hide_index=True, width="stretch")
    st.caption("Suspeita de gabarito: menos de 35% de acerto e metade ou mais marcando a mesma alternativa errada. "
               "Confira se essa alternativa também está correta.")
    difer = df[df["dificuldade"] != df["observada"]]
    if usuario["perfil"] == "admin" and len(difer):
        if st.button(f"Ajustar a dificuldade de {len(difer)} questões para a observada", key="qual_ajusta"):
            for _, r in difer.iterrows():
                db.executar("UPDATE questao SET dificuldade = %s WHERE id = %s", (int(r["observada"]), int(r["id"])))
            st.success("Dificuldades ajustadas.")
            st.rerun()


def _revisao_pareceres(usuario: dict):
    st.caption("Regra sugerida: questão com pelo menos 2 aprovações e nenhum pedido de ajuste está pronta para ser aprovada.")
    linhas = db.consultar(
        """SELECT q.id, q.codigo, q.status::text AS status, q.tipo,
                  (SELECT string_agg(a.nome, ' · ') FROM questao_assunto qa JOIN assunto a ON a.id = qa.assunto_id
                    WHERE qa.questao_id = q.id) AS assunto,
                  COUNT(p.*) FILTER (WHERE p.voto = 'aprovar') AS aprovacoes,
                  COUNT(p.*) FILTER (WHERE p.voto = 'ajustar') AS ajustes
           FROM questao q LEFT JOIN parecer p ON p.questao_id = q.id
           GROUP BY q.id ORDER BY q.codigo"""
    )
    df = pd.DataFrame(linhas)
    df["pronta"] = (df["aprovacoes"] >= 2) & (df["ajustes"] == 0) & (df["status"] == "em_revisao")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Questões", len(df))
    c2.metric("Aprovadas", int((df["status"] == "aprovada").sum()))
    c3.metric("Prontas para aprovar", int(df["pronta"].sum()))
    c4.metric("Com pedido de ajuste", int((df["ajustes"] > 0).sum()))

    filtro = st.radio("Mostrar", ["Todas", "Prontas para aprovar", "Com pedido de ajuste", "Sem nenhum parecer"],
                      horizontal=True, key="rev_filtro")
    vis = {"Todas": df, "Prontas para aprovar": df[df["pronta"]], "Com pedido de ajuste": df[df["ajustes"] > 0],
           "Sem nenhum parecer": df[(df["aprovacoes"] + df["ajustes"]) == 0]}[filtro]
    st.dataframe(
        vis.assign(status=vis["status"].map(STATUS),
                   tipo=vis["tipo"].map({k: v[1] for k, v in ROTULO_TIPO.items()}))
           [["codigo", "status", "tipo", "assunto", "aprovacoes", "ajustes"]]
           .rename(columns={"codigo": "Código", "status": "Situação", "tipo": "Tipo", "assunto": "Assunto",
                            "aprovacoes": "Aprovações", "ajustes": "Ajustes"}),
        hide_index=True, width="stretch",
    )

    st.subheader("Pareceres de uma questão")
    codigo = st.selectbox("Questão", df["codigo"].tolist(), key="rev_cod")
    linha = df[df["codigo"] == codigo].iloc[0]
    pareceres = db.consultar(
        """SELECT u.nome, p.voto, p.nota, p.atualizado_em FROM parecer p JOIN usuario u ON u.id = p.usuario_id
           WHERE p.questao_id = %s ORDER BY p.atualizado_em""", (int(linha["id"]),))
    if not pareceres:
        st.caption("Nenhum parecer ainda.")
    for p in pareceres:
        icone = "✅" if p["voto"] == "aprovar" else "✏️"
        st.markdown(f"{icone} **{p['nome']}** ({p['atualizado_em']:%d/%m %H:%M}) {p['nota'] or ''}")

    if usuario["perfil"] != "admin":
        return
    st.markdown("**Decisão do administrador**")
    situacoes = list(STATUS)[:4]
    novo = _chave(STATUS, st.selectbox("Situação da questão", [STATUS[s] for s in situacoes],
                                       index=situacoes.index(linha["status"]) if linha["status"] in situacoes else 0,
                                       key="rev_status"))
    if st.button("Salvar situação", key="rev_salvar"):
        db.executar("UPDATE questao SET status = %s::status_questao, revisado_por = %s, revisado_em = now() WHERE id = %s",
                    (novo, usuario["nome"], int(linha["id"])))
        st.success(f"{codigo} agora está como: {STATUS[novo]}.")
        st.session_state.pop("filtro_ativo", None)
        st.rerun()

    prontas = df[df["pronta"]]["codigo"].tolist()
    if prontas:
        st.markdown(f"**Aprovar de uma vez as {len(prontas)} questões prontas:** {', '.join(prontas)}")
        if st.button("Aprovar todas as prontas", type="primary", key="rev_lote"):
            db.executar("""UPDATE questao SET status = 'aprovada', revisado_por = %s, revisado_em = now()
                           WHERE codigo = ANY(%s)""", (usuario["nome"], prontas))
            st.session_state.pop("filtro_ativo", None)
            st.rerun()


# ======================================================================= DESEMPENHO
def tela_desempenho(usuario: dict):
    st.header("Meu desempenho")
    uid = usuario["id"]
    tot = db.um("""SELECT COUNT(*) AS n, COALESCE(SUM(r.acertou::int), 0) AS ok, COUNT(DISTINCT r.questao_id) AS distintas
                   FROM resposta r JOIN questao q ON q.id = r.questao_id WHERE r.usuario_id = %s""" + filtro_trilha(), (uid,))
    if not tot["n"]:
        st.info("Você ainda não respondeu nenhuma questão. Vá em **Resolver questões** para começar.")
        _historico_simulados(usuario)
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("Respostas", tot["n"])
    c2.metric("Acertos", f"{100 * tot['ok'] / tot['n']:.0f}%")
    c3.metric("Questões diferentes", tot["distintas"])

    _raio_x(usuario)
    _historico_simulados(usuario)

    tipo = db.consultar(
        """SELECT CASE q.tipo WHEN 'caso_pratico' THEN 'Caso prático' WHEN 'portugues' THEN 'Português'
                              WHEN 'teoria' THEN 'Conteúdo do curso' ELSE 'Lei seca' END AS tipo,
                  COUNT(*) AS respostas, ROUND(100.0 * AVG(r.acertou::int), 0) AS pct
           FROM resposta r JOIN questao q ON q.id = r.questao_id WHERE r.usuario_id = %s""" + filtro_trilha()
        + " GROUP BY 1 ORDER BY 1", (uid,))
    st.subheader("Decorar ou aplicar?")
    st.caption("Compare seu acerto em lei seca (memória do texto) com casos práticos (aplicação da regra).")
    st.dataframe(pd.DataFrame(tipo).rename(columns={"tipo": "Tipo", "respostas": "Respostas", "pct": "% de acerto"}),
                 hide_index=True, width="stretch")

    ass = db.consultar(
        """SELECT a.nome AS assunto, COUNT(*) AS respostas, ROUND(100.0 * AVG(r.acertou::int), 0) AS pct
           FROM resposta r JOIN questao_assunto qa ON qa.questao_id = r.questao_id JOIN assunto a ON a.id = qa.assunto_id
           JOIN questao q ON q.id = r.questao_id
           WHERE r.usuario_id = %s""" + filtro_trilha() + " GROUP BY a.nome ORDER BY pct ASC, respostas DESC", (uid,))
    with st.expander("Tabela de todas as respostas por assunto"):
        df = pd.DataFrame(ass)
        st.dataframe(df.rename(columns={"assunto": "Assunto", "respostas": "Respostas", "pct": "% de acerto"}),
                     hide_index=True, width="stretch")


# ----------------------------------------------------------------------- RAIO-X DO DESEMPENHO
# Para cada lei/matéria, cada assunto ganha uma cor pelo acerto do aluno, considerando a ÚLTIMA resposta de cada questão
# (assim o Raio-X melhora quando o aluno refaz e acerta). Poucos dados (< RX_MINIMO questões) ficam em cinza.
RX_MINIMO = 3
RX_FAIXAS = [(50, "vermelho", "Prioridade"), (70, "amarelo", "Atenção"), (101, "verde", "Bom")]


def _rx_cor(pct, n) -> tuple[str, str]:
    if n == 0:
        return "branco", "Não estudado"
    if n < RX_MINIMO:
        return "cinza", "Poucos dados"
    return next((c, r) for lim, c, r in RX_FAIXAS if pct < lim)


def _rx_dados(usuario: dict) -> list[dict]:
    status = status_visiveis(usuario["perfil"], True)
    linhas = db.consultar(
        """WITH ultima AS (
               SELECT DISTINCT ON (r.questao_id) r.questao_id, r.acertou
               FROM resposta r WHERE r.usuario_id = %(u)s ORDER BY r.questao_id, r.respondida_em DESC),
           disp AS (
               SELECT qa.assunto_id, COUNT(DISTINCT q.id) AS total
               FROM questao_assunto qa JOIN questao q ON q.id = qa.questao_id
               WHERE q.status::text = ANY(%(st)s) AND q.origem::text <> 'material' """
        + (FILTRO_AMOSTRA if _so_amostra() else "") + filtro_trilha() + """ GROUP BY 1),
           feito AS (
               SELECT qa.assunto_id, COUNT(*) AS n, SUM(u.acertou::int) AS ok
               FROM ultima u JOIN questao_assunto qa ON qa.questao_id = u.questao_id GROUP BY 1)
           SELECT a.id, a.nome, a.ordem, COALESCE(d.sigla, m.nome) AS grupo, COALESCE(d.id, 0) AS ordem_grupo,
                  d.nome_popular, disp.total, COALESCE(f.n, 0) AS n, COALESCE(f.ok, 0) AS ok
           FROM assunto a JOIN materia m ON m.id = a.materia_id LEFT JOIN diploma d ON d.id = a.diploma_id
           JOIN disp ON disp.assunto_id = a.id LEFT JOIN feito f ON f.assunto_id = a.id""",
        {"u": usuario["id"], "st": status})
    pos = {nome: i for i, nome in enumerate(ORDEM_GRUPOS)}
    grupos: dict[str, dict] = {}
    for l in linhas:
        l["pct"] = round(100 * l["ok"] / l["n"]) if l["n"] else None
        l["cor"], l["rotulo_cor"] = _rx_cor(l["pct"], l["n"])
        g = grupos.setdefault(l["grupo"], {"sigla": l["grupo"], "popular": l["nome_popular"], "ordem": l["ordem_grupo"],
                                           "subs": [], "n": 0, "ok": 0})
        g["subs"].append(l)
        g["n"] += l["n"]
        g["ok"] += l["ok"]
    lista = sorted(grupos.values(), key=lambda g: (pos.get(g["sigla"], len(pos)), g["ordem"], g["sigla"]))
    for g in lista:
        g["subs"].sort(key=lambda a: (a["ordem"], a["nome"]))
        g["pct"] = round(100 * g["ok"] / g["n"]) if g["n"] else None
        g["cor"], _ = _rx_cor(g["pct"], g["n"])
    return lista


def _rx_treinar(sigla: str, assunto_id: int, perfil: str):
    """Leva o aluno para Resolver questões já filtrado no assunto escolhido."""
    arv = _arvore(status_visiveis(perfil, True), "")
    g = next((x for x in arv if x["sigla"] == sigla), None)
    if g is None:
        return
    st.session_state["f_orig"] = ORIGENS[""]
    st.session_state["f_grupo"] = g["rotulo"]
    st.session_state[f"f_sub_{sigla}"] = [a["rotulo"] for a in g["subs"] if a["id"] == assunto_id]
    st.session_state.pop("filtro_ativo", None)
    st.session_state["menu"] = "Resolver questões"


def _rx_simulado(fracos: list[dict]):
    """Leva o aluno para Simulados com as leis e os assuntos mais fracos já marcados."""
    st.session_state["sim_grupos"] = list(dict.fromkeys(a["grupo"] for a in fracos))
    st.session_state["sim_assuntos"] = [a["id"] for a in fracos]
    st.session_state["sim_qtd"] = 20
    st.session_state.pop("sim_ver", None)
    st.session_state["sim_aviso_rx"] = True
    st.session_state["menu"] = "Simulados"


def _rx_pdf(usuario: dict, grupos: list[dict]) -> bytes:
    """Raio-X em PDF (A4), com o nome do aluno no cabeçalho de cada página."""
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    cores = {"vermelho": (0.64, 0.20, 0.16), "amarelo": (0.85, 0.62, 0.10), "verde": (0.12, 0.42, 0.23),
             "cinza": (0.62, 0.62, 0.62), "branco": (0.86, 0.86, 0.86)}
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    quando = f"{_local(pd.Timestamp.now(tz='UTC').to_pydatetime()):%d/%m/%Y %H:%M}"

    def cabecalho():
        c.setFillColorRGB(0.29, 0.35, 0.14)
        c.rect(0, h - 58, w, 58, stroke=0, fill=1)
        c.setFillColorRGB(1, 1, 1)
        c.setFont("Helvetica-Bold", 15)
        c.drawString(40, h - 30, "Raio-X do desempenho")
        c.setFont("Helvetica", 9)
        c.drawString(40, h - 46, f"{usuario['nome']} ({usuario['login']}) · {quando} · {NOME_APP}")
        y = h - 76
        c.setFont("Helvetica", 7.5)
        x = 40
        for cor, txt in (("vermelho", "abaixo de 50%: prioridade"), ("amarelo", "50 a 69%: atenção"),
                         ("verde", "70% ou mais: bom"), ("cinza", f"menos de {RX_MINIMO} questões"),
                         ("branco", "não estudado")):
            c.setFillColorRGB(*cores[cor])
            c.rect(x, y - 1, 8, 8, stroke=0, fill=1)
            c.setFillColorRGB(0.2, 0.2, 0.2)
            c.drawString(x + 11, y, txt)
            x += c.stringWidth(txt, "Helvetica", 7.5) + 26
        return y - 18

    y = cabecalho()
    for g in grupos:
        if y < 90:
            c.showPage()
            y = cabecalho()
        titulo = g["sigla"] + (f" · {g['popular']}" if g["popular"] and g["popular"] != g["sigla"] else "")
        c.setFillColorRGB(0.2, 0.25, 0.09)
        c.setFont("Helvetica-Bold", 10.5)
        c.drawString(40, y, titulo[:80])
        c.setFont("Helvetica", 8.5)
        resumo = f"{g['pct']}% de acerto · {g['n']} questões" if g["n"] else "ainda não estudado"
        c.drawRightString(w - 40, y, resumo)
        y -= 14
        for a in g["subs"]:
            if y < 50:
                c.showPage()
                y = cabecalho()
            nome = a["nome"] if len(a["nome"]) <= 70 else a["nome"][:67] + "..."
            c.setFillColorRGB(0.15, 0.15, 0.15)
            c.setFont("Helvetica", 8)
            c.drawString(52, y, nome)
            larg = 120
            c.setFillColorRGB(0.92, 0.92, 0.92)
            c.rect(w - 40 - larg - 70, y - 1.5, larg, 8, stroke=0, fill=1)
            if a["n"]:
                c.setFillColorRGB(*cores[a["cor"]])
                c.rect(w - 40 - larg - 70, y - 1.5, larg * (a["pct"] or 0) / 100, 8, stroke=0, fill=1)
            c.setFillColorRGB(0.25, 0.25, 0.25)
            c.drawRightString(w - 40, y, f"{a['pct']}% · {a['n']}/{a['total']}" if a["n"] else f"0/{a['total']}")
            y -= 12
        y -= 8
    c.save()
    return buf.getvalue()


def _raio_x(usuario: dict):
    st.subheader("Raio-X do desempenho")
    st.caption("Cada assunto ganha uma cor pelo seu acerto, contando a sua última resposta em cada questão: refez e "
               "acertou, o Raio-X melhora. Use para decidir o que estudar primeiro.")
    grupos = _rx_dados(usuario)
    if not grupos:
        st.info("Ainda não há questões disponíveis para montar o Raio-X.")
        return
    estudados = [g for g in grupos if g["n"]]
    if estudados:
        mostrar = st.radio("Mostrar", ["Só o que já estudei", "Todas as matérias e leis"], horizontal=True,
                           key="rx_mostrar", label_visibility="collapsed")
        vis = estudados if mostrar == "Só o que já estudei" else grupos
    else:
        st.info("Você ainda não respondeu questões. Abaixo estão todos os assuntos: resolva algumas questões e "
                "eles vão ganhando cor.")
        vis = grupos

    fracos = sorted([a for g in grupos for a in g["subs"] if a["n"] >= RX_MINIMO and a["pct"] < 70],
                    key=lambda a: (a["pct"], -a["n"]))[:5]
    if fracos:
        with st.container(border=True):
            st.markdown("**Prioridades de estudo** (os assuntos em que você mais erra)")
            for a in fracos:
                c1, c2 = st.columns([3.2, 1])
                c1.markdown(f'<span class="rx-dot rx-{a["cor"]}"></span> <b>{esc(a["grupo"])}</b> › {esc(a["nome"])} '
                            f'<span class="rx-num">{a["pct"]}% em {a["n"]} questões</span>', unsafe_allow_html=True)
                c2.button("Treinar", key=f"rx_treinar_{a['id']}", width="stretch",
                          on_click=_rx_treinar, args=(a["grupo"], a["id"], usuario["perfil"]))
            st.button("Montar um simulado com meus pontos fracos", key="rx_simulado", type="primary",
                      on_click=_rx_simulado, args=(fracos,))
    elif estudados:
        st.success(f"Nenhum assunto abaixo de 70% com pelo menos {RX_MINIMO} questões. Continue assim.")

    partes = []
    for g in vis:
        resumo = f"{g['pct']}% · {g['n']} questões" if g["n"] else "não estudado"
        titulo = esc(g["sigla"]) + (f' <span class="rx-pop">· {esc(g["popular"])}</span>'
                                    if g["popular"] and g["popular"] != g["sigla"] else "")
        chips = "".join(
            f'<div class="rx-chip rx-{a["cor"]}" title="{esc(a["rotulo_cor"])}"><span class="rx-nome">{esc(a["nome"])}</span>'
            f'<span class="rx-num">{(str(a["pct"]) + "%") if a["n"] else "—"} · {a["n"]}/{a["total"]}</span></div>'
            for a in g["subs"])
        partes.append(f'<div class="rx-grupo"><div class="rx-cab"><span class="rx-dot rx-{g["cor"]}"></span>{titulo}'
                      f'<span class="rx-res">{resumo}</span></div><div class="rx-grid">{chips}</div></div>')
    st.markdown("".join(partes) or "<p>Nada para mostrar.</p>", unsafe_allow_html=True)
    st.markdown('<div class="rx-leg"><span class="rx-dot rx-vermelho"></span>abaixo de 50% · '
                '<span class="rx-dot rx-amarelo"></span>50 a 69% · <span class="rx-dot rx-verde"></span>70% ou mais · '
                f'<span class="rx-dot rx-cinza"></span>menos de {RX_MINIMO} questões · '
                '<span class="rx-dot rx-branco"></span>não estudado · números: acerto · feitas/disponíveis</div>',
                unsafe_allow_html=True)
    st.download_button("📥 Baixar meu Raio-X em PDF", data=_rx_pdf(usuario, grupos),
                       file_name=f"raio-x-{usuario['login']}.pdf", mime="application/pdf", key="rx_pdf")


# ======================================================================= USUÁRIOS (ADMIN)
# ======================================================================= FINANCEIRO (só admin)
def tela_financeiro(usuario: dict):
    st.header("Financeiro")
    st.caption("Cadastros e pagamentos por período. Cada liberação de acesso feita em Usuários com valor maior que zero "
               "entra aqui automaticamente; pagamentos avulsos podem ser lançados abaixo.")
    hoje = _local(datetime.now(timezone.utc)).date()
    periodos = {"Este mês": (hoje.replace(day=1), hoje),
                "Mês passado": ((hoje.replace(day=1) - timedelta(days=1)).replace(day=1), hoje.replace(day=1) - timedelta(days=1)),
                "Últimos 7 dias": (hoje - timedelta(days=6), hoje),
                "Este ano": (hoje.replace(month=1, day=1), hoje),
                "Tudo": (datetime(2026, 1, 1).date(), hoje),
                "Escolher datas": None}
    esc_p = st.radio("Período", list(periodos), horizontal=True, key="fin_periodo")
    if periodos[esc_p] is None:
        c1, c2 = st.columns(2)
        ini = c1.date_input("De", value=hoje.replace(day=1), format="DD/MM/YYYY", key="fin_ini")
        fim = c2.date_input("Até", value=hoje, format="DD/MM/YYYY", key="fin_fim")
    else:
        ini, fim = periodos[esc_p]
    t0 = datetime(ini.year, ini.month, ini.day, tzinfo=FUSO)
    t1 = datetime(fim.year, fim.month, fim.day, tzinfo=FUSO) + timedelta(days=1)
    r = db.um("""SELECT (SELECT COUNT(*) FROM usuario WHERE perfil = 'aluno' AND criado_em >= %(a)s AND criado_em < %(b)s) AS cadastros,
                        (SELECT COUNT(*) FROM pagamento WHERE pago_em >= %(a)s AND pago_em < %(b)s) AS pagamentos,
                        (SELECT COALESCE(SUM(valor), 0) FROM pagamento WHERE pago_em >= %(a)s AND pago_em < %(b)s) AS receita,
                        (SELECT COUNT(DISTINCT usuario_id) FROM pagamento WHERE pago_em >= %(a)s AND pago_em < %(b)s) AS pagantes,
                        (SELECT COUNT(*) FROM usuario WHERE perfil = 'aluno') AS alunos_total,
                        (SELECT COALESCE(SUM(valor), 0) FROM pagamento) AS receita_total""", {"a": t0, "b": t1})
    real = lambda v: f"R$ {float(v):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Receita no período", real(r["receita"]))
    m2.metric("Pagamentos", r["pagamentos"])
    m3.metric("Novos alunos", r["cadastros"])
    m4.metric("Ticket médio", real(r["receita"] / r["pagamentos"]) if r["pagamentos"] else "—")
    st.caption(f"Desde o início: **{real(r['receita_total'])}** recebidos · **{r['alunos_total']}** alunos cadastrados.")

    mensal = db.consultar(
        """SELECT to_char(date_trunc('month', pago_em AT TIME ZONE 'America/Campo_Grande'), 'YYYY-MM') AS mes,
                  SUM(valor)::float AS receita, COUNT(*) AS pagamentos
           FROM pagamento GROUP BY 1 ORDER BY 1""")
    cad = db.consultar(
        """SELECT to_char(date_trunc('month', criado_em AT TIME ZONE 'America/Campo_Grande'), 'YYYY-MM') AS mes,
                  COUNT(*) AS cadastros FROM usuario WHERE perfil = 'aluno' GROUP BY 1 ORDER BY 1""")
    if mensal or cad:
        df = pd.merge(pd.DataFrame(mensal or [], columns=["mes", "receita", "pagamentos"]),
                      pd.DataFrame(cad or [], columns=["mes", "cadastros"]), on="mes", how="outer").fillna(0).sort_values("mes")
        for col in ("receita", "pagamentos", "cadastros"):        # tabela vazia vira 'object': o gráfico precisa de número
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        st.subheader("Mês a mês")
        if df["receita"].sum() > 0:
            grafico_barras([f"{m[5:]}/{m[2:4]}" for m in df["mes"]], [float(v) for v in df["receita"]],
                           texto=lambda v: real(v).replace("R$ ", ""))
        else:
            st.caption("O gráfico de receita aparece a partir do primeiro pagamento registrado.")
        st.dataframe(df.assign(receita=df["receita"].map(real), pagamentos=df["pagamentos"].astype(int),
                               cadastros=df["cadastros"].astype(int))
                       .rename(columns={"mes": "Mês", "receita": "Receita", "pagamentos": "Pagamentos",
                                        "cadastros": "Novos alunos"}), hide_index=True, width="stretch")

    st.subheader("Novos alunos do período")
    novos = db.consultar(
        """SELECT u.nome, u.login, u.whatsapp, u.concurso, u.criado_em, u.acesso_tipo, u.acesso_ate,
                  EXISTS (SELECT 1 FROM acesso_log l WHERE l.usuario_id = u.id AND l.evento = 'cadastro_proprio') AS proprio,
                  EXISTS (SELECT 1 FROM acesso_log l WHERE l.usuario_id = u.id AND l.evento = 'perfil_aluno') AS ex_equipe
           FROM usuario u WHERE u.perfil = 'aluno' AND u.criado_em >= %s AND u.criado_em < %s ORDER BY u.criado_em DESC""",
        (t0, t1))
    if novos:
        st.dataframe(pd.DataFrame([{
            "Cadastro": f"{_local(n['criado_em']):%d/%m/%Y %H:%M}", "Nome": n["nome"], "Usuário": n["login"],
            "WhatsApp": n["whatsapp"] or "", "Concurso": CONCURSOS_CURTO.get(n["concurso"], n["concurso"]),
            "Como entrou": "criou a conta no app" if n["proprio"] else (
                "era da equipe (perfil trocado)" if n["ex_equipe"] else "cadastrado por você"),
            "Acesso": _rotulo_acesso(n | {"perfil": "aluno",
                                          "acesso_vencido": n["acesso_ate"] is not None
                                          and n["acesso_ate"] <= datetime.now(timezone.utc)})} for n in novos]),
            hide_index=True, width="stretch")
    else:
        st.info("Nenhum aluno novo neste período.")

    st.subheader("Pagamentos do período")
    pags = db.consultar(
        """SELECT p.id, p.pago_em, u.nome, u.login, p.valor::float AS valor, p.descricao, p.acesso_ate
           FROM pagamento p JOIN usuario u ON u.id = p.usuario_id
           WHERE p.pago_em >= %s AND p.pago_em < %s ORDER BY p.pago_em DESC""", (t0, t1))
    if pags:
        dp = pd.DataFrame(pags)
        vis = pd.DataFrame({"Data": dp["pago_em"].map(lambda d: f"{_local(d):%d/%m/%Y %H:%M}"), "Aluno": dp["nome"],
                            "Usuário": dp["login"], "Valor": dp["valor"].map(real), "Descrição": dp["descricao"].fillna(""),
                            "Acesso até": dp["acesso_ate"].map(lambda d: f"{_local(d):%d/%m/%Y}" if pd.notna(d) else "sem prazo")})
        st.dataframe(vis, hide_index=True, width="stretch")
        st.download_button("📥 Baixar planilha (CSV)", vis.to_csv(index=False, sep=";").encode("utf-8-sig"),
                           file_name=f"pagamentos_{ini:%Y%m%d}_{fim:%Y%m%d}.csv", mime="text/csv", key="fin_csv")
        with st.expander("Corrigir um lançamento errado"):
            rot = {p["id"]: f"{_local(p['pago_em']):%d/%m %H:%M} · {p['nome']} · {real(p['valor'])}" for p in pags}
            pid = st.selectbox("Lançamento", list(rot), format_func=rot.get, key="fin_del_sel")
            if st.button("Excluir este lançamento", key="fin_del"):
                db.executar("DELETE FROM pagamento WHERE id = %s", (pid,))
                auth.registrar("pagamento_excluido", usuario["id"])
                st.rerun()
    else:
        st.info("Nenhum pagamento neste período.")

    with st.expander("Lançar pagamento avulso (sem mexer no acesso)"):
        alunos = db.consultar("SELECT id, nome, login FROM usuario WHERE perfil = 'aluno' ORDER BY nome")
        if alunos:
            with st.form("fin_avulso", clear_on_submit=True):
                rot_a = {a["id"]: f"{a['nome']} ({a['login']})" for a in alunos}
                aid = st.selectbox("Aluno", list(rot_a), format_func=rot_a.get, key="fin_av_aluno")
                c1, c2 = st.columns(2)
                val = c1.number_input("Valor (R$)", min_value=0.0, step=10.0, value=_valor_padrao(), format="%.2f",
                                      key="fin_av_valor")
                data_p = c2.date_input("Data do pagamento", value=hoje, format="DD/MM/YYYY", key="fin_av_data")
                desc = st.text_input("Descrição", value="Pagamento avulso", key="fin_av_desc")
                if st.form_submit_button("Lançar", type="primary") and val > 0:
                    db.executar("""INSERT INTO pagamento (usuario_id, valor, pago_em, descricao, registrado_por)
                                   VALUES (%s, %s, %s, %s, %s)""",
                                (aid, round(val, 2), datetime(data_p.year, data_p.month, data_p.day, 12, tzinfo=FUSO),
                                 desc.strip() or None, usuario["id"]))
                    st.rerun()


# ======================================================================= SATISFAÇÃO
# Pergunta de recomendação (0 a 10) que aparece UMA vez para o aluno que já usou o app de verdade: 50 questões respondidas
# ou 1 simulado entregue (na avaliação grátis, 20 questões). "Agora não" adia 7 dias; depois de responder, volta em 30.
# Tabela satisfacao: nota NULL = o aluno escolheu "Agora não". NPS = % de notas 9-10 menos % de notas 0-6.
SAT_MIN_RESP = 50
SAT_MIN_RESP_AVALIACAO = 20
SAT_REPETIR_DIAS = 30
SAT_ADIAR_DIAS = 7


def _satisfacao_pendente(usuario: dict, acesso: dict) -> bool:
    if usuario["perfil"] != "aluno" or st.session_state.get("sat_feito"):
        return False
    r = db.um(
        """SELECT (SELECT COUNT(DISTINCT questao_id) FROM resposta WHERE usuario_id = %(u)s) AS resp,
                  (SELECT COUNT(*) FROM simulado WHERE usuario_id = %(u)s AND status = 'finalizado') AS sims,
                  (SELECT COUNT(*) FROM simulado WHERE usuario_id = %(u)s AND status = 'em_andamento') AS aberto,
                  (SELECT COUNT(*) FROM satisfacao WHERE usuario_id = %(u)s
                     AND ((nota IS NULL AND criado_em > now() - make_interval(days => %(adiar)s))
                       OR (nota IS NOT NULL AND criado_em > now() - make_interval(days => %(repetir)s)))) AS recente""",
        {"u": usuario["id"], "adiar": SAT_ADIAR_DIAS, "repetir": SAT_REPETIR_DIAS})
    if r["recente"] or r["aberto"]:          # durante um simulado a pergunta não aparece
        return False
    minimo = SAT_MIN_RESP_AVALIACAO if acesso.get("acesso_tipo") == "avaliacao" else SAT_MIN_RESP
    return r["resp"] >= minimo or r["sims"] >= 1


def _sat_gravar(uid: int, acesso_tipo, adiar: bool):
    nota = None if adiar else st.session_state.get("sat_nota")
    if not adiar and nota is None:
        st.session_state["sat_aviso"] = "Escolha uma nota de 0 a 10 antes de enviar."
        return
    coment = None if adiar else (st.session_state.get("sat_coment") or "").strip()[:1000] or None
    db.executar("INSERT INTO satisfacao (usuario_id, nota, comentario, trilha, acesso_tipo) VALUES (%s, %s, %s, %s, %s)",
                (uid, nota, coment, trilha_atual(), acesso_tipo))
    st.session_state["sat_feito"] = True
    st.session_state["sat_obrigado"] = not adiar


def caixa_satisfacao(usuario: dict, acesso: dict):
    if st.session_state.pop("sat_obrigado", False):
        st.toast("Obrigado pela avaliação! Ela ajuda a melhorar o app.", icon="💚")
    if not _satisfacao_pendente(usuario, acesso):
        return
    with st.container(border=True):
        st.markdown(f"**💬 Rapidinho: de 0 a 10, quanto você recomendaria o {NOME_APP} a um colega de curso?**")
        st.radio("Nota", list(range(11)), index=None, horizontal=True, key="sat_nota", label_visibility="collapsed")
        st.caption("0 = não recomendaria · 10 = recomendaria com certeza")
        st.text_area("O que mais ajudou ou o que está faltando? (opcional)", key="sat_coment", max_chars=1000, height=80)
        if aviso := st.session_state.pop("sat_aviso", None):
            st.warning(aviso)
        c1, c2, _ = st.columns([1, 1, 2])
        c1.button("Enviar", type="primary", key="sat_enviar", width="stretch",
                  on_click=_sat_gravar, args=(usuario["id"], acesso.get("acesso_tipo"), False))
        c2.button("Agora não", key="sat_adiar", width="stretch",
                  on_click=_sat_gravar, args=(usuario["id"], acesso.get("acesso_tipo"), True))


def _nps(notas: list[int]) -> tuple[float | None, int, int, int]:
    n = len(notas)
    if not n:
        return None, 0, 0, 0
    prom, det = sum(1 for x in notas if x >= 9), sum(1 for x in notas if x <= 6)
    return round(100 * (prom - det) / n), prom, n - prom - det, det


SAT_TRILHAS = {"todas": "As duas trilhas", "cfs": "CFS PMMS 2026", "provao": "Provão do CFS 2026"}


def tela_satisfacao(usuario: dict):
    st.header("Satisfação dos alunos")
    st.caption(f"A pergunta aparece uma vez para cada aluno depois de {SAT_MIN_RESP} questões respondidas ou do 1º simulado "
               f"entregue ({SAT_MIN_RESP_AVALIACAO} questões na avaliação grátis). \"Agora não\" adia {SAT_ADIAR_DIAS} dias; "
               f"quem respondeu é perguntado de novo depois de {SAT_REPETIR_DIAS} dias. Conta a última nota de cada aluno.")
    tr = _chave(SAT_TRILHAS, st.radio("Trilha", list(SAT_TRILHAS.values()), horizontal=True, key="sat_trilha"))
    f_sat = "" if tr == "todas" else " AND s.trilha = %(tr)s"
    f_usu = "" if tr == "todas" else " AND u.concurso = %(tr)s"
    p = {"tr": tr}

    ult = db.consultar(
        """SELECT DISTINCT ON (s.usuario_id) s.usuario_id, s.nota, s.comentario, s.criado_em, s.trilha, s.acesso_tipo,
                  u.nome, u.login
           FROM satisfacao s JOIN usuario u ON u.id = s.usuario_id
           WHERE s.nota IS NOT NULL""" + f_sat + " ORDER BY s.usuario_id, s.criado_em DESC", p)
    adiados = db.um("SELECT COUNT(DISTINCT s.usuario_id) AS n FROM satisfacao s WHERE s.nota IS NULL" + f_sat, p)["n"]
    nps, prom, neu, det = _nps([r["nota"] for r in ult])

    st.subheader("Recomendação (NPS)")
    if not ult:
        st.info("Nenhuma avaliação ainda. Ela aparece para o aluno depois que ele usa o app de verdade.")
    else:
        n = len(ult)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("NPS", f"{nps:+d}", help="% de notas 9-10 menos % de notas 0-6. Vai de -100 a +100; acima de 50 é muito bom.")
        m2.metric("Avaliações", n)
        m3.metric("Nota média", f"{sum(r['nota'] for r in ult) / n:.1f}".replace(".", ","))
        m4.metric("Disseram \"agora não\"", adiados)
        st.caption(f"😀 Promotores (9-10): **{prom}** ({100 * prom / n:.0f}%) · 😐 Neutros (7-8): **{neu}** "
                   f"({100 * neu / n:.0f}%) · 🙁 Detratores (0-6): **{det}** ({100 * det / n:.0f}%)")
        dist = [sum(1 for r in ult if r["nota"] == k) for k in range(11)]
        grafico_barras([str(k) for k in range(11)], dist, texto=lambda v: str(int(v)) if v else "")
        com = [r for r in ult if r["comentario"]]
        st.markdown(f"**Comentários ({len(com)})**")
        if com:
            st.dataframe(pd.DataFrame([{
                "Data": f"{_local(r['criado_em']):%d/%m/%Y}", "Aluno": r["nome"], "Nota": r["nota"],
                "Trilha": SAT_TRILHAS.get(r["trilha"], r["trilha"]),
                "Acesso": "avaliação" if r["acesso_tipo"] == "avaliacao" else "pago",
                "Comentário": r["comentario"]} for r in sorted(com, key=lambda r: r["criado_em"], reverse=True)]),
                hide_index=True, width="stretch")
        else:
            st.caption("Ninguém escreveu comentário ainda.")

    st.subheader("Uso do app")
    st.caption("O comportamento confirma (ou desmente) a nota: aluno satisfeito volta e continua resolvendo questões.")
    u = db.um(
        """SELECT COUNT(*) AS alunos,
                  COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM resposta r WHERE r.usuario_id = u.id
                                                   AND r.respondida_em > now() - interval '7 days')) AS ativos7,
                  COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM resposta r WHERE r.usuario_id = u.id
                                                   AND r.respondida_em > now() - interval '30 days')) AS ativos30,
                  COUNT(*) FILTER (WHERE (SELECT COUNT(DISTINCT (r.respondida_em AT TIME ZONE 'America/Campo_Grande')::date)
                                          FROM resposta r WHERE r.usuario_id = u.id) >= 2) AS voltaram,
                  COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM simulado s WHERE s.usuario_id = u.id
                                                   AND s.status = 'finalizado')) AS com_simulado,
                  COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM material_download d WHERE d.usuario_id = u.id)) AS baixaram,
                  COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM acesso_log l WHERE l.usuario_id = u.id
                                                   AND l.evento IN ('cadastro_proprio', 'acesso_avaliacao'))) AS avaliaram,
                  COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM acesso_log l WHERE l.usuario_id = u.id
                                                   AND l.evento IN ('cadastro_proprio', 'acesso_avaliacao'))
                                     AND EXISTS (SELECT 1 FROM pagamento g WHERE g.usuario_id = u.id)) AS converteram,
                  (SELECT COUNT(*) FROM resposta r JOIN usuario x ON x.id = r.usuario_id
                    WHERE x.perfil = 'aluno' AND r.respondida_em > now() - interval '7 days'"""
        + ("" if tr == "todas" else " AND x.concurso = %(tr)s") + """) AS resp7
           FROM usuario u WHERE u.perfil = 'aluno' AND u.ativo""" + f_usu, p)
    tot = u["alunos"] or 0
    pct = lambda v: f"{v} ({100 * v / tot:.0f}%)" if tot else str(v)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Alunos", tot)
    m2.metric("Ativos (7 dias)", u["ativos7"], help="Responderam ao menos 1 questão nos últimos 7 dias.")
    m3.metric("Ativos (30 dias)", u["ativos30"])
    m4.metric("Questões/ativo na semana", f"{u['resp7'] / u['ativos7']:.0f}" if u["ativos7"] else "—")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Voltaram em 2+ dias", pct(u["voltaram"]))
    m2.metric("Fizeram simulado", pct(u["com_simulado"]))
    m3.metric("Baixaram PDF", pct(u["baixaram"]))
    conv = f"{100 * u['converteram'] / u['avaliaram']:.0f}%" if u["avaliaram"] else "—"
    m4.metric("Avaliação → pago", f"{conv} ({u['converteram']} de {u['avaliaram']})" if u["avaliaram"] else conv,
              help="Dos alunos que entraram pela avaliação grátis, quantos registraram pagamento.")

    with st.expander("Uso por aluno (com a última nota)"):
        linhas = db.consultar(
            """SELECT u.nome, u.login, u.concurso,
                      (SELECT COUNT(DISTINCT r.questao_id) FROM resposta r WHERE r.usuario_id = u.id) AS questoes,
                      (SELECT COUNT(*) FROM resposta r WHERE r.usuario_id = u.id
                         AND r.respondida_em > now() - interval '7 days') AS semana,
                      (SELECT COUNT(DISTINCT (r.respondida_em AT TIME ZONE 'America/Campo_Grande')::date)
                         FROM resposta r WHERE r.usuario_id = u.id) AS dias,
                      (SELECT COUNT(*) FROM simulado s WHERE s.usuario_id = u.id AND s.status = 'finalizado') AS simulados,
                      (SELECT COUNT(DISTINCT d.material_id) FROM material_download d WHERE d.usuario_id = u.id) AS pdfs,
                      (SELECT MAX(r.respondida_em) FROM resposta r WHERE r.usuario_id = u.id) AS ultimo,
                      (SELECT s.nota FROM satisfacao s WHERE s.usuario_id = u.id AND s.nota IS NOT NULL
                         ORDER BY s.criado_em DESC LIMIT 1) AS nota
               FROM usuario u WHERE u.perfil = 'aluno' AND u.ativo""" + f_usu + " ORDER BY questoes DESC, u.nome", p)
        if linhas:
            st.dataframe(pd.DataFrame([{
                "Aluno": l["nome"], "Usuário": l["login"], "Concurso": CONCURSOS_CURTO.get(l["concurso"], l["concurso"]),
                "Questões": l["questoes"], "Na semana": l["semana"], "Dias de uso": l["dias"],
                "Simulados": l["simulados"], "PDFs": l["pdfs"],
                "Último uso": f"{_local(l['ultimo']):%d/%m/%Y}" if l["ultimo"] else "—",
                "Nota": "—" if l["nota"] is None else str(l["nota"])} for l in linhas]), hide_index=True, width="stretch")
            st.caption("Atenção a quem deu nota alta e parou de usar: a nota foi educação, não satisfação. "
                       "E a quem usa muito e deu nota baixa: costuma ser quem mais tem a dizer.")
        else:
            st.caption("Nenhum aluno nesta trilha.")


# ======================================================================= ACESSO E PAGAMENTO
# Aluno com usuario.acesso_ate preenchido só usa o app até essa data (NULL = sem prazo). Equipe nunca é bloqueada.
# Pagamento: Pix com QR Code gerado pelo próprio app (sem intermediário e sem taxa). O aluno paga, manda o comprovante
# pelo WhatsApp e o administrador libera em Usuários. Dados do Pix ficam nos Secrets do Streamlit, seção [pix].
AVALIACAO_DIAS = 2
ACESSO_OPCOES = {"avaliacao": f"Avaliação grátis ({AVALIACAO_DIAS} dias)", "livre": "Sem prazo"}


def _acesso(uid: int) -> dict:
    a = db.um("""SELECT acesso_ate, acesso_tipo, concurso, (acesso_ate IS NOT NULL AND acesso_ate <= now()) AS vencido
                 FROM usuario WHERE id = %s""", (uid,))
    return a or {"acesso_ate": None, "acesso_tipo": None, "concurso": "cfs", "vencido": False}


def em_avaliacao(usuario: dict) -> bool:
    """Aluno na avaliação grátis: usa tudo, menos baixar os PDFs."""
    return usuario["perfil"] == "aluno" and _acesso(usuario["id"])["acesso_tipo"] == "avaliacao"


def _pix_cfg() -> dict | None:
    try:
        cfg = {k: str(v) for k, v in dict(st.secrets.get("pix", {})).items()}
    except Exception:
        cfg = {}
    return cfg if cfg.get("chave") else None


def _sem_acento(t: str) -> str:
    t = unicodedata.normalize("NFKD", t).encode("ascii", "ignore").decode()
    return re.sub(r"[^A-Za-z0-9 ]", "", t).upper().strip()


def _crc16(dados: str) -> str:
    crc = 0xFFFF
    for b in dados.encode("utf-8"):
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return f"{crc:04X}"


def pix_copia_e_cola(chave: str, nome: str, cidade: str, valor: str | None = None, txid: str = "***") -> str:
    """Código Pix estático (padrão BR Code do Banco Central), o mesmo que o app do banco gera para "Receber"."""
    campo = lambda i, v: f"{i}{len(v):02d}{v}"
    conta = campo("00", "br.gov.bcb.pix") + campo("01", chave.strip())
    p = campo("00", "01") + campo("26", conta) + campo("52", "0000") + campo("53", "986")
    if valor:
        p += campo("54", f"{float(str(valor).replace(',', '.')):.2f}")
    p += campo("58", "BR") + campo("59", _sem_acento(nome)[:25]) + campo("60", _sem_acento(cidade)[:15])
    p += campo("62", campo("05", re.sub(r"[^A-Za-z0-9]", "", txid)[:25] or "***"))
    p += "6304"
    return p + _crc16(p)


def _qr_img(texto: str, tamanho: int = 230) -> str:
    """QR Code como <img> SVG (usa o reportlab, que o app já tem)."""
    from reportlab.graphics import renderSVG
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing

    w = QrCodeWidget(texto)
    x0, y0, x1, y1 = w.getBounds()
    d = Drawing(tamanho, tamanho, transform=[tamanho / (x1 - x0), 0, 0, tamanho / (y1 - y0), 0, 0])
    d.add(w)
    svg = renderSVG.drawToString(d)
    return (f'<img alt="QR Code Pix" style="background:#fff;padding:6px;border-radius:8px" '
            f'src="data:image/svg+xml;base64,{base64.b64encode(svg.encode()).decode()}">')


def _bloco_pagamento(usuario: dict):
    cfg = _pix_cfg()
    if not cfg:
        st.info("Para adquirir o acesso, fale com o administrador do app.")
        return
    if cfg.get("oferta"):
        st.markdown(f"**{esc(cfg['oferta'])}**", unsafe_allow_html=True)
    valor = cfg.get("valor")
    if valor:
        st.markdown(f"Valor: **R$ {float(valor.replace(',', '.')):.2f}**".replace(".", ","))
    codigo = pix_copia_e_cola(cfg["chave"], cfg.get("nome", NOME_APP), cfg.get("cidade", "CAMPO GRANDE"), valor,
                              txid=usuario["login"])
    c1, c2 = st.columns([1, 1.5])
    c1.markdown(_qr_img(codigo), unsafe_allow_html=True)
    with c2:
        st.markdown("**1.** Abra o app do seu banco, escolha **Pix → Ler QR Code** (ou **Pix copia e cola**) e pague.  \n"
                    f"**2.** Mande o comprovante pelo WhatsApp, informando o seu usuário: **{esc(usuario['login'])}**.  \n"
                    "**3.** Assim que o pagamento for conferido, o seu acesso é liberado. É só entrar de novo.")
        if cfg.get("whatsapp"):
            from urllib.parse import quote
            msg = (f"Olá! Fiz o Pix do {NOME_APP}. Meu usuário é {usuario['login']} "
                   f"({usuario['nome']}). Segue o comprovante.")
            st.link_button("📲 Enviar comprovante pelo WhatsApp",
                           f"https://wa.me/{re.sub(r'[^0-9]', '', cfg['whatsapp'])}?text={quote(msg)}",
                           type="primary", width="stretch")
    st.caption("Pix copia e cola:")
    st.code(codigo, language=None)


def tela_acesso_encerrado(usuario: dict, acesso: dict):
    _cabecalho()
    quando = _local(acesso["acesso_ate"])
    st.warning(f"Olá, {usuario['nome']}. O seu acesso ao app terminou em **{quando:%d/%m/%Y às %H:%M}**. "
               "Suas respostas, simulados e o seu Raio-X continuam guardados: quando o acesso for liberado, "
               "está tudo lá.")
    st.subheader("Como continuar")
    _bloco_pagamento(usuario)
    st.button("Sair", key="ae_sair", on_click=_sair, args=(usuario["id"],))


def _aviso_prazo(usuario: dict, acesso: dict):
    resta = acesso["acesso_ate"] - datetime.now(timezone.utc)
    horas = max(0, int(resta.total_seconds() // 3600))
    tempo = f"{horas // 24} dia(s) e {horas % 24} h" if horas >= 24 else f"{horas} h"
    st.caption(f"⏳ Seu acesso vai até **{_local(acesso['acesso_ate']):%d/%m %H:%M}** (faltam {tempo}).")
    with st.popover("💳 Adquirir acesso", width="stretch"):
        _bloco_pagamento(usuario)


AVALIACAO_SIMULADOS = 1
AVALIACAO_PDFS = 1
AVALIACAO_TIPOS_PDF = ("resumo", "mapa", "bizu")      # a lei seca comentada e o relatório ficam só para quem adquiriu


def _contador_amostra(usuario: dict):
    r = db.um("""SELECT (SELECT COUNT(*) FROM questao q WHERE q.status = 'aprovada' AND (q.essencial OR q.amostra)"""
              + filtro_trilha() + """) AS total,
                        (SELECT COUNT(DISTINCT r.questao_id) FROM resposta r JOIN questao q ON q.id = r.questao_id
                          WHERE r.usuario_id = %s AND (q.essencial OR q.amostra)""" + filtro_trilha() + """) AS feitas""",
              (usuario["id"],))
    total, feitas = r["total"], min(r["feitas"], r["total"])
    st.progress(feitas / total if total else 0, text=f"🎁 Avaliação: {feitas} de {total} questões grátis")
    if total and feitas >= total:
        st.caption("Você fez todas as questões da avaliação. Adquira o acesso para liberar as mais de 2.000 do banco.")


def _simulados_feitos(uid: int) -> int:
    return db.um("SELECT COUNT(*) AS n FROM simulado WHERE usuario_id = %s AND status <> 'descartado'", (uid,))["n"]


def _pdfs_baixados(uid: int) -> set[int]:
    return {r["material_id"] for r in db.consultar("SELECT DISTINCT material_id FROM material_download WHERE usuario_id = %s AND modo <> 'video'",
                                                    (uid,))}


def _uso_materiais() -> dict:
    """Por pessoa: PDFs diferentes abertos, páginas lidas/páginas dos abertos, downloads e o maior nº de downloads de um mesmo PDF."""
    _garante_materiais()
    linhas = db.consultar(
        f"""WITH por_pdf AS (
                SELECT d.usuario_id, d.material_id, MAX(m.paginas) AS paginas,
                       LEAST(MAX(COALESCE(d.maior_pagina, 0)), MAX(m.paginas)) AS lidas, SUM({SQL_DL}) AS dl
                FROM material_download d JOIN material_estudo m ON m.id = d.material_id
                GROUP BY d.usuario_id, d.material_id)
            SELECT usuario_id, COUNT(*) AS abertos, SUM(dl) AS downloads, MAX(dl) AS max_dl,
                   SUM(lidas) AS lidas, SUM(paginas) FILTER (WHERE lidas > 0) AS paginas
            FROM por_pdf GROUP BY usuario_id""")
    return {r["usuario_id"]: {"abertos": r["abertos"], "downloads": int(r["downloads"] or 0),
                              "max_dl": int(r["max_dl"] or 0), "lidas": int(r["lidas"] or 0),
                              "paginas": int(r["paginas"] or 0)} for r in linhas}


def _total_pdfs(concurso: str) -> int:
    return db.um("SELECT COUNT(*) AS n FROM material_estudo WHERE publicado AND trilha IN (%s, 'todas')", (concurso,))["n"]


def _uso_materiais_aluno(alvo: dict):
    """Detalhe por PDF para o administrador: quando abriu, até onde leu, quantas vezes baixou."""
    linhas = db.consultar(
        f"""SELECT m.titulo, m.lei, m.paginas, MIN(d.baixado_em) AS primeiro, MAX(COALESCE(d.lido_em, d.baixado_em)) AS ultimo,
                   COUNT(*) AS aberturas, MAX(COALESCE(d.maior_pagina, 0)) AS lidas, SUM({SQL_DL}) AS dl
            FROM material_download d JOIN material_estudo m ON m.id = d.material_id
            WHERE d.usuario_id = %s GROUP BY m.id ORDER BY MIN(d.baixado_em)""", (alvo["id"],))
    tot = _total_pdfs(alvo.get("concurso") or "cfs")
    if not linhas:
        st.caption(f"Ainda não abriu nenhum dos {tot} materiais da trilha.")
        return
    ini, fim = _local(linhas[0]["primeiro"]), _local(max(r["ultimo"] for r in linhas))
    dias = max(1, (fim.date() - ini.date()).days + 1)
    pct = round(100 * len(linhas) / tot) if tot else 0
    st.markdown(f"Abriu **{len(linhas)} de {tot}** materiais da trilha ({pct}%) em **{dias} dia(s)**: "
                f"de {ini:%d/%m} a {fim:%d/%m}.")
    st.dataframe(pd.DataFrame([{
        "Material": r["titulo"], "Matéria": r["lei"],
        "Leu até": f"pág. {min(r['lidas'], r['paginas'] or r['lidas'])} de {r['paginas'] or '?'}" if r["lidas"] else "—",
        "Aberturas": r["aberturas"], "Downloads": int(r["dl"] or 0),
        "Primeira vez": f"{_local(r['primeiro']):%d/%m %H:%M}", "Última vez": f"{_local(r['ultimo']):%d/%m %H:%M}",
    } for r in linhas]), hide_index=True, width="stretch")


def _rotulo_acesso(c: dict) -> str:
    if c["perfil"] != "aluno":
        return "equipe"
    tipo = " (avaliação)" if c.get("acesso_tipo") == "avaliacao" else ""
    if c["acesso_ate"] is None:
        return "sem prazo" + tipo
    d = _local(c["acesso_ate"])
    return (f"encerrado em {d:%d/%m %H:%M}" if c["acesso_vencido"] else f"até {d:%d/%m/%Y %H:%M}") + tipo


def _definir_acesso(alvo_id: int, ate, evento: str, tipo: str | None = "pago"):
    """tipo: 'avaliacao' (sem download de PDF) ou 'pago'. tipo=None mantém o que estava (ex.: encerrar agora)."""
    if tipo is None:
        db.executar("UPDATE usuario SET acesso_ate = %s WHERE id = %s", (ate, alvo_id))
    else:
        db.executar("UPDATE usuario SET acesso_ate = %s, acesso_tipo = %s WHERE id = %s", (ate, tipo, alvo_id))
    auth.registrar(evento, alvo_id)


def _registrar_pagamento(alvo_id: int, valor: float, ate, descricao: str, admin_id: int):
    if valor and valor > 0:
        db.executar("""INSERT INTO pagamento (usuario_id, valor, acesso_ate, descricao, registrado_por)
                       VALUES (%s, %s, %s, %s, %s)""", (alvo_id, round(float(valor), 2), ate, descricao, admin_id))


def _valor_padrao() -> float:
    try:
        return float(str((_pix_cfg() or {}).get("valor", "0")).replace(",", "."))
    except ValueError:
        return 0.0


def _gerenciar_acesso(alvo: dict, admin: dict | None = None):
    """Liberar, estender ou encerrar o acesso de um aluno (avaliação grátis ou período pago).
    Ao liberar (+30 dias, sem prazo, até a data), o valor informado entra no Financeiro (0 = cortesia, não registra)."""
    st.markdown(f"**Acesso de {esc(alvo['nome'])}:** {_rotulo_acesso(alvo)}", unsafe_allow_html=True)
    admin_id = admin["id"] if admin else None
    valor = st.number_input("Valor recebido nesta liberação (R$) · deixe 0 para cortesia", min_value=0.0, step=10.0,
                            value=_valor_padrao(), format="%.2f", key=f"acval_{alvo['id']}")
    agora = datetime.now(timezone.utc)
    base = max(agora, alvo["acesso_ate"]) if alvo["acesso_ate"] is not None else agora
    a1, a2, a3, a4 = st.columns(4)
    if a1.button("Liberar +30 dias", key=f"ac30_{alvo['id']}", width="stretch",
                 help="Soma 30 dias ao prazo atual (ou a partir de agora, se já venceu)."):
        _definir_acesso(alvo["id"], base + timedelta(days=30), "acesso_mais_30")
        _registrar_pagamento(alvo["id"], valor, base + timedelta(days=30), "Liberação +30 dias", admin_id)
        st.rerun()
    if a2.button(f"Avaliação de {AVALIACAO_DIAS} dias", key=f"acav_{alvo['id']}", width="stretch",
                 help=f"Libera {AVALIACAO_DIAS} dias a partir de agora."):
        _definir_acesso(alvo["id"], agora + timedelta(days=AVALIACAO_DIAS), "acesso_avaliacao", "avaliacao")
        st.rerun()
    if a3.button("Sem prazo", key=f"aclivre_{alvo['id']}", width="stretch"):
        _definir_acesso(alvo["id"], None, "acesso_sem_prazo")
        _registrar_pagamento(alvo["id"], valor, None, "Liberação sem prazo", admin_id)
        st.rerun()
    if a4.button("Encerrar agora", key=f"acfim_{alvo['id']}", width="stretch"):
        _definir_acesso(alvo["id"], agora, "acesso_encerrado", None)
        st.rerun()
    d1, d2 = st.columns([1.4, 1])
    data = d1.date_input("Ou liberar até a data", value=(_local(base) + timedelta(days=30)).date(), format="DD/MM/YYYY",
                         key=f"acdata_{alvo['id']}")
    if d2.button("Liberar até essa data", key=f"acdt_{alvo['id']}", width="stretch"):
        ate = datetime(data.year, data.month, data.day, 23, 59, tzinfo=FUSO)
        _definir_acesso(alvo["id"], ate, "acesso_ate_data")
        _registrar_pagamento(alvo["id"], valor, ate, f"Liberação até {data:%d/%m/%Y}", admin_id)
        st.rerun()


def tela_usuarios(usuario: dict):
    st.header("Usuários")
    st.caption("A senha provisória aparece uma única vez: envie em particular.")
    aberto = config_app("cadastro_aberto", "1") == "1"
    novo = st.toggle(f"Cadastro aberto na tela de entrada (quem se cadastra ganha {AVALIACAO_DIAS} dias de avaliação)",
                     value=aberto, key="cfg_cadastro")
    if novo != aberto:
        definir_config("cadastro_aberto", "1" if novo else "0")
        auth.registrar("cadastro_aberto" if novo else "cadastro_fechado", usuario["id"])
    tot = db.um("""SELECT COUNT(*) FILTER (WHERE perfil = 'aluno' AND ativo) AS alunos,
                          COUNT(*) FILTER (WHERE perfil = 'aluno' AND ativo AND acesso_tipo = 'avaliacao'
                                           AND acesso_ate > now()) AS avaliacao,
                          COUNT(*) FILTER (WHERE perfil = 'aluno' AND ativo AND COALESCE(acesso_tipo, '') <> 'avaliacao'
                                           AND (acesso_ate IS NULL OR acesso_ate > now())) AS liberados,
                          COUNT(*) FILTER (WHERE perfil = 'aluno' AND ativo AND acesso_ate <= now()) AS vencidos,
                          COUNT(*) FILTER (WHERE perfil <> 'aluno' AND ativo) AS equipe
                   FROM usuario WHERE login IS NOT NULL""")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Alunos", tot["alunos"])
    m2.metric("Em avaliação", tot["avaliacao"])
    m3.metric("Com acesso liberado", tot["liberados"])
    m4.metric("Acesso vencido", tot["vencidos"])
    m5.metric("Equipe", tot["equipe"])

    with st.form("novo_usuario", clear_on_submit=True):
        st.markdown("**Cadastrar pessoa**")
        c1, c2, c3, c4 = st.columns([2, 1.4, 1, 1.4])
        nome = c1.text_input("Nome (ex.: Cb PM Lozo)", key="nu_nome")
        login = c2.text_input("Usuário (ex.: lozo)", key="nu_login")
        perfil = _chave(auth.PERFIS, c3.selectbox("Perfil", list(auth.PERFIS.values()), index=2, key="nu_perfil"))
        acesso_ini = _chave(ACESSO_OPCOES, c4.selectbox("Acesso (aluno)", list(ACESSO_OPCOES.values()), key="nu_acesso",
                                                        help="Avaliação grátis: o app bloqueia sozinho no fim do prazo."))
        criar = st.form_submit_button("Cadastrar", type="primary")
    if criar:
        login_n = auth.normalizar_login(login)
        erro = ("Preencha o nome." if not nome.strip() else
                "Usuário inválido: 3 a 30 caracteres entre letras minúsculas, números, ponto, hífen ou sublinhado."
                if not LOGIN_OK.match(login_n) else
                "Esse usuário já existe." if auth.login_existe(login_n) else None)
        if erro:
            st.error(erro)
        else:
            senha = auth.senha_provisoria()
            uid = auth.criar_usuario(nome, login_n, perfil, senha, trocar=True)
            auth.registrar("usuario_criado", uid)
            if perfil == "aluno" and acesso_ini == "avaliacao":
                _definir_acesso(uid, datetime.now(timezone.utc) + timedelta(days=AVALIACAO_DIAS), "acesso_avaliacao",
                                "avaliacao")
            st.session_state["senha_mostrar"] = (nome.strip(), login_n, senha)
    _mostrar_senha()

    contas = db.consultar(
        """SELECT id, nome, login, perfil, ativo, ultimo_acesso, acesso_ate, acesso_tipo, whatsapp, concurso, criado_em,
                  (acesso_ate IS NOT NULL AND acesso_ate <= now()) AS acesso_vencido,
                  (bloqueado_ate IS NOT NULL AND bloqueado_ate > now()) AS bloqueado,
                  (SELECT COUNT(*) FROM resposta r WHERE r.usuario_id = u.id) AS respostas,
                  (SELECT COUNT(*) FROM parecer p WHERE p.usuario_id = u.id) AS pareceres
           FROM usuario u WHERE login IS NOT NULL ORDER BY ativo DESC, nome""")
    uso = _uso_materiais()
    for c in contas:
        x = uso.get(c["id"], {})
        tot = _total_pdfs(c.get("concurso") or "cfs")
        c["pdfs"] = f"{x.get('abertos', 0)}/{tot}"
        c["leitura"] = f"{round(100 * x['lidas'] / x['paginas'])}%" if x.get("paginas") else "—"
        c["downloads"] = x.get("downloads", 0)
        c["alerta"] = (f"⚠️ {x['max_dl']}x o mesmo PDF" if x.get("max_dl", 0) >= ALERTA_DOWNLOADS_PDF else "")
    df = pd.DataFrame(contas)
    df["acesso"] = [_rotulo_acesso(c) for c in contas]
    df["concurso"] = df["concurso"].map(lambda c: CONCURSOS_CURTO.get(c, c))
    df["whatsapp"] = df["whatsapp"].fillna("")
    df["criado_em"] = df["criado_em"].apply(lambda d: f"{_local(d):%d/%m/%Y}" if pd.notna(d) else "")
    st.dataframe(
        df.assign(perfil=df["perfil"].map(auth.PERFIS),
                  ativo=df["ativo"].map({True: "Ativo", False: "Desativado"}),
                  bloqueado=df["bloqueado"].map({True: "Bloqueado", False: ""}),
                  ultimo_acesso=df["ultimo_acesso"].apply(lambda d: f"{d:%d/%m/%Y %H:%M}" if pd.notna(d) else "nunca"))
          [["nome", "login", "perfil", "concurso", "whatsapp", "criado_em", "ativo", "acesso", "bloqueado", "ultimo_acesso",
            "respostas", "pdfs", "leitura", "downloads", "alerta", "pareceres"]]
          .rename(columns={"nome": "Nome", "login": "Usuário", "perfil": "Perfil", "ativo": "Situação", "acesso": "Acesso",
                           "concurso": "Concurso", "whatsapp": "WhatsApp", "criado_em": "Cadastro",
                           "bloqueado": "Bloqueio", "ultimo_acesso": "Último acesso", "respostas": "Respostas",
                           "pdfs": "Materiais abertos", "leitura": "Leitura", "downloads": "Downloads",
                           "alerta": "Atenção", "pareceres": "Pareceres"}),
        hide_index=True, width="stretch")
    st.caption("Materiais abertos = PDFs e vídeos diferentes que a pessoa abriu, do total publicado na trilha dela. Leitura = páginas "
               f"lidas no app sobre as páginas dos PDFs que abriu. Atenção = baixou {ALERTA_DOWNLOADS_PDF} vezes ou mais o "
               "mesmo PDF (vale olhar se a senha está sendo dividida; o app não bloqueia nada).")

    st.subheader("Gerenciar uma conta")
    nomes = {f"{c['nome']} ({c['login']})": c["id"] for c in contas}
    alvo_id = nomes[st.selectbox("Conta", list(nomes), key="gu_alvo")]
    alvo = next(c for c in contas if c["id"] == alvo_id)
    eu = alvo_id == usuario["id"]
    c1, c2, c3 = st.columns(3)
    if c1.button("Gerar nova senha provisória", key="gu_reset", width="stretch"):
        senha = auth.senha_provisoria()
        auth.definir_senha(alvo_id, senha, provisoria=True)
        st.session_state["senha_mostrar"] = (alvo["nome"], alvo["login"], senha)
        st.rerun()
    if alvo["ativo"]:
        if c2.button("Desativar acesso", key="gu_off", disabled=eu, width="stretch",
                     help="Você não pode desativar a própria conta." if eu else "A pessoa não consegue mais entrar."):
            db.executar("UPDATE usuario SET ativo = FALSE WHERE id = %s", (alvo_id,))
            auth.registrar("usuario_desativado", alvo_id)
            st.rerun()
    elif c2.button("Reativar acesso", key="gu_on", width="stretch"):
        db.executar("UPDATE usuario SET ativo = TRUE, tentativas_falhas = 0, bloqueado_ate = NULL WHERE id = %s", (alvo_id,))
        auth.registrar("usuario_reativado", alvo_id)
        st.rerun()
    novo_perfil = _chave(auth.PERFIS, c3.selectbox("Perfil", list(auth.PERFIS.values()),
                                                   index=list(auth.PERFIS).index(alvo["perfil"]),
                                                   key=f"gu_perfil_{alvo_id}", disabled=eu, label_visibility="collapsed"))
    if not eu and novo_perfil != alvo["perfil"]:
        db.executar("UPDATE usuario SET perfil = %s WHERE id = %s", (novo_perfil, alvo_id))
        auth.registrar(f"perfil_{novo_perfil}", alvo_id)
        st.rerun()
    if alvo["perfil"] == "aluno":
        with st.container(border=True):
            atual = alvo.get("concurso") or "cfs"
            novo = _chave(CONCURSOS, st.selectbox(
                "Concurso / trilha do aluno", list(CONCURSOS.values()),
                index=list(CONCURSOS).index(atual) if atual in CONCURSOS else 0, key=f"gu_conc_{alvo_id}",
                help="Define o que o aluno vê: o banco do CFS ou o do Provão de conclusão do CFS 2026."))
            if novo != atual:
                db.executar("UPDATE usuario SET concurso = %s WHERE id = %s", (novo, alvo_id))
                auth.registrar(f"concurso_{novo}", alvo_id)
                st.rerun()
            _gerenciar_acesso(alvo, usuario)
        with st.expander("📚 Uso dos materiais"):
            _uso_materiais_aluno(alvo)

    with st.expander("Registro de acessos (últimos 100)"):
        log = db.consultar(
            """SELECT l.em, COALESCE(u.nome, '—') AS nome, COALESCE(u.login, l.login_tentado) AS usuario, l.evento
               FROM acesso_log l LEFT JOIN usuario u ON u.id = l.usuario_id ORDER BY l.em DESC LIMIT 100""")
        if log:
            dl = pd.DataFrame(log)
            dl["em"] = dl["em"].apply(lambda d: f"{d:%d/%m/%Y %H:%M}")
            st.dataframe(dl.rename(columns={"em": "Quando", "nome": "Nome", "usuario": "Usuário", "evento": "Evento"}),
                         hide_index=True, width="stretch")


def _mostrar_senha():
    info = st.session_state.get("senha_mostrar")
    if not info:
        return
    nome, login, senha = info
    st.success(f"Acesso de **{nome}** pronto. Envie em particular (ela some desta tela quando você clicar em OK):")
    st.code(f"Usuário: {login}\nSenha provisória: {senha}\nNo primeiro acesso o app pede para trocar a senha.", language=None)
    if st.button("OK, já anotei", key="senha_ok"):
        st.session_state.pop("senha_mostrar", None)
        st.rerun()


# ======================================================================= BIBLIOTECA (só admin)
CATEGORIAS_BIB = ["CFS PMMS", "PCMS (Polícia Civil)", "BMMS (Bombeiros)", "CFC PMMS", "Outros"]
TIPOS_BIB = ["pdf", "docx", "doc", "pptx", "xlsx", "txt", "jpg", "jpeg", "png", "zip"]
LIMITE_MB = 450  # o plano gratuito do Neon tem 0,5 GB no total


@st.cache_resource(show_spinner=False)
def _garante_biblioteca() -> bool:
    db.executar(
        """CREATE TABLE IF NOT EXISTS material (
               id          SERIAL PRIMARY KEY,
               categoria   TEXT NOT NULL,
               nome        TEXT NOT NULL,
               mime        TEXT,
               tamanho     INT  NOT NULL,
               observacao  TEXT,
               dados       BYTEA NOT NULL,
               enviado_por INT REFERENCES usuario(id),
               criado_em   TIMESTAMPTZ NOT NULL DEFAULT now(),
               UNIQUE (categoria, nome, tamanho))""")
    return True


def _mb(b) -> str:
    return f"{(b or 0) / 1048576:.1f} MB"


def tela_biblioteca(usuario: dict):
    st.header("Biblioteca de materiais")
    st.caption("Área exclusiva do administrador para guardar o material de estudo dos próximos concursos. "
               "Nada daqui aparece para revisores ou alunos.")
    _garante_biblioteca()
    usado = db.um("SELECT COALESCE(SUM(tamanho), 0) AS t, COUNT(*) AS n FROM material")
    st.progress(min(usado["t"] / (LIMITE_MB * 1048576), 1.0),
                text=f"{usado['n']} arquivos · {_mb(usado['t'])} usados de ~{LIMITE_MB} MB livres no banco")

    with st.form("bib_envio", clear_on_submit=True):
        c1, c2 = st.columns([1, 1.4])
        categoria = c1.selectbox("Para qual concurso", CATEGORIAS_BIB, key="bib_cat")
        obs = c2.text_input("Observação (opcional)", key="bib_obs", placeholder="ex.: versão antiga, reconferir no Planalto")
        arquivos = st.file_uploader("Arquivos", type=TIPOS_BIB, accept_multiple_files=True, key="bib_arq")
        enviar = st.form_submit_button("Guardar na biblioteca", type="primary")
    if enviar:
        if not arquivos:
            st.warning("Escolha pelo menos um arquivo.")
        else:
            novos, repetidos = 0, 0
            for a in arquivos:
                dados = a.getvalue()
                if usado["t"] + len(dados) > LIMITE_MB * 1048576:
                    st.error(f"Sem espaço para {a.name}. Apague arquivos antigos ou fale com o suporte do banco.")
                    break
                existe = db.um("SELECT 1 FROM material WHERE categoria=%s AND nome=%s AND tamanho=%s",
                               (categoria, a.name, len(dados)))
                if existe:
                    repetidos += 1
                    continue
                db.executar("""INSERT INTO material (categoria, nome, mime, tamanho, observacao, dados, enviado_por)
                               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                            (categoria, a.name, a.type, len(dados), obs or None, dados, usuario["id"]))
                usado["t"] += len(dados)
                novos += 1
            if novos:
                st.success(f"{novos} arquivo(s) guardado(s) em {categoria}.")
            if repetidos:
                st.info(f"{repetidos} arquivo(s) já estavam na biblioteca e foram ignorados.")

    itens = db.consultar("""SELECT id, categoria, nome, tamanho, observacao, criado_em
                            FROM material ORDER BY categoria, nome""")
    if not itens:
        st.info("A biblioteca ainda está vazia.")
        return
    st.subheader("Arquivos guardados")
    filtro = st.selectbox("Concurso", ["Todos"] + sorted({i["categoria"] for i in itens}), key="bib_filtro")
    vis = [i for i in itens if filtro == "Todos" or i["categoria"] == filtro]
    st.dataframe(pd.DataFrame([{"Concurso": i["categoria"], "Arquivo": i["nome"], "Tamanho": _mb(i["tamanho"]),
                                "Observação": i["observacao"] or "", "Guardado em": i["criado_em"].strftime("%d/%m/%Y")}
                               for i in vis]), hide_index=True, width="stretch")

    rotulos = {f"{i['nome']} ({i['categoria']})": i["id"] for i in vis}
    escolhido = st.selectbox("Escolha um arquivo para baixar ou apagar", list(rotulos), index=None, key="bib_sel")
    if escolhido:
        mid = rotulos[escolhido]
        c1, c2 = st.columns(2)
        reg = db.um("SELECT nome, mime, dados FROM material WHERE id = %s", (mid,))
        c1.download_button("Baixar", data=bytes(reg["dados"]), file_name=reg["nome"],
                           mime=reg["mime"] or "application/octet-stream", width="stretch", key=f"bib_dl_{mid}")
        if c2.toggle("Quero apagar este arquivo", key=f"bib_conf_{mid}"):
            if c2.button("Apagar definitivamente", key=f"bib_del_{mid}", width="stretch"):
                db.executar("DELETE FROM material WHERE id = %s", (mid,))
                st.session_state.pop("bib_sel", None)
                st.rerun()


# ======================================================================= MINHA CONTA
def tela_conta(usuario: dict):
    st.header("Minha conta")
    st.write(f"**{usuario['nome']}** · usuário `{usuario['login']}` · {auth.PERFIS[usuario['perfil']]}")
    atual = _acesso(usuario["id"])["concurso"] or "cfs"
    if usuario["perfil"] == "aluno":
        # Cada trilha é um produto: o aluno não troca o concurso sozinho (só o administrador, em Usuários).
        st.markdown(f"**Concurso:** {CONCURSOS.get(atual, atual)}")
        st.caption("Para mudar de concurso (por exemplo, do CFS para o Provão), fale com o administrador.")
        if atual not in CONCURSOS_COM_CONTEUDO:
            st.info(f"O conteúdo próprio do {CONCURSOS_CURTO[atual]} está em preparação. Enquanto isso, use o do CFS PMMS: "
                    "a legislação da PMMS é a mesma base.")
        st.subheader("Trocar senha")
        tela_trocar_senha(usuario, obrigatoria=False)
        return
    escolha = _chave(CONCURSOS, st.selectbox("Concurso que vou fazer", list(CONCURSOS.values()),
                                             index=list(CONCURSOS).index(atual) if atual in CONCURSOS else 0,
                                             key="mc_conc"))
    if escolha != atual:
        db.executar("UPDATE usuario SET concurso = %s WHERE id = %s", (escolha, usuario["id"]))
        if usuario["perfil"] == "aluno":
            st.session_state["trilha"] = trilha_de(escolha)
            for k in [k for k in st.session_state if k.startswith(("f_grupo", "f_sub_", "sim_grupos", "sim_assuntos"))]:
                del st.session_state[k]
            st.session_state.pop("filtro_ativo", None)
        st.success("Concurso atualizado. Questões, simulados e materiais já seguem a nova escolha.")
    if escolha not in CONCURSOS_COM_CONTEUDO:
        st.info(f"O conteúdo próprio do {CONCURSOS_CURTO[escolha]} está em preparação. Enquanto isso, use o do CFS PMMS: "
                "a legislação da PMMS é a mesma base.")
    st.subheader("Trocar senha")
    tela_trocar_senha(usuario, obrigatoria=False)


# ======================================================================
# APP
# ======================================================================
st.set_page_config(page_title=NOME_APP, page_icon=logo_app(64), layout="centered")
aplicar()

# 1) Ainda não há administrador: só mostra a criação dele.
if not auth.existe_admin():
    tela_primeiro_acesso()
    st.stop()

_garante_extras()
aplicar_cookie_sessao()

# 2) Sem login: tenta retomar a sessão salva no cookie do navegador; senão, tela de entrada.
sessao = st.session_state.get("usuario")
if not sessao:
    sessao = retomar_sessao()
    if sessao:
        st.session_state["usuario"] = sessao
if not sessao:
    tela_login()
    st.stop()

# 3) A cada clique, confere se a conta ainda está ativa (desativar corta o acesso na hora).
usuario = auth.recarregar(sessao["id"])
if usuario is None:
    fechar_sessao()
    db.executar("DELETE FROM sessao_login WHERE usuario_id = %s", (sessao["id"],))
    st.session_state.clear()
    _apagar_cookie_depois()
    aplicar_cookie_sessao()
    st.error("Seu acesso foi encerrado. Fale com o administrador.")
    st.stop()
st.session_state["usuario"] = usuario

# 3b) Aluno com o acesso vencido (fim da avaliação grátis ou do período pago): só vê como adquirir.
acesso = _acesso(usuario["id"])
if usuario["perfil"] == "aluno" and acesso["vencido"]:
    tela_acesso_encerrado(usuario, acesso)
    st.stop()

st.session_state["so_amostra"] = usuario["perfil"] == "aluno" and acesso.get("acesso_tipo") == "avaliacao"
if usuario["perfil"] == "aluno":
    st.session_state["trilha"] = trilha_de(acesso.get("concurso"))
else:
    st.session_state["trilha"] = st.session_state.get("trilha_sel", st.session_state.get("trilha", "cfs"))

# 4) Senha provisória: obriga a trocar antes de qualquer coisa.
if usuario["trocar_senha"]:
    tela_trocar_senha(usuario, obrigatoria=True)
    st.stop()

# 5) Marca d'água com o nome de quem está logado, em toda a tela.
aplicar_marca_dagua(usuario["nome"], usuario["login"])

if st.session_state.pop("boas_vindas", False):
    st.success(f"Conta criada! Bem-vindo(a), {usuario['nome']}. Você tem {AVALIACAO_DIAS} dias de acesso grátis para avaliar "
               "o app. Comece por **Resolver questões** ou monte um **Simulado**.")

# 6) Menu conforme o perfil.
ICONES_MENU = {"Resolver questões": ":material/edit_note:", "Simulados": ":material/timer:",
               "Materiais": ":material/menu_book:", "Meu desempenho": ":material/insights:",
               "Revisão da equipe": ":material/fact_check:", "Usuários": ":material/group:",
               "Financeiro": ":material/payments:", "Satisfação": ":material/sentiment_satisfied:",
               "Biblioteca": ":material/local_library:",
               "Minha conta": ":material/account_circle:"}
# Menu lateral como lista de navegação: some a bolinha do rádio e a opção ativa ganha destaque.
CSS_MENU = """<style>
[data-testid="stProgress"] [role="progressbar"] > div > div > div {background-color:#4b5a23 !important}
section[data-testid="stSidebar"] div[role="radiogroup"] { gap: 2px; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label {
  width: 100%; margin: 0; padding: 7px 10px; border-radius: 8px; cursor: pointer; transition: background .15s; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:first-child { display: none; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover { background: rgba(75, 90, 35, .10); }
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
  background: rgba(75, 90, 35, .18); box-shadow: inset 3px 0 0 #4B5A23; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p { font-weight: 600; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label span[data-testid="stIconMaterial"] { color: #4B5A23; margin-right: 4px; }
</style>"""
TELAS = {"Resolver questões": tela_questoes, "Simulados": tela_simulados, "Materiais": tela_materiais,
         "Meu desempenho": tela_desempenho}
if usuario["perfil"] in ("admin", "revisor"):
    TELAS["Revisão da equipe"] = tela_revisao
if usuario["perfil"] == "admin":
    TELAS["Usuários"] = tela_usuarios
    TELAS["Financeiro"] = tela_financeiro
    TELAS["Satisfação"] = tela_satisfacao
    TELAS["Biblioteca"] = tela_biblioteca
TELAS["Minha conta"] = tela_conta

with st.sidebar:
    st.markdown(f"### {NOME_APP}")
    st.caption(TRILHAS[trilha_atual()]["sub"])
    st.write(f"👤 **{usuario['nome']}**  \n{auth.PERFIS[usuario['perfil']]}")
    if usuario["perfil"] != "aluno":
        st.selectbox("Trilha", list(TRILHAS), index=list(TRILHAS).index(trilha_atual()),
                     format_func=lambda t: TRILHAS[t]["nome"], key="trilha_sel", on_change=_trocou_trilha,
                     help="Cada trilha tem as suas questões, simulados e materiais. Os alunos veem só a trilha do "
                          "concurso que escolheram.")
    if usuario["perfil"] == "aluno":
        conc = acesso.get("concurso") or "cfs"
        st.caption(f"🎯 Concurso: **{CONCURSOS_CURTO.get(conc, conc)}**"
                   + ("" if conc in CONCURSOS_COM_CONTEUDO else " · conteúdo em preparação (use o do CFS)"))
    if usuario["perfil"] == "aluno" and acesso["acesso_ate"] is not None:
        _aviso_prazo(usuario, acesso)
    if _so_amostra():
        _contador_amostra(usuario)
    st.markdown(CSS_MENU, unsafe_allow_html=True)
    escolha = st.radio("Menu", list(TELAS), key="menu", label_visibility="collapsed",
                       format_func=lambda t: f"{ICONES_MENU.get(t, ':material/chevron_right:')} {t}")
    SLOT_MENU = st.container()  # logo abaixo do menu: a tela de Materiais põe aqui o índice das matérias
    st.button("Sair", width="stretch", on_click=_sair, args=(usuario["id"],))

if edital_atual() is None:
    st.info("O conteúdo desta trilha ainda está sendo preparado. Volte em breve.")
caixa_satisfacao(usuario, acesso)
TELAS[escolha](usuario)
