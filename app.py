"""
Aprovar Concursos — banco de questões comentadas do CFS PMMS.
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
import re
import secrets
import string
from types import SimpleNamespace

import bcrypt
import pandas as pd
import streamlit as st
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

db = SimpleNamespace(consultar=consultar, um=um, executar=executar)


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
    registrar("senha_resetada" if provisoria else "senha_trocada", usuario_id)


def senha_atual_confere(usuario_id: int, senha: str) -> bool:
    u = db.um("SELECT senha_hash FROM usuario WHERE id = %s", (usuario_id,))
    return bool(u) and confere(senha, u["senha_hash"])

auth = SimpleNamespace(MAX_TENTATIVAS=MAX_TENTATIVAS, MINUTOS_BLOQUEIO=MINUTOS_BLOQUEIO, PERFIS=PERFIS, gerar_hash=gerar_hash, confere=confere, problema_na_senha=problema_na_senha, senha_provisoria=senha_provisoria, normalizar_login=normalizar_login, registrar=registrar, existe_admin=existe_admin, autenticar=autenticar, recarregar=recarregar, criar_usuario=criar_usuario, login_existe=login_existe, definir_senha=definir_senha, senha_atual_confere=senha_atual_confere)


# ======================================================================
# ESTILO
# ======================================================================
NOME_APP = "Aprovar Concursos"
SUBTITULO = "CFS PMMS · Banco de questões comentadas"

CSS = """
<style>
:root{--verde:#4B5A23;--verde-claro:#E2E7D2;--ok:#1F6B3A;--ok-bg:#DCEFE1;--erro:#A3322A;--erro-bg:#F6DEDB;
      --lei:#F2F1E8;--linha:#D4D9CE;--texto-suave:#5B6559;--bronze:#8A6A1F}
.cartao{position:relative;border:1px solid var(--linha);border-radius:10px;padding:18px 20px;margin:4px 0 12px;
        background-repeat:repeat;background-size:320px 120px;-webkit-user-select:none;user-select:none}
.cartao .topo{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px;font-size:.82rem;color:var(--texto-suave);margin-bottom:8px}
.cartao .cod{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--verde);font-weight:600}
.cartao .enun{font-size:1.05rem;font-weight:500;line-height:1.55;margin:0}
.etq{display:inline-block;font-size:.72rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;border-radius:999px;padding:1px 8px;margin-left:6px}
.etq.lei{background:var(--verde-claro);color:var(--verde)} .etq.caso{background:#F5E8C8;color:#8A5A00}
.etq.rev{background:#E8E2F4;color:#4B3A7A}
.alt{border:1px solid var(--linha);border-radius:8px;padding:9px 12px;margin:6px 0;line-height:1.5}
.alt.certa{border-color:var(--ok);background:var(--ok-bg)} .alt.errada{border-color:var(--erro);background:var(--erro-bg)}
.alt .why{display:block;font-size:.88rem;color:var(--texto-suave);margin-top:4px}
.dica{background:var(--verde-claro);border-radius:6px;padding:8px 12px;margin:8px 0}
.lei-txt{background:var(--lei);border-radius:6px;padding:8px 12px;font-family:Georgia,'Times New Roman',serif;font-size:.93rem;margin:4px 0}
.lei-txt .ref{display:block;font-family:ui-monospace,Menlo,monospace;font-size:.72rem;color:var(--texto-suave)}
button[kind="primary"],button[kind="primaryFormSubmit"]{background:#4B5A23!important;border-color:#4B5A23!important;color:#fff!important}
.rotulo{font-size:.75rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--bronze);margin:10px 0 2px}
@media (prefers-color-scheme: dark){
 :root{--verde:#B5C77A;--verde-claro:#2A331C;--ok:#7FD39A;--ok-bg:#173222;--erro:#F19A90;--erro-bg:#3A1C19;--lei:#20261F;--linha:#2E372F;--texto-suave:#9AA597;--bronze:#D9B45E}
 .etq.caso{background:#352A12;color:#E8C26A} .etq.rev{background:#2B2540;color:#C9B8F2}}
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


# ======================================================================
# TELAS_ACESSO
# ======================================================================
LOGIN_OK = re.compile(r"^[a-z0-9._-]{3,30}$")


def _cabecalho():
    st.title(NOME_APP)
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


def tela_login():
    _cabecalho()
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
TIPOS = {"": "Lei seca e casos práticos", "lei_seca": "Só lei seca", "caso_pratico": "Só casos práticos"}
SITUACOES = {"todas": "Todas", "nao_respondidas": "Ainda não respondidas", "erradas": "Errei na última tentativa"}


def _chave(dicionario: dict, rotulo):
    """Devolve a chave a partir do rótulo exibido (ou None)."""
    return next((k for k, v in dicionario.items() if v == rotulo), None)


def status_visiveis(perfil: str, incluir_revisao: bool) -> list[str]:
    if perfil == "aluno":
        return ["aprovada"]
    return ["aprovada", "em_revisao"] if incluir_revisao else ["aprovada"]


def _assuntos(status: list[str]) -> list[dict]:
    return db.consultar(
        """SELECT a.id, a.nome, COUNT(DISTINCT q.id) AS n
           FROM assunto a JOIN questao_assunto qa ON qa.assunto_id = a.id
           JOIN questao q ON q.id = qa.questao_id
           WHERE q.status::text = ANY(%s)
           GROUP BY a.id, a.nome ORDER BY a.nome""",
        (status,),
    )


def _questoes(uid: int, status: list[str], assunto_id, tipo: str, situacao: str) -> list[dict]:
    return db.consultar(
        """SELECT q.id, q.codigo, q.tipo, q.dificuldade, q.enunciado, q.texto_apoio, q.comentario, q.dica,
                  q.status::text AS status,
                  (SELECT string_agg(a.nome, ' · ') FROM questao_assunto qa JOIN assunto a ON a.id = qa.assunto_id
                    WHERE qa.questao_id = q.id) AS assuntos
           FROM questao q
           WHERE q.status::text = ANY(%(st)s)
             AND (%(ass)s::int IS NULL OR EXISTS (SELECT 1 FROM questao_assunto qa WHERE qa.questao_id = q.id AND qa.assunto_id = %(ass)s))
             AND (%(tipo)s = '' OR q.tipo = %(tipo)s)
             AND (%(sit)s = 'todas'
                  OR (%(sit)s = 'nao_respondidas' AND NOT EXISTS (SELECT 1 FROM resposta r WHERE r.questao_id = q.id AND r.usuario_id = %(u)s))
                  OR (%(sit)s = 'erradas' AND (SELECT r.acertou FROM resposta r WHERE r.questao_id = q.id AND r.usuario_id = %(u)s
                                               ORDER BY r.respondida_em DESC LIMIT 1) = FALSE))
           ORDER BY q.codigo""",
        {"st": status, "ass": assunto_id, "tipo": tipo, "sit": situacao, "u": uid},
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


def tela_questoes(usuario: dict):
    st.header("Resolver questões")
    uid, perfil = usuario["id"], usuario["perfil"]

    c1, c2, c3 = st.columns([2, 1.3, 1.3])
    incluir = True
    if perfil != "aluno":
        incluir = st.toggle("Incluir questões ainda em revisão", value=True, key="f_rev",
                            help="Alunos só veem as questões aprovadas.")
    status = status_visiveis(perfil, incluir)
    assuntos = _assuntos(status)
    opcoes = {"Todos os assuntos": None} | {f"{a['nome']} ({a['n']})": a["id"] for a in assuntos}
    assunto_id = opcoes.get(c1.selectbox("Assunto", list(opcoes), key="f_ass"))
    tipo = _chave(TIPOS, c2.selectbox("Tipo", list(TIPOS.values()), key="f_tipo"))
    situacao = _chave(SITUACOES, c3.selectbox("Situação", list(SITUACOES.values()), key="f_sit"))

    filtro = (tuple(status), assunto_id, tipo, situacao)
    if st.session_state.get("filtro_ativo") != filtro:
        st.session_state["filtro_ativo"] = filtro
        st.session_state["q_idx"] = 0
        st.session_state["lista_q"] = _questoes(uid, status, assunto_id, tipo, situacao)
    lista = st.session_state["lista_q"]

    if not lista:
        st.info("Nenhuma questão com esses filtros. Troque o assunto, o tipo ou a situação.")
        return

    idx = min(st.session_state.get("q_idx", 0), len(lista) - 1)
    q = lista[idx]
    _navegacao(idx, len(lista), "topo")
    _questao(q, usuario)
    _navegacao(idx, len(lista), "base")


def _navegacao(idx: int, total: int, onde: str):
    a, b, c = st.columns([1, 2, 1])
    if a.button("◀ Anterior", disabled=idx == 0, width="stretch", key=f"ant_{onde}"):
        st.session_state["q_idx"] = idx - 1
        st.rerun()
    b.markdown(f"<div style='text-align:center;padding-top:6px'>Questão <b>{idx + 1}</b> de {total}</div>",
               unsafe_allow_html=True)
    if c.button("Próxima ▶", disabled=idx >= total - 1, width="stretch", key=f"prox_{onde}"):
        st.session_state["q_idx"] = idx + 1
        st.rerun()


def _questao(q: dict, usuario: dict):
    fundo = marca_dagua(usuario["nome"], usuario["login"])
    etq_tipo = '<span class="etq caso">Caso prático</span>' if q["tipo"] == "caso_pratico" else '<span class="etq lei">Lei seca</span>'
    etq_rev = '<span class="etq rev">Em revisão</span>' if q["status"] == "em_revisao" else ""
    apoio = f"<p>{esc(q['texto_apoio'])}</p>" if q["texto_apoio"] else ""
    st.markdown(
        f"""<div class="cartao">
              <div class="topo"><span><span class="cod">{esc(q['codigo'])}</span> · {esc(q['assuntos'])}</span>
              <span>{DIF.get(q['dificuldade'], '')}{etq_tipo}{etq_rev}</span></div>
              {apoio}<p class="enun">{esc(q['enunciado'])}</p></div>""",
        unsafe_allow_html=True,
    )

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
    if st.button("Refazer esta questão", key=f"refazer_{q['id']}"):
        respondidas.pop(q["id"], None)
        st.session_state.pop(f"radio_{q['id']}", None)
        st.rerun()
    if usuario["perfil"] in ("admin", "revisor"):
        _parecer(q, usuario)


def _correcao(q: dict, alts: list[dict], escolha_id: int, fundo: str):
    certa = next(a for a in alts if a["correta"])
    if escolha_id == certa["id"]:
        st.success(f"Você acertou. Gabarito: {certa['letra']}")
    else:
        marcada = next(a for a in alts if a["id"] == escolha_id)
        st.error(f"Você marcou {marcada['letra']}. Gabarito: {certa['letra']}")

    partes = []
    for a in alts:
        cls = "certa" if a["correta"] else ("errada" if a["id"] == escolha_id else "")
        partes.append(f'<div class="alt {cls}"><b>{a["letra"]})</b> {esc(a["texto"])}'
                      f'<span class="why">{esc(a["comentario"])}</span></div>')
    st.markdown(
        f"""<div class="cartao">{''.join(partes)}
            <div class="rotulo">Comentário</div><p>{esc(q['comentario'])}</p>
            <div class="dica"><b>Para memorizar:</b> {esc(q['dica'])}</div></div>""",
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
    return re.sub(r" \[L\d+\]$", "", referencia)


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
# TELAS_GESTAO
# ======================================================================
STATUS = {"em_revisao": "Em revisão", "aprovada": "Aprovada", "desatualizada": "Desatualizada",
          "anulada": "Anulada", "rascunho": "Rascunho"}


# ======================================================================= REVISÃO
def tela_revisao(usuario: dict):
    st.header("Revisão da equipe")
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
                   tipo=vis["tipo"].map({"lei_seca": "Lei seca", "caso_pratico": "Caso prático"}))
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
    tot = db.um("""SELECT COUNT(*) AS n, COALESCE(SUM(acertou::int), 0) AS ok, COUNT(DISTINCT questao_id) AS distintas
                   FROM resposta WHERE usuario_id = %s""", (uid,))
    if not tot["n"]:
        st.info("Você ainda não respondeu nenhuma questão. Vá em **Resolver questões** para começar.")
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("Respostas", tot["n"])
    c2.metric("Acertos", f"{100 * tot['ok'] / tot['n']:.0f}%")
    c3.metric("Questões diferentes", tot["distintas"])

    tipo = db.consultar(
        """SELECT CASE q.tipo WHEN 'caso_pratico' THEN 'Caso prático' ELSE 'Lei seca' END AS tipo,
                  COUNT(*) AS respostas, ROUND(100.0 * AVG(r.acertou::int), 0) AS pct
           FROM resposta r JOIN questao q ON q.id = r.questao_id WHERE r.usuario_id = %s GROUP BY 1 ORDER BY 1""", (uid,))
    st.subheader("Decorar ou aplicar?")
    st.caption("Compare seu acerto em lei seca (memória do texto) com casos práticos (aplicação da regra).")
    st.dataframe(pd.DataFrame(tipo).rename(columns={"tipo": "Tipo", "respostas": "Respostas", "pct": "% de acerto"}),
                 hide_index=True, width="stretch")

    ass = db.consultar(
        """SELECT a.nome AS assunto, COUNT(*) AS respostas, ROUND(100.0 * AVG(r.acertou::int), 0) AS pct
           FROM resposta r JOIN questao_assunto qa ON qa.questao_id = r.questao_id JOIN assunto a ON a.id = qa.assunto_id
           WHERE r.usuario_id = %s GROUP BY a.nome ORDER BY pct ASC, respostas DESC""", (uid,))
    st.subheader("Por assunto (do mais fraco para o mais forte)")
    df = pd.DataFrame(ass)
    st.bar_chart(df.set_index("assunto")["pct"], horizontal=True, y_label="", x_label="% de acerto")
    st.dataframe(df.rename(columns={"assunto": "Assunto", "respostas": "Respostas", "pct": "% de acerto"}),
                 hide_index=True, width="stretch")


# ======================================================================= USUÁRIOS (ADMIN)
def tela_usuarios(usuario: dict):
    st.header("Usuários")
    st.caption("Só entra no app quem você cadastrar aqui. A senha provisória aparece uma única vez: envie em particular.")

    with st.form("novo_usuario", clear_on_submit=True):
        st.markdown("**Cadastrar pessoa**")
        c1, c2, c3 = st.columns([2, 1.5, 1])
        nome = c1.text_input("Nome (ex.: Cb PM Lozo)", key="nu_nome")
        login = c2.text_input("Usuário (ex.: lozo)", key="nu_login")
        perfil = _chave(auth.PERFIS, c3.selectbox("Perfil", list(auth.PERFIS.values()), index=1, key="nu_perfil"))
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
            st.session_state["senha_mostrar"] = (nome.strip(), login_n, senha)
    _mostrar_senha()

    contas = db.consultar(
        """SELECT id, nome, login, perfil, ativo, ultimo_acesso,
                  (bloqueado_ate IS NOT NULL AND bloqueado_ate > now()) AS bloqueado,
                  (SELECT COUNT(*) FROM resposta r WHERE r.usuario_id = u.id) AS respostas,
                  (SELECT COUNT(*) FROM parecer p WHERE p.usuario_id = u.id) AS pareceres
           FROM usuario u WHERE login IS NOT NULL ORDER BY ativo DESC, nome""")
    df = pd.DataFrame(contas)
    st.dataframe(
        df.assign(perfil=df["perfil"].map(auth.PERFIS),
                  ativo=df["ativo"].map({True: "Ativo", False: "Desativado"}),
                  bloqueado=df["bloqueado"].map({True: "Bloqueado", False: ""}),
                  ultimo_acesso=df["ultimo_acesso"].apply(lambda d: f"{d:%d/%m/%Y %H:%M}" if pd.notna(d) else "nunca"))
          [["nome", "login", "perfil", "ativo", "bloqueado", "ultimo_acesso", "respostas", "pareceres"]]
          .rename(columns={"nome": "Nome", "login": "Usuário", "perfil": "Perfil", "ativo": "Situação",
                           "bloqueado": "Bloqueio", "ultimo_acesso": "Último acesso", "respostas": "Respostas",
                           "pareceres": "Pareceres"}),
        hide_index=True, width="stretch")

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


# ======================================================================= MINHA CONTA
def tela_conta(usuario: dict):
    st.header("Minha conta")
    st.write(f"**{usuario['nome']}** · usuário `{usuario['login']}` · {auth.PERFIS[usuario['perfil']]}")
    st.subheader("Trocar senha")
    tela_trocar_senha(usuario, obrigatoria=False)


# ======================================================================
# APP
# ======================================================================
st.set_page_config(page_title=NOME_APP, page_icon="📘", layout="centered")
aplicar()

# 1) Ainda não há administrador: só mostra a criação dele.
if not auth.existe_admin():
    tela_primeiro_acesso()
    st.stop()

# 2) Sem login: tela de entrada.
sessao = st.session_state.get("usuario")
if not sessao:
    tela_login()
    st.stop()

# 3) A cada clique, confere se a conta ainda está ativa (desativar corta o acesso na hora).
usuario = auth.recarregar(sessao["id"])
if usuario is None:
    st.session_state.clear()
    st.error("Seu acesso foi encerrado. Fale com o administrador.")
    st.stop()
st.session_state["usuario"] = usuario

# 4) Senha provisória: obriga a trocar antes de qualquer coisa.
if usuario["trocar_senha"]:
    tela_trocar_senha(usuario, obrigatoria=True)
    st.stop()

# 5) Marca d'água com o nome de quem está logado, em toda a tela.
aplicar_marca_dagua(usuario["nome"], usuario["login"])

# 6) Menu conforme o perfil.
TELAS = {"Resolver questões": tela_questoes, "Meu desempenho": tela_desempenho}
if usuario["perfil"] in ("admin", "revisor"):
    TELAS["Revisão da equipe"] = tela_revisao
if usuario["perfil"] == "admin":
    TELAS["Usuários"] = tela_usuarios
TELAS["Minha conta"] = tela_conta

with st.sidebar:
    st.markdown(f"### {NOME_APP}")
    st.caption(SUBTITULO)
    st.write(f"👤 **{usuario['nome']}**  \n{auth.PERFIS[usuario['perfil']]}")
    escolha = st.radio("Menu", list(TELAS), key="menu", label_visibility="collapsed")
    if st.button("Sair", width="stretch"):
        auth.registrar("logout", usuario["id"])
        st.session_state.clear()
        st.rerun()

TELAS[escolha](usuario)