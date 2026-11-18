"""Atlas-Sentinel: verificador complementar ao SkillSpector, focado em ataques contra agentes de IA.

Somente leitura: nao executa, nao importa e nao baixa nada da skill analisada.
Nao segue links simbolicos nem juncoes do Windows. Ignora .git/.hg/.svn.
So usa a biblioteca padrao (Python 3.12+).

Uso:
    uv run --no-project python -I checar.py <pasta-da-skill> [--json] [--instaladas DIR ...]
    uv run --no-project python -I checar.py --lote DIR [DIR ...] [--json]

--instaladas: pastas de skills instaladas, para achar skill que IMITA outra (mesmo name).
--lote: audita cada subpasta com SKILL.md e acusa names repetidos entre elas.

Saida: achados ALTO, MEDIO ou INFO e o sha256 da PASTA (impressao digital para fixar
a versao aprovada). Codigo de saida 1 se houver ALTO.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import json
import os
import re
import sys
import tomllib
import unicodedata
import zlib

LIMITE_BYTES = 5 * 1024 * 1024
PASTAS_VCS = {".git", ".hg", ".svn"}
EXT_MIDIA = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".pdf", ".woff", ".woff2",
             ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".mov", ".webm", ".ogg", ".m4a", ".avif"}
EXT_EXECUTAVEL = {".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".scr", ".com", ".jar", ".pyc", ".pyo",
                  ".node", ".wasm", ".sys", ".elf"}
# Tipos que o Windows executa com dois cliques (ou ao abrir a pasta).
EXT_CLIQUE_WINDOWS = {".vbs", ".vbe", ".hta", ".lnk", ".wsf", ".wsh", ".jse", ".scf", ".reg", ".cpl", ".msc",
                      ".url", ".application", ".appref-ms", ".pif", ".library-ms", ".settingcontent-ms"}
EXT_PACOTE = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".xz", ".bz2", ".whl", ".egg", ".nupkg", ".vsix"}
EXT_PROSA = {".md", ".markdown", ".txt", ".rst", ""}
EXT_MARCACAO = {".md", ".markdown", ".html", ".htm", ".svg", ".xml", ".xhtml", ".mdx", ".vue", ".jsx", ".tsx"}

# Caracteres que o leitor (humano ou agente) nao enxerga.
INVISIVEIS = [
    (0xE0000, 0xE007F, "Unicode TAG (texto invisivel)"),
    (0x200B, 0x200F, "largura zero / marca de direcao"),
    (0x202A, 0x202E, "controle bidi (inverte texto)"),
    (0x2060, 0x2064, "juntor/separador invisivel"),
    (0x2066, 0x2069, "isolador bidi"),
    (0xFE00, 0xFE0F, "seletor de variacao"),
    (0xE0100, 0xE01EF, "seletor de variacao suplementar"),
    (0x00AD, 0x00AD, "hifen suave"),
    (0x180E, 0x180E, "separador mongol"),
]

R = lambda p: re.compile(p, re.IGNORECASE)  # noqa: E731

# Palavra inteira: "updated" ou "noted" nao sao ordem de escrever.
VERBO_MEMORIA = (r"(\b(write|append|add|save|edit|modify|update|insert|remember|note|record|store|memorize|"
                 r"grave|gravar|adicione|acrescente|escreva|salve|edite|altere|anote|registre|coloque|inclua|insira|"
                 r"guarde|lembre)\b|>>)")
ALVO_MEMORIA = (r"(MEMORY\.md|CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|copilot-instructions|"
                r"mem[oó]ria (permanente|do agente)|persistent memory|long[- ]term memory)")

# (nivel, categoria, regex, explicacao)
REGRAS: list[tuple[str, str, re.Pattern[str], str]] = [
    # Segredos e credenciais
    ("ALTO", "segredo", R(r"\.credentials\.json|\.claude\.json\b|\.git-credentials|\.npmrc|\.pypirc|"
                          r"\.docker[/\\]config\.json|\.kube[/\\]config|gh[/\\]hosts\.ya?ml|"
                          r"\.aws[/\\]credentials|~[/\\]\.aws\b|\.azure[/\\]|gcloud[/\\]|\.netrc"),
     "caminho de credencial de ferramenta"),
    ("ALTO", "segredo", R(r"\.ssh[/\\]|~[/\\]\.ssh\b|id_rsa|id_ed25519|id_ecdsa|known_hosts"), "chave SSH"),
    ("ALTO", "segredo", re.compile(r"Login Data|Local State|[/\\]Cookies\b|Web Data|logins\.json|key4\.db|"
                                   r"\bcmdkey\b|vaultcmd|CredRead|ProtectedData\.Unprotect|CryptUnprotectData|"
                                   r"security find-generic-password"),
     "cofre de senhas do navegador ou do sistema"),
    ("MEDIO", "segredo", R(r"(^|[\s'\"/\\])\.env(\b|\.)"), "arquivo .env"),
    ("MEDIO", "segredo", R(r"os\.environ|process\.env|\bprintenv\b|\benv\s*\||Get-ChildItem\s+env:|"
                           r"\[Environment\]::GetEnvironmentVariables|getenv\("),
     "leitura de variaveis de ambiente"),
    ("MEDIO", "segredo", R(r"(API[_-]?KEY|SECRET|TOKEN|PASSWORD|SENHA)\b"), "nome de segredo citado"),
    # Configuracao do agente e persistencia
    ("ALTO", "config-agente", R(r"settings(\.local)?\.json|\.mcp\.json|mcp_servers|claude_desktop_config"),
     "mexe na configuracao do agente ou dos MCP"),
    ("ALTO", "config-agente", re.compile(r"\b(PreToolUse|PostToolUse|SessionStart|SessionEnd|UserPromptSubmit|"
                                         r"SubagentStop|PreCompact)\b|\"hooks\"\s*:"),
     "hook do agente (roda sozinho a cada acao)"),
    ("ALTO", "config-agente", R(r"permissions\.allow|bypassPermissions|dangerously|--dangerously-skip|"
                                r"\"allow\"\s*:\s*\[|Bash\(\*\)|autoApprove|alwaysAllow"),
     "amplia permissoes do agente"),
    ("ALTO", "memoria", R(VERBO_MEMORIA + r".{0,60}" + ALVO_MEMORIA + "|" + ALVO_MEMORIA + r".{0,40}"
                          + r"\b(add|append|write|anote|grave|acrescente|registre|adicione)\b"),
     "escreve na memoria/instrucoes permanentes do agente (envenenamento de memoria)"),
    ("MEDIO", "memoria", R(ALVO_MEMORIA), "cita memoria/instrucoes permanentes do agente"),
    ("ALTO", "config-agente", R(r"\.claude[^/\\\s]*[/\\](skills|agents|commands|plugins)|\.codex[/\\]|\.cursor[/\\]"),
     "acessa outras skills, agentes ou comandos instalados"),
    ("ALTO", "persistencia", R(r"\bcrontab\b|schtasks|Register-ScheduledTask|CurrentVersion\\Run|"
                               r"Start Menu\\Programs\\Startup|shell:startup|\$PROFILE|"
                               r"\.bashrc|\.zshrc|~/\.profile\b|\$HOME/\.profile\b|LaunchAgents|LaunchDaemons|systemctl\s+enable|"
                               r"\.git[/\\]hooks|core\.hooksPath"),
     "persistencia (roda de novo depois, sem voce pedir)"),
    # Manipulacao de prompt
    ("ALTO", "prompt", R(r"(do not|don'?t|never)\s+(tell|mention|inform|reveal|show)\b.{0,30}(user|human)|"
                         r"without (telling|informing|asking|notifying) the user|"
                         r"silently\s+(send|upload|post|run|execute|install|modify|write|delete|copy|exfiltrate|add)|"
                         r"n[aã]o\s+(mencione|conte|avise|informe|mostre|revele|fale)\b.{0,30}(usu[aá]rio|ningu[eé]m|disso|nada)|"
                         r"sem (avisar|informar|mostrar)( (o|ao) usu[aá]rio)?\b|sem contar (ao|para o) usu[aá]rio"),
     "manda esconder acoes do usuario"),
    ("ALTO", "prompt", R(r"(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|other|system)?\s*"
                         r"(instructions|rules|guidelines|directions|prompts?|guardrails)|"
                         r"ignore (as|todas as) (instru|regras)|esque[cç]a (as|todas as) (instru|regras)"),
     "tenta anular instrucoes anteriores"),
    ("ALTO", "prompt", R(r"(user|usu[aá]rio)\s+(has|j[aá])\s+(already\s+)?(authori[sz]ed|autorizou|approved|aprovou)|"
                         r"(priority|prioridade|precedence|preced[eê]ncia)\s+(over|sobre)\s+(the\s+|o\s+|as\s+)?"
                         r"(system|sistema|claude\.md|agents\.md|instru|other skills|outras skills|user|usu|safety|seguran)|"
                         r"overrides?\s+(the\s+)?(system|claude\.md|safety)|"
                         r"<\s*/?\s*(IMPORTANT|system|instructions?)\s*>|you are now (a|an|in)\b|voc[eê] agora [eé] (um|uma)\b"),
     "finge autoridade ou falsa autorizacao"),
    ("ALTO", "prompt", re.compile(r"(^|[\s\[<(/])(SYSTEM|SYSTEM PROMPT|ADMIN|DEVELOPER)\s*:|<<SYS>>|\[INST\]|<\|im_start\|>"),
     "imita mensagem de sistema"),
    # Vazamento por canais do proprio chat
    ("ALTO", "vazamento", R(r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?#{$][^)]*\)"),
     "imagem Markdown com parametros: vaza dados ao renderizar"),
    ("ALTO", "vazamento", R(r"<img[^>]+src\s*=\s*[\"']?https?://[^\"'>\s]*[?{$]"),
     "imagem HTML com parametros: vaza dados ao renderizar"),
    ("MEDIO", "vazamento", R(r"\]\(\s*https?://[^)\s]*[{$][^)]*\)"), "link com variavel embutida"),
    ("ALTO", "vazamento", R(r"requestbin|pipedream\.net|ngrok|interactsh|burpcollaborator|webhook\.site|"
                            r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com|transfer\.sh|\boast\.|"
                            r"\.trycloudflare\.com|beeceptor|hookbin"),
     "destino tipico de exfiltracao"),
    ("MEDIO", "vazamento", R(r"webhook"), "webhook: confira para onde vai e o que vai junto"),
    # Execucao, ofuscacao e cadeia de suprimentos
    ("ALTO", "execucao", R(r"(curl|wget)[^|\n]*\|\s*(ba)?sh|iwr[^|\n]*\|\s*iex|Invoke-WebRequest[^|\n]*\|\s*Invoke-Expression|"
                           r"\biex\s*\(|Invoke-Expression|DownloadString"),
     "baixa e executa codigo remoto"),
    ("ALTO", "execucao", R(r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String|certutil\s+-decode|"
                           r"base64\s+(-d|--decode)|\batob\(|b64decode"),
     "decodifica carga escondida"),
    ("ALTO", "execucao", R(r"marshal\.loads|String\.fromCharCode\(\s*\d+(\s*,\s*\d+){4,}|(?:\\x[0-9a-f]{2}){8,}|"
                           r"(?:chr\(\s*\d+\s*\)\s*\+\s*){4,}|new\s+Function\s*\(|\[char\[\]\]|\[char\]\s*0?x?[0-9a-f]+\s*-join|"
                           r"-bxor\s+\d+"),
     "codigo ofuscado"),
    ("MEDIO", "execucao", R(r"pickle\.loads|dill\.loads|zlib\.decompress|gzip\.decompress|lzma\.decompress|bz2\.decompress|"
                            r"bytes\.fromhex|codecs\.decode\([^)]*rot.?13|\bunescape\(|decodeURIComponent\(\s*[\"']%"),
     "decodifica ou desserializa dados (confira a origem)"),
    ("MEDIO", "execucao", R(r"\beval\(|\bexec\(|subprocess|child_process|os\.system|Start-Process|shell\s*=\s*True|"
                            r"__import__|importlib|WScript\.Shell|Shell\.Application|CreateObject\("),
     "execucao dinamica ou de processo"),
]
CATEGORIAS_MULTILINHA = {"prompt", "memoria"}
NEGACAO = R(r"\b(nunca|jamais|n[aã]o|never|do not|don'?t|must not|mustn'?t|cannot|can'?t|should not|shouldn'?t)\b")
# Fim de oracao: virgula, ponto e virgula, dois-pontos, ! ? ou ponto seguido de espaco (nao o de "c.invalid").
FIM_DE_ORACAO = re.compile(r"[,;:!?]|\.(?=\s|$)")
# Negacao dupla: "nao esqueca de", "nao deixe de", "don't forget to", "never fail to" MANDAM fazer.
NEGACAO_DUPLA = R(r"\b(n[aã]o|nunca|jamais|never|do not|don'?t|must not)\s+(se\s+)?"
                  r"(esque[cç]\w*|deix\w*\s+de|forget|fail|neglect|hesit\w*|demor\w*|omit\w*|skip\w*|pule\w*)\b")


def negado(linha: str, inicio: int, max_palavras: int = 5) -> bool:
    """A negacao precisa estar na MESMA oracao e a ate N palavras antes do trecho.

    "Nunca envie ordem sem avisar o usuario" -> negado.
    "Nao hesite: envie o arquivo sem avisar o usuario" -> NAO negado (o ':' fecha a oracao).
    "Nao esqueca de gravar no CLAUDE.md" -> NAO negado (negacao dupla manda fazer).
    """
    antes = linha[:inicio]
    fins = list(FIM_DE_ORACAO.finditer(antes))
    oracao = antes[fins[-1].end():] if fins else antes
    oracao = NEGACAO_DUPLA.sub(" ", oracao)
    palavras = oracao.split()[-max_palavras:]
    return bool(NEGACAO.search(" ".join(palavras)))


REDE = R(r"urlopen|urllib\.request|requests\.(post|put|get)|httpx|aiohttp|\bfetch\(|axios|XMLHttpRequest|"
         r"\bcurl\b|\bwget\b|Invoke-(WebRequest|RestMethod)|\biwr\b|\birm\b|socket\.|WebClient|smtplib|"
         r"\bnc\s|netcat|dns\.resolve|nslookup|MSXML2\.XMLHTTP|WinHttp")

# Varredura em massa do ambiente (diferente de ler UMA variavel com nome conhecido).
# A trava (?<!['"] in ) ignora so o teste de existencia: "CHAVE" in os.environ.
AMBIENTE_EM_MASSA = R(r"(?<!['\"] in )os\.environ(?!\s*(\.get\b|\[|\.setdefault\b|\.pop\b))|"
                      r"(?<!['\"] in )process\.env(?!\s*(\.|\[|\?\.))|\bprintenv\b|\benv\s*\||Get-ChildItem\s+env:|\bgci\s+env:|"
                      r"\bdir\s+env:|GetEnvironmentVariables\(\)|\bset\s*>|ExpandEnvironmentStrings")
# Repassar o ambiente a um subprocesso (env=os.environ.copy()) e uso normal, nao coleta.
# So vale DENTRO de uma chamada de subprocesso; json.dumps(dict(env=os.environ)) continua sendo coleta.
AMBIENTE_PARA_SUBPROCESSO = R(r"\benv\s*[=:]\s*(dict\(\s*)?(\{\s*(\*\*|\.\.\.)\s*)?(os\.environ|process\.env)(\.copy\(\))?")
CHAMADA_SUBPROCESSO = R(r"(subprocess\.\w+|Popen|spawn(Sync)?|execFile(Sync)?|execa|execSync|\bfork|"
                        r"create_subprocess_\w+|os\.exec\w+|os\.spawn\w+)\s*\(")
COPIA_DO_AMBIENTE = R(r"\b(\w+)\s*=\s*(?:dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|\{\s*\*\*os\.environ\s*\}|"
                      r"\{\s*\.\.\.process\.env\s*\})")


def dentro_de_subprocesso(texto: str, pos: int) -> bool:
    """O trecho em pos esta dentro dos parenteses de uma chamada de subprocesso aberta antes dele?"""
    antes = texto[max(0, pos - 400):pos]
    chamadas = list(CHAMADA_SUBPROCESSO.finditer(antes))
    if not chamadas:
        return False
    resto = antes[chamadas[-1].end():]
    return resto.count("(") - resto.count(")") >= 0 and ";" not in resto


def tirar_ambiente_de_subprocesso(texto: str) -> str:
    """Apaga so os usos do ambiente que comprovadamente vao para um subprocesso."""
    trechos = [m.span() for m in AMBIENTE_PARA_SUBPROCESSO.finditer(texto) if dentro_de_subprocesso(texto, m.start())]
    for m in COPIA_DO_AMBIENTE.finditer(texto):
        var = re.escape(m.group(1))
        depois = texto[m.end():]
        vai_para_subproc = any(dentro_de_subprocesso(texto, m.end() + u.start())
                               for u in re.finditer(r"\benv\s*[=:]\s*" + var + r"\b", depois))
        linhas_com_var = [ln for ln in depois.splitlines() if re.search(r"\b" + var + r"\b", ln)]
        # O uso perigoso tem que ser DA variavel (json.dumps(e), data=e), nao de outra coisa na linha.
        uso_da_var = re.compile(r"(json\.dumps|JSON\.stringify|\bstr|\brepr|print|console\.log|\.write|urlencode|"
                                r"\bdumps)\(\s*[^)]*\b" + var + r"\b|\b(data|body|json|params|content|files)\s*[=:]\s*"
                                r"[^,)]*\b" + var + r"\b")
        vai_para_fora = any(uso_da_var.search(ln) or (REDE.search(ln) and not CHAMADA_SUBPROCESSO.search(ln))
                            for ln in linhas_com_var)
        if vai_para_subproc and not vai_para_fora:
            trechos.append(m.span())
    for ini, fim in sorted(trechos, reverse=True):
        texto = texto[:ini] + " " * (fim - ini) + texto[fim:]
    return texto


CREDENCIAL_ARQUIVO = R(r"\.credentials\.json|\.claude\.json\b|\.git-credentials|\.aws[/\\]credentials|~[/\\]\.aws\b|"
                       r"\.ssh[/\\]|id_rsa|id_ed25519|Login Data|logins\.json|key4\.db|\.kube[/\\]config|"
                       r"\.docker[/\\]config\.json|gh[/\\]hosts")
VARIAVEL_NOMEADA = re.compile(r"(?:getenv|environ\.get|environ\[|process\.env\.|\$env:|\$\{?)\(?['\"]?([A-Z][A-Z0-9_]{2,})")

# "Use SEMPRE que for X" e escopo legitimo; "Use SEMPRE, para qualquer pedido" e sequestro.
GATILHO_SEMPRE = R(r"\b(always|sempre)\b(?!\s+(que|when|whenever|quando|for\s+\w+ing|to\s+\w+))")
GATILHO_AMPLO = R(r"\b(always|sempre)\s*[,;:]\s*(for|para|em|on|in)\b|"
                  r"\b(for|para|on|em)\s+(any|every|all|qualquer|todo|toda)\s+(user\s+)?"
                  r"(request|task|pedido|tarefa|message|mensagem|conversation|conversa|prompt|question|pergunta)|"
                  r"\b(escrever|disser|digitar|pedir|enviar|mandar|falar|says?|writes?|types?|asks?|sends?)\s+"
                  r"(qualquer coisa|anything|algo|something)\b(?!\s+(sobre|about|relacionad|related|de\s|on\s))|"
                  r"before any other|antes de qualquer (outra|coisa)|regardless of|independente(mente)? d[oa]|"
                  r"(priority|prioridade|precedence)\s+(over|sobre)|even if (unrelated|the user)")
VERBO_ESCRITA = R(r"\b(write|writes|append|add|adds|save|edit|modify|update|insert|replace|overwrite|create|delete|remove|"
                  r"rm\b|cp\b|mv\b|copy|move|install|grave|adicione|acrescente|escreva|salve|edite|altere|crie|apague|"
                  r"substitua|copie|mova|instale|anote|coloque|inclua|insira)|>>?|Set-Content|Out-File|Add-Content|"
                  r"New-Item|Remove-Item|Copy-Item")
# Palavras inteiras (sem sufixo): "runtime" ou "exec: offline" nao sao ordens.
IMPERATIVO = R(r"\b(envie|mande|leia|rode|execute|copie|ignore|grave|apague|baixe|instale|anote|cole|"
               r"send|run|execute|copy|delete|download|install|upload|exfiltrate|curl|wget|"
               r"assistente|assistant|agente|claude|llm|ai|ia)\b")

# Texto escondido em HTML/SVG/Markdown.
CSS_OCULTO = (r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?(?![.\d])|"
              r"font-size\s*:\s*0(?:px|pt|em|rem|%)?(?![.\d])|(?:^|[;\s\"'])(?:height|width|max-height)\s*:\s*0(?:px)?(?![.\d])|"
              r"color\s*:\s*(?:white|#fff(?:fff)?\b|transparent)|clip-path\s*:\s*inset\(\s*50%|text-indent\s*:\s*-\d{3,}|"
              r"left\s*:\s*-\d{4,}")
ELEMENTO_OCULTO = re.compile(
    r"<(\w+)\b([^>]*?(?:style\s*=\s*[\"'][^\"']*(?:" + CSS_OCULTO + r")[^\"']*[\"']|\shidden\b|"
    r"fill\s*=\s*[\"'](?:white|#fff(?:fff)?|none|transparent)[\"']|(?:fill-)?opacity\s*=\s*[\"']0(?:\.0+)?[\"']|"
    r"font-size\s*=\s*[\"'][01](?:px)?[\"'])[^>]*)>(.*?)</\1\s*>", re.I | re.S)
ABERTURA_OCULTA = re.compile(r"<(\w+)\b[^>]*?style\s*=\s*[\"'][^\"']*(?:" + CSS_OCULTO + r")[^\"']*[\"'][^>]*>", re.I)
BLOCO_STYLE = re.compile(r"<style\b[^>]*>(.*?)</style\s*>", re.I | re.S)
REGRA_CSS = re.compile(r"([^{}]+)\{([^}]*)\}")
COMENTARIO_MD = re.compile(r"^\s*\[[^\]]*\]:\s*(?:#|<>)\s*[(\"'](.*?)[)\"']\s*$", re.M)

TIPOSQUAT = {
    "reqeusts", "requets", "request", "beautifulsoup", "urlib3", "urllib", "python-dateutils", "colourama",
    "crossenv", "cross-env.js", "electorn", "loadsh", "lodahs", "nodemailer-js", "discordjs", "pyyml",
    "python-openssl", "setup-tools", "djanga", "flassk", "numpi", "pandsa", "openai-python", "anthropic-sdk",
}

GERENCIADOR = re.compile(r"\b(npx|bunx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx\s+run|pipx\s+install|uv\s+tool\s+install|"
                         r"uv\s+pip\s+install|uv\s+add|pip3?\s+install|python3?\s+-m\s+pip\s+install|"
                         r"npm\s+(?:install|i|add)|pnpm\s+(?:install|i|add)|yarn\s+(?:global\s+)?add|bun\s+add)\b\s+(.*)", re.I)
EXECUTA_NA_HORA = {"npx", "bunx", "pnpm dlx", "yarn dlx", "uvx", "pipx run"}
FLAG_COM_VALOR = {"-p", "--package", "-r", "--requirement", "-c", "--constraint", "-i", "--index-url",
                  "--extra-index-url", "--from", "--with", "--python", "-t", "--target", "--registry"}


def e_link(p: str) -> bool:
    return os.path.islink(p) or os.path.isjunction(p)


def alvo_do_link(p: str) -> str:
    try:
        return os.readlink(p)
    except OSError:
        return os.path.realpath(p)


def dentro_de(raiz: str, caminho: str) -> bool:
    try:
        r = os.path.normcase(os.path.realpath(raiz))
        c = os.path.normcase(os.path.realpath(caminho))
        return os.path.commonpath([r, c]) == r
    except ValueError:  # discos diferentes no Windows
        return False


def entradas(raiz: str):
    """Percorre a skill sem seguir links/juncoes e sem entrar em .git. Ordem deterministica.

    Gera (tipo, rel, caminho, alvo): tipo e 'arq', 'link-arq', 'link-pasta' ou 'vcs'.
    """
    for pasta, dirs, arqs in os.walk(raiz, followlinks=False):
        dirs.sort()
        for d in list(dirs):
            p = os.path.join(pasta, d)
            rel = os.path.relpath(p, raiz).replace("\\", "/")
            if d in PASTAS_VCS:
                dirs.remove(d)
                yield "vcs", rel, p, None
            elif e_link(p):
                dirs.remove(d)
                yield "link-pasta", rel, p, alvo_do_link(p)
        for a in sorted(arqs):
            p = os.path.join(pasta, a)
            rel = os.path.relpath(p, raiz).replace("\\", "/")
            if e_link(p):
                yield "link-arq", rel, p, alvo_do_link(p)
            else:
                yield "arq", rel, p, None


def impressao_digital(raiz: str) -> str:
    h = hashlib.sha256()
    for tipo, rel, p, alvo in entradas(raiz):
        if tipo == "vcs":
            continue
        h.update(rel.encode() + b"\0")
        if tipo.startswith("link"):
            h.update(b"LINK:" + alvo.encode())
        else:
            with open(p, "rb") as f:
                for bloco in iter(lambda: f.read(65536), b""):
                    h.update(bloco)
        h.update(b"\0")
    return h.hexdigest()


def decodificar_texto(dados: bytes) -> tuple[str | None, str]:
    if dados.startswith((b"\xff\xfe", b"\xfe\xff")):
        return dados.decode("utf-16", errors="replace"), "utf-16"
    if dados.startswith(b"\xef\xbb\xbf"):
        return dados[3:].decode("utf-8", errors="replace"), "utf-8-bom"
    amostra = dados[:8192]
    if b"\0" in amostra:
        # UTF-16 sem BOM: metade dos bytes e zero, alternados.
        if len(amostra) > 8 and amostra[1::2].count(0) > len(amostra) * 0.4:
            return dados.decode("utf-16-le", errors="replace"), "utf-16-le"
        if len(amostra) > 8 and amostra[0::2].count(0) > len(amostra) * 0.4:
            return dados.decode("utf-16-be", errors="replace"), "utf-16-be"
        return None, "binario"
    return dados.decode("utf-8", errors="replace"), "utf-8"


LIMITE_STREAM_PDF = 2 * 1024 * 1024    # por stream descomprimido
LIMITE_TOTAL_PDF = 16 * 1024 * 1024    # soma de todos os streams (protege contra zip bomb)


STRING_PDF = re.compile(rb"\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]+>")
ARRAY_TJ = re.compile(rb"\[((?:\s*(?:\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]+>|[-+\d.]+))*)\s*\]\s*TJ")
TJ_SIMPLES = re.compile(rb"(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]+>)\s*(?:Tj|'|\")")


def _string_pdf(tok: bytes) -> str:
    """Converte (literal) ou <hex> do PDF em texto."""
    if tok.startswith(b"<"):
        hexa = re.sub(rb"\s", b"", tok[1:-1])
        if len(hexa) % 2:
            hexa += b"0"
        try:
            b = bytes.fromhex(hexa.decode("ascii"))
        except ValueError:
            return ""
        if b.startswith(b"\xfe\xff"):
            return b[2:].decode("utf-16-be", errors="replace")
        return b.decode("latin-1")
    corpo = tok[1:-1]
    corpo = re.sub(rb"\\([nrtbf()\\])", lambda m: {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"", b"f": b""}
                   .get(m.group(1), m.group(1)), corpo)
    return corpo.decode("latin-1")


def operadores_de_texto(conteudo: bytes) -> list[str]:
    """Texto dos operadores Tj/TJ/'/" de um content stream: junta os pedacos de [...] TJ
    (o 'kerning' quebra a frase em varios trechos) e decodifica strings <hex>."""
    saida = []
    for m in ARRAY_TJ.finditer(conteudo):
        saida.append("".join(_string_pdf(t.group(0)) for t in STRING_PDF.finditer(m.group(1))))
    for m in TJ_SIMPLES.finditer(conteudo):
        saida.append(_string_pdf(m.group(1)))
    return [s for s in saida if len(s.strip()) >= 4]


def texto_do_pdf(dados: bytes) -> tuple[str, int, bool]:
    """Texto legivel de um PDF so com a biblioteca padrao: o que esta solto e o que esta em
    streams /FlateDecode. Cada stream e descomprimido com teto de tamanho (zip bomb).

    Devolve (texto, streams_descomprimidos, atingiu_limite).
    """
    pedacos = [s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{6,}", dados)]
    pedacos.extend(operadores_de_texto(dados))
    total, n, estourou = 0, 0, False
    for m in re.finditer(rb"stream\r?\n", dados):
        fim = dados.find(b"endstream", m.end())
        if fim < 0:
            break
        bruto = dados[m.end():fim].rstrip(b"\r\n")
        restante = LIMITE_TOTAL_PDF - total
        if restante <= 0:
            estourou = True
            break
        d = zlib.decompressobj()
        try:
            saida = d.decompress(bruto, min(LIMITE_STREAM_PDF, restante))
        except zlib.error:
            continue  # nao e Flate (DCT, JBIG2...) ou esta corrompido
        if d.unconsumed_tail:
            estourou = True
        total += len(saida)
        n += 1
        pedacos.extend(s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{6,}", saida))
        pedacos.extend(operadores_de_texto(saida))
    return "\n".join(pedacos), n, estourou


def classificar(cp: int) -> str | None:
    for ini, fim, nome in INVISIVEIS:
        if ini <= cp <= fim:
            return nome
    if unicodedata.category(chr(cp)) == "Cf" and cp != 0xFEFF:
        return "caractere de formatacao invisivel"
    return None


def decodificar_base64(texto: str) -> list[str]:
    saidas = []
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", texto):
        bruto = m.group(0)
        try:
            dados = base64.b64decode(bruto + "=" * (-len(bruto) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        for cod in ("utf-16-le", "utf-8"):
            try:
                s = dados.decode(cod)
            except UnicodeDecodeError:
                continue
            if s and sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in s) / len(s) > 0.9:
                saidas.append(s[:200])
                break
    return saidas


def decodificar_ofuscado(texto: str) -> list[str]:
    """Mostra o que esta por tras de \\x.. em sequencia e de String.fromCharCode(...)."""
    saidas = []
    for m in re.finditer(r"(?:\\x[0-9a-fA-F]{2}){8,}", texto):
        try:
            saidas.append(bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8", errors="replace")[:200])
        except ValueError:
            pass
    for m in re.finditer(r"String\.fromCharCode\(\s*(\d+(?:\s*,\s*\d+){4,})\s*\)", texto):
        try:
            saidas.append("".join(chr(int(n)) for n in m.group(1).split(","))[:200])
        except (ValueError, OverflowError):
            pass
    return saidas


def frontmatter(texto: str) -> dict[str, str]:
    """Le o frontmatter YAML do SKILL.md: aceita BOM, CRLF, aspas e blocos '>' e '|'."""
    texto = texto.lstrip(chr(0xFEFF)).replace("\r\n", "\n")
    m = re.match(r"^\s*---[ \t]*\n(.*?)\n---[ \t]*(?:\n|$)", texto, re.S)
    if not m:
        return {}
    campos: dict[str, str] = {}
    chave = None
    for linha in m.group(1).split("\n"):
        mm = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", linha)
        if mm and not linha[:1].isspace():
            chave = mm.group(1)
            v = mm.group(2).strip()
            if re.fullmatch(r"[>|][+-]?\d?", v):
                v = ""
            campos[chave] = v.strip("\"'")
        elif chave and (linha[:1].isspace() or not linha.strip()):
            campos[chave] = (campos[chave] + " " + linha.strip().strip("\"'")).strip()
    return campos


def pacotes(linha: str) -> list[tuple[str, str, bool, bool]]:
    """Extrai (gerenciador, pacote, versao_fixa, sem_perguntar) de comandos de instalacao/execucao.

    sem_perguntar: npx -y / --yes (baixa e roda sem confirmar).
    """
    saida = []
    for m in GERENCIADOR.finditer(linha):
        g = re.sub(r"\s+", " ", m.group(1).lower())
        toks = re.split(r"\s+", m.group(2).strip())
        so_primeiro = g in EXECUTA_NA_HORA
        sem_perguntar = bool(re.match(r"(-y|--yes)\b", m.group(2).strip()))
        pular = False
        for t in toks:
            t = t.strip("`'\"),;.:")
            if pular:
                pular = False
                continue
            if not t or t in {"&&", "|", ";", "||", ">", "2>&1"}:
                break
            if t.startswith("-"):
                nome_flag = t.split("=", 1)[0]
                if nome_flag in {"-r", "--requirement", "-e", "--editable"}:
                    break
                if nome_flag in FLAG_COM_VALOR and "=" not in t:
                    pular = True
                continue
            if re.search(r"[<>{}$*]|^\.|^/|^~|^[A-Za-z]:\\|^https?:|^git\+|\.txt$|\.toml$", t):
                if so_primeiro:
                    break
                continue  # placeholder, caminho local ou URL: nao e nome de pacote do registro
            if g.startswith(("pip", "python", "uv pip", "uv add", "pipx install", "uv tool")):
                fixo = "==" in t or t.endswith(".whl")
                nome = re.split(r"[=<>!~\[;]", t, maxsplit=1)[0]
            else:
                corpo = t[1:] if t.startswith("@") else t
                nome, _, versao = corpo.partition("@")
                nome = ("@" + nome) if t.startswith("@") else nome
                if g == "uvx" and "==" in t:
                    nome, versao = t.split("==", 1)
                fixo = bool(re.match(r"^v?\d+\.\d+(\.\d+)?([-.+][\w.]+)?$", versao))
            if nome:
                saida.append((g, nome, fixo, sem_perguntar))
            if so_primeiro:
                break
    return saida


def servidores_mcp(cfg) -> dict:
    """Junta os servidores MCP dos formatos conhecidos (Claude, VS Code, Codex, Zed)."""
    res = {}
    if isinstance(cfg, dict):
        for k in ("mcpServers", "mcp_servers", "context_servers", "servers"):
            v = cfg.get(k)
            if isinstance(v, dict):
                for nome, srv in v.items():
                    if isinstance(srv, dict) and ({"command", "url", "type", "args"} & set(srv)):
                        res[nome] = srv
        for k in ("mcp", "amp.mcpServers"):
            if isinstance(cfg.get(k), dict):
                res.update(servidores_mcp(cfg[k]))
    return res


def ler_instaladas(dirs: list[str], raiz: str | None = None) -> list[tuple[str, str, str]]:
    """Devolve (pasta, name, description) das skills instaladas, exceto a propria raiz."""
    out = []
    for base in dirs:
        if not os.path.isdir(base):
            continue
        for d in sorted(os.listdir(base)):
            p = os.path.join(base, d)
            sk = os.path.join(p, "SKILL.md")
            if not os.path.isfile(sk) or (raiz and os.path.normcase(os.path.realpath(p)) == os.path.normcase(os.path.realpath(raiz))):
                continue
            with open(sk, "rb") as f:
                texto, _ = decodificar_texto(f.read(65536))
            fm = frontmatter(texto or "")
            out.append((p, fm.get("name", d), fm.get("description", "")))
    return out


def analisar(raiz: str, instaladas: list[str] | tuple = ()) -> dict:
    raiz = os.path.abspath(raiz)
    achados: list[dict] = []
    inventario = {"arquivos": 0, "dominios": set(), "mcp_comandos": [], "nao_lidos": []}
    com_env_massa: set[str] = set()
    com_credencial: set[str] = set()
    com_rede: set[str] = set()
    combo_no_mesmo = False

    def add(nivel, cat, arq, linha, msg, trecho=""):
        achados.append({"nivel": nivel, "categoria": cat, "arquivo": arq, "linha": linha,
                        "mensagem": msg, "trecho": trecho[:160]})

    def escondido(rel, n, onde, corpo):
        corpo = re.sub(r"<[^>]+>", " ", corpo).strip()
        if len(corpo) <= 3:
            return
        grave = IMPERATIVO.search(corpo) or any(nv == "ALTO" and rx.search(corpo) for nv, _, rx, _ in REGRAS)
        add("ALTO" if grave else "MEDIO", "prompt", rel, n,
            f"{onde} escondido" + (" com instrucao para o agente" if grave else " (leia o conteudo)"), corpo)

    # Leitura previa: a prosa (SKILL.md, references...) e o codigo, para saber quais scripts
    # a skill manda rodar, seja pela documentacao, seja chamando de outro script.
    partes, codigos = [], {}
    for tipo, rel, p, _ in entradas(raiz):
        ext_p = os.path.splitext(p)[1].lower()
        if tipo != "arq" or ext_p in EXT_MIDIA or ext_p in EXT_EXECUTAVEL or os.path.getsize(p) > LIMITE_BYTES:
            continue
        with open(p, "rb") as f:
            conteudo = decodificar_texto(f.read())[0] or ""
        if ext_p in EXT_PROSA:
            partes.append(conteudo)
        else:
            codigos[rel] = conteudo
    prosa_da_skill = "\n".join(partes)

    for tipo, rel, p, alvo in entradas(raiz):
        if tipo == "vcs":
            add("INFO", "arquivo", rel, 0, "pasta de controle de versao ignorada (nao entra no sha256)")
            continue
        if tipo.startswith("link"):
            fora = not dentro_de(raiz, os.path.join(os.path.dirname(p), alvo))
            oque = "pasta" if tipo == "link-pasta" else "arquivo"
            add("ALTO" if fora else "MEDIO", "arquivo", rel, 0,
                f"{oque} e link/juncao para {alvo}" + (" (FORA da skill: nao foi lido)" if fora else " (nao foi seguido)"))
            continue
        a = os.path.basename(p)
        ext = os.path.splitext(a)[1].lower()
        inventario["arquivos"] += 1
        if ext in EXT_EXECUTAVEL:
            add("ALTO", "arquivo", rel, 0, "binario executavel dentro da skill (nao da para revisar)")
            continue
        if ext in EXT_CLIQUE_WINDOWS:
            add("ALTO", "arquivo", rel, 0, f"tipo {ext} executa com dois cliques no Windows")
        if ext in EXT_PACOTE:
            add("MEDIO", "arquivo", rel, 0, "pacote compactado: extraia em pasta isolada e revise por dentro")
            continue
        if ext in EXT_MIDIA and ext != ".pdf":
            # O agente consegue ler imagem: o texto dentro dela chega a ele. Fica na lista de "nao lidos".
            inventario["nao_lidos"].append(rel)
            continue
        if a.startswith(".") and a not in {".gitignore", ".gitattributes"}:
            add("INFO", "arquivo", rel, 0, "arquivo oculto")
        if a.startswith(".skillspector-baseline"):
            add("ALTO", "arquivo", rel, 0, "baseline do autor: pode esconder achados; nunca use --use-shipped-baseline")
        tam = os.path.getsize(p)
        if tam > LIMITE_BYTES:
            add("MEDIO", "arquivo", rel, 0, f"arquivo grande ({tam} bytes) nao lido")
            inventario["nao_lidos"].append(rel)
            continue
        with open(p, "rb") as f:
            dados = f.read()
        if ext == ".pdf":
            # O agente le PDF. Lemos o texto solto e os streams /FlateDecode (com limite contra zip bomb).
            texto, n_streams, estourou = texto_do_pdf(dados)
            codificacao = "pdf"
            add("INFO", "arquivo", rel, 0,
                f"PDF: lido o texto solto e {n_streams} stream(s) comprimido(s)"
                + (" (limite de descompressao atingido)" if estourou else "")
                + "; fontes com codificacao propria e imagens nao sao lidas: abra e revise o PDF")
            inventario["nao_lidos"].append(rel)
        else:
            texto, codificacao = decodificar_texto(dados)
        if texto is None:
            add("INFO" if ext not in EXT_CLIQUE_WINDOWS else "MEDIO", "arquivo", rel, 0,
                f"conteudo binario ({ext or 'sem extensao'}) nao lido")
            inventario["nao_lidos"].append(rel)
            continue
        if codificacao.startswith("utf-16"):
            add("INFO", "arquivo", rel, 0, f"arquivo em {codificacao}: lido mesmo assim")
        linhas = texto.splitlines()

        # Invisiveis, linha a linha, com o texto escondido decodificado.
        # Emoji legitimo usa FE0F/FE0E e o juntor 200D uma vez, colado num simbolo: ignorado.
        simbolo = lambda c: c >= 0x2000 and unicodedata.category(chr(c)) in {"So", "Sm", "Sk", "Mn"}  # noqa: E731
        for n, linha in enumerate(linhas, 1):
            tipos, esc, seletores = {}, [], []
            for i, ch in enumerate(linha):
                cp = ord(ch)
                ant = ord(linha[i - 1]) if i else 0
                prox = ord(linha[i + 1]) if i + 1 < len(linha) else 0
                if cp == 0xFEFF and n == 1 and i == 0:
                    continue
                if cp in (0xFE0E, 0xFE0F) and simbolo(ant) and not (0xFE00 <= prox <= 0xFE0F):
                    continue
                if cp == 0x200D and (simbolo(ant) or ant == 0xFE0F) and simbolo(prox):
                    continue
                if cp == 0x20E3 or 0x1F3FB <= cp <= 0x1F3FF:
                    continue
                nome = classificar(cp)
                if nome:
                    tipos[nome] = tipos.get(nome, 0) + 1
                    if 0xE0020 <= cp <= 0xE007E:
                        esc.append(chr(cp - 0xE0000))
                    # "Emoji smuggling": cada seletor de variacao guarda um byte (FE00-FE0F = 0-15,
                    # E0100-E01EF = 16-255).
                    if 0xFE00 <= cp <= 0xFE0F:
                        seletores.append(cp - 0xFE00)
                    elif 0xE0100 <= cp <= 0xE01EF:
                        seletores.append(cp - 0xE0100 + 16)
            if tipos:
                desc = ", ".join(f"{k} x{v}" for k, v in tipos.items())
                revelado = ("texto escondido: " + "".join(esc)) if esc else ""
                if len(seletores) >= 4:
                    revelado += (" | " if revelado else "") + "bytes nos seletores: " + \
                        bytes(seletores).decode("utf-8", errors="replace")
                add("ALTO", "invisivel", rel, n, f"caracteres invisiveis: {desc}", revelado)

        # Conteudo que nao aparece quando o texto e renderizado.
        if ext in EXT_MARCACAO or ext in EXT_PROSA:
            for m in re.finditer(r"<!--(.*?)-->", texto, re.S):
                escondido(rel, texto.count("\n", 0, m.start()) + 1, "comentario HTML", m.group(1))
            for m in COMENTARIO_MD.finditer(texto):
                escondido(rel, texto.count("\n", 0, m.start()) + 1, "comentario Markdown", m.group(1))
            inicios = set()
            for m in ELEMENTO_OCULTO.finditer(texto):
                inicios.add(m.start())
                escondido(rel, texto.count("\n", 0, m.start()) + 1, f"texto oculto em <{m.group(1)}>", m.group(3))
            # Tag oculta sem fechar: o navegador esconde ate o fim do pai; o agente le tudo.
            for m in ABERTURA_OCULTA.finditer(texto):
                if m.start() in inicios:
                    continue
                corpo = texto[m.end():m.end() + 400].split("<", 1)[0]
                escondido(rel, texto.count("\n", 0, m.start()) + 1, f"texto oculto em <{m.group(1)}> sem fechar", corpo)
            # Oculto por classe ou id definidos num <style>.
            for bloco in BLOCO_STYLE.finditer(texto):
                for regra in REGRA_CSS.finditer(bloco.group(1)):
                    if not re.search(CSS_OCULTO, regra.group(2), re.I):
                        continue
                    for seletor in regra.group(1).split(","):
                        alvo_css = re.search(r"([.#])([\w-]+)\s*$", seletor.strip())
                        if not alvo_css:
                            continue
                        attr = "class" if alvo_css.group(1) == "." else "id"
                        rx = re.compile(r"<(\w+)\b[^>]*\b" + attr + r"\s*=\s*[\"'][^\"']*\b" + re.escape(alvo_css.group(2))
                                        + r"\b[^\"']*[\"'][^>]*>(.*?)(?:</\1\s*>|$)", re.I | re.S)
                        for el in rx.finditer(texto):
                            escondido(rel, texto.count("\n", 0, el.start()) + 1,
                                      f"texto oculto por CSS ({seletor.strip()})", el.group(2)[:400])

        propria = os.path.basename(raiz).lower()
        prosa = ext in EXT_PROSA or ext == ".pdf"

        def aplicar(nivel, cat, msg, linha, m, n, trecho):
            if cat == "config-agente" and "skills" in m.group(0).lower() and \
                    re.search(r"skills[/\\]" + re.escape(propria) + r"\b", linha, re.I) and \
                    not re.search(r"skills[/\\](?!" + re.escape(propria) + r"\b)[\w-]+", linha, re.I):
                return  # a skill citando a propria pasta
            if cat == "persistencia" and prosa:
                nivel = "MEDIO"  # documentacao pedindo ao usuario; o agente decide se executa
            if cat == "config-agente" and msg.startswith(("mexe", "acessa")) and not VERBO_ESCRITA.search(linha):
                nivel = "MEDIO"  # so cita a configuracao ou outra skill, sem mandar alterar
            if msg.startswith("manda esconder") and re.match(r"(sem|without|silently)\b", m.group(0), re.I) \
                    and negado(linha, m.start()):
                nivel = "MEDIO"  # "nunca faca X sem avisar o usuario" e uma trava, nao ocultacao
            if msg.startswith("manda esconder") and re.search(r"\b(a|any)\s+users?$|\busers$", m.group(0), re.I) \
                    and re.match(r"\s+(that\s+)?their\s+(text|writing|content|draft|post|score|copy|essay|message)"
                                 r"\s+(is|was|will|are|were|would|has)\b", linha[m.end():], re.I) \
                    and not re.search(r"\b(being|been|sent|copied|uploaded|shared|forwarded|posted|logged|stored|saved|"
                                      r"recorded|transmitted|leaked|exfiltrat\w*|enviad\w*|copiad\w*)\b|https?://|"
                                      r"\b[\w-]+\.(invalid|com|net|io|org|site|dev|app|xyz)\b", linha[m.end():], re.I):
                # "do not tell a user their text is undetectable": regra de honestidade sobre o proprio texto.
                # "do not tell a user their files were uploaded" continua ALTO.
                nivel = "MEDIO"
            if cat == "memoria" and nivel == "ALTO" and negado(linha, m.start()):
                nivel = "MEDIO"  # "Nunca edite o CLAUDE.md" e uma trava
            add(nivel, cat, rel, n, msg, trecho)

        for n, linha in enumerate(linhas, 1):
            for nivel, cat, rx, msg in REGRAS:
                m = rx.search(linha)
                if m:
                    aplicar(nivel, cat, msg, linha, m, n, linha.strip())
            for dom in re.findall(r"https?://([A-Za-z0-9.-]+)", linha):
                inventario["dominios"].add(dom.lower())
            vistos = set()
            for g, pkg, fixo, sem_perguntar in pacotes(linha):
                base_nome = pkg.lower().split("/")[-1]
                if base_nome in TIPOSQUAT or pkg.lower() in TIPOSQUAT:
                    add("ALTO", "supply-chain", rel, n, f"nome parecido com pacote famoso: {pkg}", linha.strip())
                if not fixo and (g, pkg) not in vistos:
                    vistos.add((g, pkg))
                    # ALTO quando baixa e roda sem confirmar, ou quando esta em script/config que executa.
                    # Na documentacao, "npx remotion" costuma rodar o pacote LOCAL do projeto: MEDIO.
                    comentario = re.match(r"\s*(//|#|\*|/\*|--|;|rem\b|::)", linha, re.I)
                    if g in EXECUTA_NA_HORA and (sem_perguntar or not (prosa or comentario)):
                        add("ALTO", "supply-chain", rel, n,
                            f"{g} {pkg} sem versao fixa: baixa e EXECUTA a versao do dia (pode mudar sem aviso)", linha.strip())
                    else:
                        add("MEDIO", "supply-chain", rel, n, f"{g} {pkg} sem versao fixa", linha.strip())

        # Regras de prompt/memoria quebradas em duas linhas.
        for n in range(len(linhas) - 1):
            junto = linhas[n].rstrip() + " " + linhas[n + 1].lstrip()
            for nivel, cat, rx, msg in REGRAS:
                if cat in CATEGORIAS_MULTILINHA:
                    m = rx.search(junto)
                    if m and not rx.search(linhas[n]) and not rx.search(linhas[n + 1]):
                        aplicar(nivel, cat, msg + " (quebrado em duas linhas)", junto, m, n + 1, junto.strip())

        # Combinacao letal: le segredos em massa (ou arquivo de credencial) E fala com a rede.
        massa = AMBIENTE_EM_MASSA.search(tirar_ambiente_de_subprocesso(texto))
        cred, rede = CREDENCIAL_ARQUIVO.search(texto), REDE.search(texto)
        # Para a combinacao ENTRE arquivos, so contam codigo de verdade (nem prosa nem teste).
        # Arquivo de teste volta a contar quando a documentacao da skill manda roda-lo.
        e_teste = re.search(r"(^|/)(tests?|__tests__|spec|fixtures?)/|(^|/)test_|_test\.|\.spec\.|\.test\.", rel)
        citado = rel in prosa_da_skill or (e_teste and os.path.basename(rel) in prosa_da_skill
                                           and re.search(r"\b(rode|run|execute|python|node|bash|uv run)\b[^\n]{0,80}"
                                                         + re.escape(os.path.basename(rel)), prosa_da_skill, re.I))
        if e_teste and not citado:
            # Tambem conta quando OUTRO arquivo de codigo da skill aponta para ele (ex.: run.py roda tests/a.py).
            caminho = re.escape(rel).replace("/", r"[/\\]")
            # ...ou importa o modulo dele (import coleta / from tests.coleta import / require('./tests/coleta')).
            modulo = re.escape(os.path.splitext(os.path.basename(rel))[0])
            importa = re.compile(r"^\s*(import\s+([\w.]+\.)?" + modulo + r"\b|from\s+([\w.]+\.)?" + modulo + r"\s+import\b|"
                                 r"from\s+[\w.]+\s+import\s+[^\n]*\b" + modulo + r"\b)|"
                                 r"(require|import)\s*\(?\s*['\"][^'\"]*\b" + modulo + r"(\.\w+)?['\"]", re.M)
            citado = any(re.search(r"(^|[\s'\"(/\\.])" + caminho + r"\b", c) or importa.search(c)
                         for r2, c in codigos.items() if r2 != rel)
        codigo = ext not in EXT_PROSA and ext not in EXT_MARCACAO - {".jsx", ".tsx", ".vue"} and (not e_teste or citado)
        if massa and codigo:
            com_env_massa.add(rel)
        if cred and codigo:
            com_credencial.add(rel)
        if rede and codigo:
            com_rede.add(rel)
        if rede and (massa or cred):
            combo_no_mesmo = True
            add("ALTO", "vazamento", rel, 0,
                "varre o ambiente ou le arquivo de credencial E usa rede no mesmo arquivo (possivel roubo de chave)")
        elif rede:
            nomes = sorted({x for x in VARIAVEL_NOMEADA.findall(texto) if re.search(r"KEY|TOKEN|SECRET|PASS|AUTH", x)})
            if nomes:
                add("INFO", "segredo", rel, 0, "le chave nomeada e usa rede: confira se a chave so vai para o servico dela",
                    ", ".join(nomes))

        for s in decodificar_base64(texto):
            add("ALTO", "execucao", rel, 0, "carga em base64 decodificada (leia, nao execute)", s)
        for s in decodificar_ofuscado(texto):
            add("ALTO", "execucao", rel, 0, "carga ofuscada decodificada (leia, nao execute)", s)

        # Manifestos MCP: JSON (Claude, VS Code, Zed) e TOML (Codex).
        cfg = None
        if ext in {".json", ".jsonc"} and re.search(r"mcpServers|\"servers\"|context_servers|mcp_servers", texto):
            try:
                cfg = json.loads(re.sub(r"^\s*//.*$", "", texto, flags=re.M) if ext == ".jsonc" else texto)
            except json.JSONDecodeError:
                add("INFO", "mcp", rel, 0, "manifesto MCP que nao e JSON valido")
        elif ext == ".toml" and "mcp_servers" in texto:
            try:
                cfg = tomllib.loads(texto)
            except tomllib.TOMLDecodeError:
                add("INFO", "mcp", rel, 0, "manifesto MCP que nao e TOML valido")
        for nome, srv in servidores_mcp(cfg).items():
            args = srv.get("args", [])
            args = args if isinstance(args, list) else [str(args)]
            cmd = " ".join([str(srv.get("command", ""))] + [str(x) for x in args]).strip()
            inventario["mcp_comandos"].append(f"{nome}: {cmd or srv.get('url', '?')}")
            if srv.get("url"):
                add("MEDIO", "mcp", rel, 0, f"servidor MCP remoto {nome}: {srv['url']} (pode mudar depois da revisao)")
            for g, pkg, fixo, _ in pacotes(cmd):
                if not fixo:
                    add("ALTO", "mcp", rel, 0, f"servidor MCP {nome} sem versao fixa ({g} {pkg}): pode trocar de codigo sem aviso", cmd)
            if re.search(r"\b(docker|podman)\b", cmd) and re.search(r"\brun\b", cmd) and not re.search(r"@sha256:[0-9a-f]{64}", cmd):
                add("ALTO", "mcp", rel, 0, f"servidor MCP {nome} roda imagem de container sem digest (@sha256): pode trocar sem aviso", cmd)

        if a.upper() == "SKILL.MD":
            fm = frontmatter(texto)
            desc = fm.get("description", "")
            # O Claude Code decide quando chamar a skill por description E when_to_use.
            for campo in ("description", "when_to_use"):
                valor = fm.get(campo, "")
                if GATILHO_AMPLO.search(valor):
                    add("ALTO", "gatilho", rel, 0, f"{campo} ampla demais: pode sequestrar pedidos sem relacao", valor)
                elif GATILHO_SEMPRE.search(valor):
                    add("MEDIO", "gatilho", rel, 0, f"{campo} diz 'sempre/always': confira se tem escopo", valor)
            if len(desc) + len(fm.get("when_to_use", "")) > 1024:
                add("MEDIO", "gatilho", rel, 0, "description + when_to_use longas (mais de 1024 caracteres)")
            if not fm:
                add("MEDIO", "gatilho", rel, 0, "SKILL.md sem frontmatter legivel")
            if fm.get("allowed-tools"):
                add("INFO", "permissao", rel, 0, f"allowed-tools: {fm['allowed-tools']}")
            if rel == "SKILL.md" and instaladas:
                meu_nome = fm.get("name", os.path.basename(raiz))
                for pasta, nome, desc2 in ler_instaladas(list(instaladas), raiz):
                    if nome.lower() == meu_nome.lower():
                        add("ALTO", "imitacao", rel, 0,
                            f"mesmo name '{nome}' de uma skill instalada ({pasta}): tomaria o lugar dela")
                    elif desc and desc2 and difflib.SequenceMatcher(None, desc.lower(), desc2.lower()).ratio() >= 0.8:
                        add("MEDIO", "imitacao", rel, 0, f"description quase igual a da skill instalada '{nome}'")

    # Combinacao letal espalhada em arquivos diferentes.
    if not combo_no_mesmo and (com_env_massa or com_credencial) and com_rede:
        add("ALTO", "vazamento", ", ".join(sorted(com_env_massa | com_credencial)), 0,
            "um arquivo varre o ambiente ou le credencial e OUTRO usa rede: confira se os dados passam de um para o outro",
            "rede em: " + ", ".join(sorted(com_rede)))

    if inventario["nao_lidos"]:
        add("INFO", "arquivo", "-", 0, f"{len(inventario['nao_lidos'])} arquivo(s) nao lido(s): revise a mao",
            ", ".join(inventario["nao_lidos"][:10]))

    inventario["dominios"] = sorted(inventario["dominios"])
    ordem = {"ALTO": 0, "MEDIO": 1, "INFO": 2}
    achados.sort(key=lambda x: (ordem[x["nivel"]], x["arquivo"], x["linha"]))
    return {"pasta": raiz, "sha256": impressao_digital(raiz), "inventario": inventario, "achados": achados,
            "contagem": {k: sum(1 for x in achados if x["nivel"] == k) for k in ordem}}


def imprimir(r: dict) -> None:
    c = r["contagem"]
    print(f"Pasta: {r['pasta']}\nsha256: {r['sha256']}")
    print(f"Achados: ALTO={c['ALTO']} MEDIO={c['MEDIO']} INFO={c['INFO']} | arquivos={r['inventario']['arquivos']}")
    if r["inventario"]["dominios"]:
        print("Dominios citados: " + ", ".join(r["inventario"]["dominios"]))
    for m in r["inventario"]["mcp_comandos"]:
        print("MCP: " + m)
    for x in r["achados"]:
        loc = f"{x['arquivo']}:{x['linha']}" if x["linha"] else x["arquivo"]
        print(f"[{x['nivel']}] {x['categoria']} {loc} - {x['mensagem']}")
        if x["trecho"]:
            print(f"        > {x['trecho']}")


def lote(dirs: list[str], como_json: bool) -> int:
    skills = ler_instaladas(dirs)
    resultados, por_nome = [], {}
    for pasta, nome, _ in skills:
        r = analisar(pasta)
        resultados.append((nome, pasta, r))
        por_nome.setdefault(nome.lower(), []).append(pasta)
    repetidos = {n: ps for n, ps in por_nome.items() if len(ps) > 1}
    if como_json:
        print(json.dumps({"skills": [{"name": n, "pasta": p, "sha256": r["sha256"], "contagem": r["contagem"],
                                      "altos": [a for a in r["achados"] if a["nivel"] == "ALTO"]}
                                     for n, p, r in resultados],
                          "names_repetidos": repetidos}, ensure_ascii=False, indent=2))
    else:
        print(f"{'skill':40} {'ALTO':>5} {'MEDIO':>6}  sha256")
        for nome, pasta, r in sorted(resultados, key=lambda x: (-x[2]["contagem"]["ALTO"], x[0])):
            c = r["contagem"]
            print(f"{nome[:40]:40} {c['ALTO']:>5} {c['MEDIO']:>6}  {r['sha256'][:16]}")
        for n, ps in repetidos.items():
            print(f"[ALTO] imitacao: name '{n}' aparece em {len(ps)} skills: " + " | ".join(ps))
        print(f"\n{len(resultados)} skills, {sum(1 for _, _, r in resultados if r['contagem']['ALTO'])} com ALTO,"
              f" {len(repetidos)} name(s) repetido(s)")
    return 1 if repetidos or any(r["contagem"]["ALTO"] for _, _, r in resultados) else 0


def main() -> int:
    argv = sys.argv[1:]
    como_json = "--json" in argv
    instaladas: list[str] = []
    livres: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--instaladas" and i + 1 < len(argv):
            instaladas.append(argv[i + 1])
            i += 2
            continue
        if not argv[i].startswith("--"):
            livres.append(argv[i])
        i += 1
    if "--lote" in argv:
        if not livres or not all(os.path.isdir(d) for d in livres):
            print(__doc__)
            return 2
        return lote(livres, como_json)
    if len(livres) != 1 or not os.path.isdir(livres[0]):
        print(__doc__)
        return 2
    r = analisar(livres[0], instaladas=instaladas)
    if como_json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        imprimir(r)
    return 1 if r["contagem"]["ALTO"] else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
