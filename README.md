# Atlas-Sentinel 🛡️

Skill para o **Claude Code** que revisa **skills, plugins e servidores MCP antes de você instalar**. Ela procura roubo de chave, injeção de prompt, instruções escondidas e outros ataques contra agentes de IA.

> *English summary: a Claude Code skill that audits agent skills, plugins and MCP servers before installation. It combines NVIDIA SkillSpector, a stdlib-only AI-attack checker (`scripts/checar.py`) and a semantic review by the agent. Docs are in Portuguese; reports follow the user's language.*

## Por que existe

Uma skill não é "só um texto". O agente obedece ao que está escrito nela, e ela tem acesso ao seu disco, ao terminal, às suas chaves e à rede. Uma skill maliciosa pode mandar o agente ler o seu `.env` e enviá-lo para fora, gravar uma ordem permanente na memória dele ou tomar o lugar de outra skill.

O Atlas-Sentinel nasceu do `skill-inspector` do [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) e foi ampliado para os ataques próprios de agentes de IA. No eval incluído (54 ataques):

| Linha de defesa | Ataques pegos | Falsos positivos em 12 controles legítimos |
|---|---:|---:|
| SkillSpector sozinho (análise estática, sem LLM) | 20/54 | 3 |
| `checar.py` do Atlas-Sentinel | **54/54** | **0** |

As iscas foram escritas junto com as regras. Esse número mede os ataques **conhecidos**, não os novos. Por isso a skill sempre termina com uma revisão semântica feita pelo agente.

## Como funciona

São três linhas de revisão. Nenhuma basta sozinha:

1. **SkillSpector** (NVIDIA): padrões clássicos de risco em código.
2. **`scripts/checar.py`**: o que é próprio de agente de IA:
   - vazamento por imagem Markdown;
   - texto invisível, como Unicode TAG, bidi e seletores de variação, **mostrado decodificado**;
   - comentários e texto oculto em HTML, SVG, Markdown e PDF;
   - gatilho sequestrador na `description` ou no `when_to_use`;
   - envenenamento de memória (`CLAUDE.md`, `MEMORY.md`, `AGENTS.md`);
   - hooks e permissões;
   - ferramenta MCP envenenada e MCP sem versão fixa (Claude, VS Code, Codex, Zed, Docker sem digest);
   - `npx -y` sem versão e typosquatting;
   - código ofuscado;
   - link ou junção do Windows para fora da pasta;
   - skill que imita outra instalada.

   Ele só lê os arquivos. Não executa nada da skill analisada e só usa a biblioteca padrão do Python.
3. **Revisão semântica** pelo agente, que dá o veredito final: `APPROVE`, `CAUTION` ou `REJECT`, junto com o sha256 da versão revisada.

## Instalação

Requisitos: [Claude Code](https://claude.com/claude-code), Python 3.12+ (ou [uv](https://docs.astral.sh/uv/)) e, de preferência, o SkillSpector.

**1. Clone direto na pasta de skills do Claude Code.**

Linux e macOS:

```bash
git clone https://github.com/Phb29/atlas-sentinel.git ~/.claude/skills/atlas-sentinel
```

Windows (PowerShell):

```powershell
git clone https://github.com/Phb29/atlas-sentinel.git "$env:USERPROFILE\.claude\skills\atlas-sentinel"
```

Para usar a skill só num projeto, clone em `<projeto>/.claude/skills/atlas-sentinel`.

**2. (Recomendado) Instale o SkillSpector da NVIDIA**, do repositório oficial e com a versão fixa:

```bash
uv tool install "git+https://github.com/NVIDIA/SkillSpector.git@v2.13.3"
```

Não use `pip install skillspector` nem `uv tool install skillspector` sem a URL: isso busca no PyPI qualquer pacote com esse nome, que pode não ser o da NVIDIA. Sem o SkillSpector, a skill avisa e segue com as outras duas linhas.

**3. Confira** que a skill aparece no Claude Code: digite `/atlas-sentinel`. Para atualizar depois, entre na pasta da skill e rode `git pull`. O sha256 da pasta muda, e é bom revisar a nova versão com a própria skill.

## Uso

No Claude Code:

```
/atlas-sentinel ~/Downloads/alguma-skill
```

Também dá para pedir com suas palavras: "essa skill é segura?", "posso instalar este MCP?" ou "verifica as skills instaladas".

O verificador também roda sozinho, fora do Claude Code:

```bash
# Uma skill
uv run --no-project python -I scripts/checar.py <pasta-da-skill>

# Uma skill, conferindo se ela imita alguma já instalada
uv run --no-project python -I scripts/checar.py <pasta-da-skill> --instaladas ~/.claude/skills

# Todas as skills instaladas (aponta names repetidos)
uv run --no-project python -I scripts/checar.py --lote ~/.claude/skills
```

## Eval

```bash
uv run --no-project python -I evals/eval.py <pasta-nova-e-vazia> --controles <skill-limpa> [...]
```

O eval cria iscas **inertes**: os domínios são `.invalid` e nada é executado. Ele mostra quantos ataques cada linha pega e mede o falso positivo nos controles. Quando surgir um ataque novo, acrescente uma isca **antes** de mudar a regra.

Ao analisar a própria pasta do Atlas-Sentinel, o `checar.py` dá dezenas de ALTO. Isso é esperado: os exemplos de ataque estão escritos nos arquivos dela.

## Limites

- As regras do `checar.py` usam expressões regulares. Uma frase reescrita com outras palavras, ou em outro idioma além de português e inglês, pode escapar. A revisão semântica continua obrigatória.
- Do PDF, ele lê o texto solto e os streams Flate. Fontes com codificação própria e imagens não são lidas e entram na lista "não lidos", para revisão manual.
- Nenhuma ferramenta prova que uma skill é segura. Ela reduz o risco e mostra a evidência para você decidir.

## Licença

[Apache-2.0](LICENSE). Este projeto deriva do `skill-inspector` do NVIDIA SkillSpector. Veja o [NOTICE](NOTICE).
