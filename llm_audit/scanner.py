"""OWASP LLM Top 10 (2025) static scanner.

Detects the source-level anti-patterns behind each LLM risk. Patterns are gated
on the file actually being LLM code (imports/uses an LLM SDK) where a pattern
would otherwise be generic, to keep precision usable. Language coverage:
Python and JavaScript/TypeScript.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# The catalogue, so findings can be labelled and reports can explain each id.
LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "System Prompt Leakage",
    "LLM07": "Vector and Embedding Weaknesses",
    "LLM08": "Misinformation",
    "LLM09": "Unbounded Consumption",
    "LLM10": "Excessive Autonomy",
}

CRIT, HIGH, MED, LOW = "critical", "high", "medium", "low"

_SRC_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next", "__pycache__", ".venv", "venv"}

# Does this file use an LLM SDK / framework? Gates the context-sensitive rules.
_LLM_CONTEXT = re.compile(
    r"\b(openai|anthropic|langchain|llama_index|llamaindex|litellm|cohere|"
    r"transformers|huggingface|ollama|chat\.completions|ChatCompletion|"
    r"ChatOpenAI|ChatAnthropic|invoke_model|bedrock-runtime|generativeai|"
    r"system_prompt|system_message|messages\s*=|completion|embeddings?\.create)\b",
    re.IGNORECASE,
)

# Sinks that must never receive model output (LLM05).
_DANGEROUS_SINK = re.compile(
    r"\b(eval|exec|os\.system|subprocess\.(?:run|call|Popen|check_output)|"
    r"pd\.eval|Function\s*\(|child_process\.(?:exec|execSync)|vm\.runInNewContext)\b"
)
# ...applied to a variable that looks like an LLM response (by name).
_LLM_OUTPUT_VAR = re.compile(
    r"(completion|response|message|answer|output|result|generated|llm_?out|"
    r"reply|content|chat_?response|prediction)", re.IGNORECASE
)
# A variable assigned from an actual LLM response shape (for output taint).
_LLM_OUTPUT_ASSIGN = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*[^=].*(\.choices\b|\.message\.content|message\.content|"
    r"\.completion\b|\.invoke\s*\(|generate_content|\.content\b|\.text\b)")

# Request/user-controlled input flowing into a prompt (LLM01).
_USER_INPUT = re.compile(r"(request\.|req\.|user_?input|params\[|body\[|query\[|argv|input\(\)|flask\.request|\.args\.get|\.get_json|req\.body|req\.query)")
_PROMPT_ASSIGN = re.compile(r"\b(system_?prompt|prompt|messages|template|instruction)s?\b\s*[=:+]", re.IGNORECASE)
# A variable assigned from user input (for light intra-file taint tracking).
_INPUT_ASSIGN = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*[^=].*?(request\.|req\.|\.args\.get|\.get_json|"
    r"params\[|body\[|query\[|input\s*\(|argv|user_?input|flask\.request)")
# Interpolation of a variable into a string (f-string / template literal / concat / .format).
def _interpolates(line: str, var: str) -> bool:
    return bool(
        re.search(r"[{$]\{?\s*" + re.escape(var) + r"\b", line)   # {var} or ${var}
        or re.search(r"\+\s*" + re.escape(var) + r"\b", line)      # + var
        or re.search(r"\.format\([^)]*\b" + re.escape(var) + r"\b", line)
    )

# Dangerous agent tool names (LLM10).
_DANGEROUS_TOOL = re.compile(
    r"(ShellTool|PythonREPLTool|PythonAstREPLTool|TerminalTool|BashProcess|"
    r"exec_tool|create_python_agent|"
    r"load_tools\s*\([^)]*(terminal|python_repl|requests_get|requests_post|shell))"
)

# Regex-based single-line rules: (llm_id, rule_id, severity, title, regex, needs_llm_context)
_LINE_RULES = [
    # LLM03/04 — untrusted model / data loading
    ("LLM04", "LLM-041", CRIT, "trust_remote_code=True (arbitrary code from a model repo)",
     re.compile(r"trust_remote_code\s*=\s*True"), False),
    ("LLM03", "LLM-031", HIGH, "Unsafe torch.load (pickle RCE) — set weights_only=True",
     re.compile(r"torch\.load\s*\((?![^)]*weights_only\s*=\s*True)"), False),
    ("LLM03", "LLM-032", HIGH, "Model/dataset loaded via pickle (deserialization RCE)",
     re.compile(r"\b(pickle|cPickle|joblib)\.(load|loads)\s*\("), True),
    ("LLM03", "LLM-033", MED, "Model downloaded from an unpinned/remote source",
     re.compile(r"from_pretrained\s*\(\s*['\"]https?://"), False),
    # LLM06 — system prompt leakage / secrets in prompt
    ("LLM06", "LLM-061", HIGH, "Possible secret hardcoded in a system prompt",
     re.compile(r"(system[_-]?(prompt|message)).{0,80}(sk-[A-Za-z0-9]{16,}|api[_-]?key|password|secret|token)\s*[:=]", re.IGNORECASE), False),
    ("LLM06", "LLM-062", MED, "System prompt returned to the user",
     re.compile(r"return[^#\n]*\bsystem[_-]?(prompt|message)\b", re.IGNORECASE), True),
    # LLM02 — sensitive info disclosure
    ("LLM02", "LLM-021", MED, "Full prompt/response logged (may leak sensitive context)",
     re.compile(r"\b(print|console\.log|logg?e?r?\.(info|debug|warn|error))\s*\([^)]*\b(prompt|messages|completion|response)\b", re.IGNORECASE), True),
    # LLM09 — unbounded consumption
    ("LLM09", "LLM-091", MED, "LLM call in an unbounded loop",
     re.compile(r"while\s+True", re.IGNORECASE), True),
    # LLM07 — vector/embedding retrieval without an access filter
    ("LLM07", "LLM-071", MED, "RAG retrieval without a tenant/metadata filter",
     re.compile(r"\.(similarity_search|as_retriever|query)\s*\((?![^)]*(filter|where|namespace|user_?id|tenant))", re.IGNORECASE), True),
]


@dataclass
class LlmFinding:
    llm_id: str          # LLM01..LLM10
    rule_id: str
    severity: str
    title: str
    category_name: str   # human name from LLM_TOP10
    file: str
    line: int
    detail: str


def _uses_llm(text: str) -> bool:
    return bool(_LLM_CONTEXT.search(text))


def scan_llm_code(text: str, file: str) -> list[LlmFinding]:
    findings: list[LlmFinding] = []
    is_llm = _uses_llm(text)
    lines = text.splitlines()

    def add(llm_id, rule_id, sev, title, line_no, detail):
        findings.append(LlmFinding(llm_id, rule_id, sev, title, LLM_TOP10[llm_id], file, line_no, detail))

    # kwarg/dict context so a comment mentioning "max_tokens" doesn't count.
    has_max_tokens = bool(re.search(r"max_(tokens|completion_tokens|output_tokens)\s*[=:]", text))
    has_llm_create = bool(re.search(r"(chat\.completions\.create|ChatCompletion\.create|\.invoke\(|messages\.create|generate_content)", text))

    # Light intra-file taint: variables assigned from user input (for LLM01)
    # and variables assigned from an LLM response (for LLM05).
    tainted: set[str] = set()
    tainted_output: set[str] = set()
    for raw in lines:
        code = raw.split("#", 1)[0]
        m = _INPUT_ASSIGN.search(code)
        if m:
            tainted.add(m.group(1))
        mo = _LLM_OUTPUT_ASSIGN.search(code)
        if mo and is_llm:
            tainted_output.add(mo.group(1))

    for i, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0] if not raw.lstrip().startswith(("//",)) else raw
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue

        # LLM05 — model output into a dangerous sink. Fires when the sink's
        # argument is a variable tainted from an LLM response, or a var whose
        # name looks like a response — but never on a pure string literal.
        sink_m = _DANGEROUS_SINK.search(line)
        if sink_m:
            arg_region = line[sink_m.end():]
            refs_tainted = any(re.search(r"\b" + re.escape(v) + r"\b", arg_region) for v in tainted_output)
            name_looks = bool(_LLM_OUTPUT_VAR.search(arg_region))
            literal_only = bool(re.match(r"\s*\(\s*['\"][^'\"]*['\"]\s*\)", arg_region))
            if (refs_tainted or (is_llm and name_looks)) and not literal_only:
                add("LLM05", "LLM-051", CRIT, "Model output passed to a code/command sink", i,
                    "An LLM response is passed to eval/exec/system/subprocess — model output is executed. Validate & sandbox before use.")

        # LLM01 — user input flowing into a prompt (direct, or via a tainted var)
        if is_llm and _PROMPT_ASSIGN.search(line):
            direct = bool(_USER_INPUT.search(line))
            via_taint = any(_interpolates(line, v) for v in tainted)
            if direct or via_taint:
                add("LLM01", "LLM-011", HIGH, "User input interpolated into a prompt without sanitization", i,
                    "Untrusted input is concatenated into the prompt/messages — a prompt-injection surface. Use delimiters, structured messages, and input validation.")

        # LLM10 — dangerous autonomous agent tools
        if _DANGEROUS_TOOL.search(line):
            add("LLM10", "LLM-101", HIGH, "Autonomous agent granted a shell/code-execution tool", i,
                "An agent is given a shell/Python/HTTP tool; without a human-approval gate this is excessive autonomy. Restrict tools and add confirmation for high-impact actions.")

        for llm_id, rule_id, sev, title, rx, needs_ctx in _LINE_RULES:
            if needs_ctx and not is_llm:
                continue
            if rx.search(line):
                add(llm_id, rule_id, sev, title, i, f"{LLM_TOP10[llm_id]} ({llm_id}).")

    # LLM09 — an LLM completion call with no output bound (file-level check)
    if has_llm_create and not has_max_tokens:
        # attach to the first create() line
        for i, raw in enumerate(lines, 1):
            if re.search(r"(completions\.create|ChatCompletion\.create|\.invoke\(|generate_content)", raw):
                add("LLM09", "LLM-092", LOW, "LLM call without a max_tokens / output bound", i,
                    "No max_tokens/output limit — a crafted request can force very large (costly) generations (unbounded consumption).")
                break

    return findings


def scan_tree(root: str | Path) -> list[LlmFinding]:
    root = Path(root)
    out: list[LlmFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SRC_EXT:
            continue
        if any(p in _SKIP_DIRS for p in path.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        out.extend(scan_llm_code(text, rel))
    return out
