# OWASP LLM Top 10 Auditor (`llm_audit`)

Static detection of the **OWASP Top 10 for LLM Applications (2025)** in AI-app
source code (Python / JS / TS). Finds the code-level anti-patterns behind each
risk and labels every finding with its `LLMxx` id.

| id | Risk | Detected by |
|---|---|---|
| **LLM01** | Prompt Injection | user input (tracked via intra-file taint) interpolated into a prompt/messages |
| **LLM02** | Sensitive Information Disclosure | full prompt/response logged |
| **LLM03** | Supply Chain | `torch.load` w/o `weights_only`, `pickle/joblib.load` of models, remote `from_pretrained` |
| **LLM04** | Data & Model Poisoning | `trust_remote_code=True` |
| **LLM05** | Improper Output Handling | LLM response (tracked via taint) passed to `eval`/`exec`/`system`/`subprocess`/`Function`/`child_process` |
| **LLM06** | System Prompt Leakage | secret hardcoded in a system prompt; system prompt returned to the user |
| **LLM07** | Vector & Embedding Weaknesses | RAG retrieval (`similarity_search`/`as_retriever`) with no tenant/metadata filter |
| **LLM08** | Misinformation | *runtime-only* — not statically detectable (documented, not falsely reported) |
| **LLM09** | Unbounded Consumption | LLM completion call with no `max_tokens`; LLM call in `while True` |
| **LLM10** | Excessive Autonomy | agent granted a shell/Python/HTTP tool (`ShellTool`, `PythonREPLTool`, `load_tools(["terminal"])`, …) |

## Precision

Rules that would otherwise be generic are **gated on the file actually using an
LLM SDK** (openai/anthropic/langchain/transformers/…). Verified negatives:
`eval("2+2")` (literal) is not LLM05; `max_tokens=256` suppresses LLM09;
`similarity_search(q, filter=...)` suppresses LLM07; a non-LLM web file does not
raise LLM01. Two lightweight intra-file taint passes track user input → prompt
(LLM01) and LLM response → dangerous sink (LLM05) so the flags land on real flows.

## Usage

```bash
python -c "from llm_audit import scan_tree; \
  [print(f.llm_id, f.severity, f.file, f.title) for f in scan_tree('./app')]"

from llm_audit import scan_llm_code
for f in scan_llm_code(open('app.py').read(), 'app.py'):
    print(f.llm_id, f.title)
```

Integrated into the GitHub repo scanner (`repo_scan`), so scanning a repo URL
now reports OWASP LLM issues alongside IaC, cloud, OS/native, and secrets.

## Honest scope

Static source analysis finds the *design/implementation* anti-patterns. It does
**not** actively test a live model (sending prompt-injection payloads to a
running endpoint) — that's a separate dynamic-testing capability — and LLM08
(Misinformation) is inherently a runtime output-quality property, so it is
mapped but not statically flagged.

## Tests

```bash
python -m unittest llm_audit.tests.test_llm_audit -v   # 9 tests (detection + precision)
```
