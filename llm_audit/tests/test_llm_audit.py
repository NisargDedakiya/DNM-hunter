"""Tests for OWASP LLM Top 10 static detection.

Run: python -m unittest llm_audit.tests.test_llm_audit -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from llm_audit import scan_llm_code, scan_tree, LLM_TOP10


def ids(findings):
    return {f.llm_id for f in findings}


_VULN = '''
import openai, torch, pickle
from langchain.agents import load_tools
SYSTEM_PROMPT = "You are a bot. api_key: sk-abc123def456ghijkl"
def chat(request):
    user = request.args.get("q")
    prompt = f"Answer: {user}"
    r = openai.chat.completions.create(model="gpt-4", messages=[{"role":"user","content":prompt}])
    ans = r.choices[0].message.content
    print("prompt", prompt)
    eval(ans)
    torch.load("m.bin")
    pickle.load(open("d.pkl","rb"))
    AutoModel.from_pretrained("x", trust_remote_code=True)
    load_tools(["terminal"])
    return store.similarity_search(user)
'''


class TestDetection(unittest.TestCase):
    def test_detects_most_of_the_top10(self):
        got = ids(scan_llm_code(_VULN, "app.py"))
        for expected in ("LLM01", "LLM03", "LLM04", "LLM05", "LLM06", "LLM09", "LLM10"):
            self.assertIn(expected, got, f"{expected} ({LLM_TOP10[expected]}) should be detected")

    def test_llm05_output_to_eval_is_critical(self):
        f = scan_llm_code("import openai\nans = resp.choices[0].message.content\neval(ans)\n", "a.py")
        self.assertTrue(any(x.llm_id == "LLM05" and x.severity == "critical" for x in f))

    def test_trust_remote_code_flagged(self):
        f = scan_llm_code('AutoModel.from_pretrained("x", trust_remote_code=True)', "a.py")
        self.assertIn("LLM04", ids(f))


class TestPrecision(unittest.TestCase):
    def test_non_llm_file_is_mostly_quiet(self):
        # generic code with no LLM SDK: context-gated rules must not fire
        f = scan_llm_code("x = request.args.get('q')\nprompt = f'hi {x}'\n", "web.py")
        self.assertNotIn("LLM01", ids(f))     # no LLM context

    def test_eval_on_string_literal_not_flagged(self):
        f = scan_llm_code('import openai\neval("2+2")', "a.py")
        self.assertNotIn("LLM05", ids(f))

    def test_max_tokens_set_suppresses_llm09(self):
        code = 'import openai\nr = openai.chat.completions.create(model="x", messages=m, max_tokens=256)'
        self.assertNotIn("LLM09", ids(scan_llm_code(code, "a.py")))

    def test_filtered_retrieval_not_flagged(self):
        code = 'import openai\nstore.similarity_search(q, filter={"user_id": uid})'
        self.assertNotIn("LLM07", ids(scan_llm_code(code, "a.py")))

    def test_comment_mentioning_max_tokens_does_not_suppress(self):
        # a comment saying "no max_tokens" must NOT count as having set it
        code = 'import openai\nr = openai.chat.completions.create(model="x", messages=m)  # no max_tokens here\n'
        self.assertIn("LLM09", ids(scan_llm_code(code, "a.py")))


class TestTree(unittest.TestCase):
    def test_scan_tree(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.py").write_text(_VULN)
            (Path(d) / "node_modules").mkdir()
            (Path(d) / "node_modules" / "x.py").write_text(_VULN)  # must be skipped
            found = scan_tree(d)
            self.assertTrue(found)
            self.assertFalse(any("node_modules" in f.file for f in found))


if __name__ == "__main__":
    unittest.main()
