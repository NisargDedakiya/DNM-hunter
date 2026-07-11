"""
Canonical AI-provider name resolution for secret-detector output.

Closes the "trufflehog / github-secret-hunt AI detector lap" documented as
reserved in readmes/GRAPH.SCHEMA.md ("Properties reserved for later laps" ->
Secret / TrufflehogFinding / GithubSecret -> ai_provider). js_recon already
sets ai_provider by correlating a leaked key against a companion AI-SDK-usage
finding in the same file; trufflehog and github-secret-hunt have no such
source-code context, so this resolves purely from the detector's own name —
TruffleHog's built-in detector names (single-word, e.g. "OpenAI") and
github_secret_hunt's descriptive SECRET_PATTERNS keys (e.g. "OpenAI API Key")
both get mapped to the same canonical provider string, so
`MATCH (s) WHERE s.ai_provider IS NOT NULL` works uniformly across all three
secret-finding node types.
"""
import re

# Ordered so more specific keywords are checked before generic ones
# (e.g. "Google Gemini" before a bare "Google" that would false-positive on
# GCP service-account keys, which are not an LLM-provider credential).
_PROVIDER_KEYWORDS: list[tuple[str, str]] = [
    (r"openai", "OpenAI"),
    (r"anthropic|claude", "Anthropic"),
    (r"hugging\s*face|\bhf[_-]", "HuggingFace"),
    (r"cohere", "Cohere"),
    (r"perplexity|\bpplx", "Perplexity"),
    (r"replicate", "Replicate"),
    (r"gemini|google\s*ai\b", "Google Gemini"),
    (r"mistral", "Mistral"),
    (r"groq", "Groq"),
    (r"together\s*ai", "Together AI"),
    (r"deepseek", "DeepSeek"),
    (r"\bxai\b|\bgrok\b", "xAI"),
    (r"fireworks", "Fireworks AI"),
    (r"langfuse", "Langfuse"),
    (r"langchain|langsmith", "LangChain"),
    (r"stability\s*ai|stable\s*diffusion", "Stability AI"),
    (r"\bai21\b", "AI21 Labs"),
    (r"voyage\s*ai", "Voyage AI"),
    (r"elevenlabs", "ElevenLabs"),
]

_COMPILED = [(re.compile(pattern, re.IGNORECASE), provider) for pattern, provider in _PROVIDER_KEYWORDS]


def resolve_ai_provider(detector_name: str) -> str | None:
    """
    Map a secret-detector/finding-type name to a canonical AI provider name.

    Returns None when the name doesn't match any known AI/LLM provider
    keyword — the overwhelming majority of secret findings (AWS, Stripe,
    Slack, database credentials, ...) correctly resolve to None here.
    """
    if not detector_name:
        return None
    for pattern, provider in _COMPILED:
        if pattern.search(detector_name):
            return provider
    return None
