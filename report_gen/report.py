"""Professional report generation from scanner-suite results.

Turns a `scanner_suite.SuiteResult` (or any iterable of findings exposing the
same fields) into a submission-ready report: every finding is enriched with a
CVSS v3.1 score, a CWE, its VRT category, verification/reproduction steps,
remediation, and references — then rendered as Markdown (for bounty submissions
and issue trackers) or a self-contained, printable HTML report (for client
deliverables).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .knowledge import guidance_for

try:
    from common.impact.cvss import base_score, severity_rating
    _HAVE_CVSS = True
except Exception:  # pragma: no cover - common may be unavailable in isolation
    _HAVE_CVSS = False

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {"critical": "#b3123b", "high": "#d1471c", "medium": "#c08a00",
              "low": "#2b6cb0", "info": "#5a6270"}


@dataclass
class EnrichedFinding:
    scanner: str
    rule_id: str
    title: str
    severity: str
    file: str
    line: int | None
    detail: str
    vrt: str
    cwe: str
    cvss_score: float
    cvss_vector: str
    verification: str
    remediation: str
    references: list[str] = field(default_factory=list)


@dataclass
class Report:
    title: str
    target: str
    generated: str
    findings: list[EnrichedFinding]
    summary: dict
    errors: list[str] = field(default_factory=list)


def _extract_cwe(detail: str) -> str:
    m = re.search(r"(CWE-\d+)", detail)
    return m.group(1) if m else ""


def _score(vector: str, severity: str) -> tuple[float, str]:
    if _HAVE_CVSS:
        try:
            r = base_score(vector)
            return r.base_score, vector
        except Exception:
            pass
    # deterministic fallback score if the CVSS engine is unavailable
    return {"critical": 9.8, "high": 7.5, "medium": 5.4, "low": 3.1, "info": 0.0}.get(severity, 5.0), vector


def enrich(findings) -> list[EnrichedFinding]:
    out: list[EnrichedFinding] = []
    for f in findings:
        g = guidance_for(f.rule_id, f.severity)
        score, vector = _score(g.cvss_vector, f.severity)
        # CVSS is the authoritative severity in the report, so the label and the
        # numeric score never contradict (no "High, CVSS 9.8").
        sev = severity_rating(score).lower() if _HAVE_CVSS else f.severity
        cwe = _extract_cwe(getattr(f, "detail", "") or "")
        # references: curated + the CWE we found + the VRT id
        refs = list(g.references)
        if cwe and not any(cwe in r for r in refs):
            refs.append(cwe)
        out.append(EnrichedFinding(
            scanner=getattr(f, "scanner", ""),
            rule_id=f.rule_id,
            title=f.title,
            severity=sev,
            file=getattr(f, "file", "") or "",
            line=getattr(f, "line", None),
            detail=getattr(f, "detail", "") or "",
            vrt=getattr(f, "vrt", "") or "",
            cwe=cwe,
            cvss_score=score,
            cvss_vector=vector,
            verification=g.verification,
            remediation=g.remediation,
            references=refs,
        ))
    out.sort(key=lambda e: (_SEV_ORDER.get(e.severity, 9), -e.cvss_score))
    return out


def build_report(result, title: str = "Security Assessment Report") -> Report:
    findings = enrich(result.findings)
    from collections import Counter
    by_sev = Counter(f.severity for f in findings)
    summary = {
        "total": len(findings),
        "bySeverity": {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "highestSeverity": min((f.severity for f in findings),
                               key=lambda s: _SEV_ORDER.get(s, 9), default="none"),
        "maxCvss": max((f.cvss_score for f in findings), default=0.0),
    }
    return Report(
        title=title,
        target=getattr(result, "target", ""),
        generated=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        findings=findings,
        summary=summary,
        errors=list(getattr(result, "errors", []) or []),
    )


# ─────────────────────────── Markdown ───────────────────────────

def to_markdown(report: Report) -> str:
    s = report.summary
    lines = [
        f"# {report.title}",
        "",
        f"- **Target:** {report.target}",
        f"- **Generated:** {report.generated}",
        "- **Tool:** NisargHunter AI security scanner suite",
        "",
        "## Executive summary",
        "",
        f"The assessment identified **{s['total']} finding(s)**. Highest severity: "
        f"**{s['highestSeverity']}** (max CVSS {s['maxCvss']}).",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if s["bySeverity"].get(sev):
            lines.append(f"| {sev.capitalize()} | {s['bySeverity'][sev]} |")
    lines += ["", "## Findings overview", "",
              "| # | Severity | CVSS | Finding | Location | VRT |",
              "|---|----------|------|---------|----------|-----|"]
    for i, f in enumerate(report.findings, 1):
        loc = f"{f.file}:{f.line}" if f.line else (f.file or "—")
        lines.append(f"| {i} | {f.severity.capitalize()} | {f.cvss_score} | {f.title} | `{loc}` | {f.vrt or '—'} |")

    lines += ["", "## Detailed findings", ""]
    for i, f in enumerate(report.findings, 1):
        loc = f"{f.file}:{f.line}" if f.line else (f.file or "—")
        lines += [
            f"### {i}. {f.title}",
            "",
            f"- **Severity:** {f.severity.capitalize()}  |  **CVSS v3.1:** {f.cvss_score} "
            f"(`{f.cvss_vector}`)",
            f"- **Rule:** `{f.rule_id}`  |  **Scanner:** {f.scanner}",
            f"- **Location:** `{loc}`",
            f"- **Classification:** VRT `{f.vrt or '—'}`" + (f"  |  {f.cwe}" if f.cwe else ""),
            "",
            f"**Description.** {f.detail}",
            "",
            f"**Verification / reproduction.** {f.verification}",
            "",
            f"**Remediation.** {f.remediation}",
            "",
        ]
        if f.references:
            lines.append("**References.** " + ", ".join(f.references))
            lines.append("")
    if report.errors:
        lines += ["## Scan notes", ""] + [f"- {e}" for e in report.errors] + [""]
    lines += ["---", "",
              "_Findings are produced by automated static/dynamic analysis and should be "
              "manually verified before submission or remediation sign-off._"]
    return "\n".join(lines)


# ─────────────────────────── HTML ───────────────────────────

def to_html(report: Report) -> str:
    e = html.escape
    s = report.summary
    sev_chips = "".join(
        f'<span class="chip" style="--c:{_SEV_COLOR[sev]}">{sev.capitalize()}: '
        f'{s["bySeverity"][sev]}</span>'
        for sev in ("critical", "high", "medium", "low", "info") if s["bySeverity"].get(sev)
    )
    rows = ""
    for i, f in enumerate(report.findings, 1):
        loc = f"{f.file}:{f.line}" if f.line else (f.file or "—")
        rows += (
            f'<tr><td>{i}</td>'
            f'<td><span class="sev" style="--c:{_SEV_COLOR.get(f.severity, "#888")}">'
            f'{f.severity.capitalize()}</span></td>'
            f'<td class="num">{f.cvss_score}</td><td>{e(f.title)}</td>'
            f'<td><code>{e(loc)}</code></td><td>{e(f.vrt or "—")}</td></tr>'
        )
    details = ""
    for i, f in enumerate(report.findings, 1):
        loc = f"{f.file}:{f.line}" if f.line else (f.file or "—")
        refs = ", ".join(e(r) for r in f.references) or "—"
        details += f"""
    <article class="finding">
      <h3><span class="sev" style="--c:{_SEV_COLOR.get(f.severity, '#888')}">{f.severity.capitalize()}</span>
          {i}. {e(f.title)}</h3>
      <div class="meta">
        <span><strong>CVSS v3.1</strong> {f.cvss_score} <code>{e(f.cvss_vector)}</code></span>
        <span><strong>Rule</strong> <code>{e(f.rule_id)}</code></span>
        <span><strong>Scanner</strong> {e(f.scanner)}</span>
        <span><strong>Location</strong> <code>{e(loc)}</code></span>
        <span><strong>VRT</strong> {e(f.vrt or '—')}</span>
        {f'<span><strong>CWE</strong> {e(f.cwe)}</span>' if f.cwe else ''}
      </div>
      <p><strong>Description.</strong> {e(f.detail)}</p>
      <p><strong>Verification / reproduction.</strong> {e(f.verification)}</p>
      <p><strong>Remediation.</strong> {e(f.remediation)}</p>
      <p class="refs"><strong>References.</strong> {refs}</p>
    </article>"""

    notes = ""
    if report.errors:
        notes = "<section><h2>Scan notes</h2><ul>" + \
                "".join(f"<li>{e(x)}</li>" for x in report.errors) + "</ul></section>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(report.title)}</title>
<style>
  :root {{ --bg:#fff; --fg:#1a1d24; --muted:#5a6270; --line:#e6e8ee; --accent:#0b5cad; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#14171d; --fg:#e7e9ee; --muted:#9aa2b1; --line:#262b34; --accent:#5aa2e6; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:40px 24px 80px; }}
  h1 {{ font-size:28px; margin:0 0 4px; }}
  h2 {{ font-size:20px; margin:36px 0 12px; padding-bottom:6px; border-bottom:2px solid var(--line); }}
  h3 {{ font-size:17px; margin:0 0 10px; }}
  .sub {{ color:var(--muted); margin:0 0 20px; }}
  .chips {{ display:flex; gap:8px; flex-wrap:wrap; margin:16px 0; }}
  .chip {{ background:color-mix(in srgb, var(--c) 14%, transparent); color:var(--c);
    border:1px solid color-mix(in srgb, var(--c) 40%, transparent);
    padding:4px 10px; border-radius:999px; font-weight:600; font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; margin:8px 0; font-size:14px; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  td.num {{ font-variant-numeric:tabular-nums; }}
  .sev {{ color:var(--c); font-weight:700; }}
  code {{ background:color-mix(in srgb, var(--fg) 8%, transparent); padding:1px 5px;
    border-radius:4px; font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .finding {{ border:1px solid var(--line); border-left:4px solid var(--line);
    border-radius:8px; padding:16px 18px; margin:14px 0; }}
  .finding .meta {{ display:flex; flex-wrap:wrap; gap:6px 18px; color:var(--muted);
    font-size:13px; margin:0 0 12px; }}
  .finding p {{ margin:8px 0; }}
  .refs {{ color:var(--muted); font-size:13px; }}
  .disclaimer {{ color:var(--muted); font-size:13px; margin-top:32px;
    border-top:1px solid var(--line); padding-top:16px; }}
  @media print {{ .finding {{ break-inside:avoid; }} }}
</style></head>
<body><div class="wrap">
  <h1>{e(report.title)}</h1>
  <p class="sub">Target: <strong>{e(report.target)}</strong> &nbsp;·&nbsp; {e(report.generated)}
     &nbsp;·&nbsp; NisargHunter AI</p>

  <h2>Executive summary</h2>
  <p>The assessment identified <strong>{s['total']} finding(s)</strong>. Highest severity:
     <strong>{e(s['highestSeverity'])}</strong> (max CVSS {s['maxCvss']}).</p>
  <div class="chips">{sev_chips}</div>

  <h2>Findings overview</h2>
  <table><thead><tr><th>#</th><th>Severity</th><th>CVSS</th><th>Finding</th>
    <th>Location</th><th>VRT</th></tr></thead><tbody>{rows}</tbody></table>

  <h2>Detailed findings</h2>
  {details}
  {notes}

  <p class="disclaimer">Findings are produced by automated static/dynamic analysis and should be
    manually verified before submission or remediation sign-off.</p>
</div></body></html>"""
