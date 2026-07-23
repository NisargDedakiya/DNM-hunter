"""mobile_audit — static source SAST for mobile apps (Android + iOS).

Where `mobile_scan` analyses a compiled APK (needs androguard + the binary), this
reads *source* — Java/Kotlin, Swift/Objective-C, AndroidManifest.xml and
Info.plist — the way the web SAST reads server code. It targets the OWASP Mobile
Top 10 (2024) classes that are decidable from source:

    M1  Improper Credential Usage       hard-coded keys/passwords/tokens
    M4  Insufficient Input/Output Val.  SQLi (rawQuery/execSQL), WebView bridges
    M5  Insecure Communication          cleartext traffic, disabled TLS/pinning,
                                        NSAllowsArbitraryLoads
    M8  Security Misconfiguration       exported/debuggable/backup, JS bridges
    M9  Insecure Data Storage           world-readable prefs, plaintext in
                                        UserDefaults/prefs, external storage
    M10 Insufficient Cryptography       MD5/SHA1/DES/ECB/RC4, hard-coded keys/IV,
                                        weak RNG

M2/M3/M6/M7 (supply chain, auth server-side, privacy, binary hardening) need
runtime, the compiled binary, or manual review and are out of scope here.

Every finding carries an `owasp` id, a Bugcrowd `vrt`, a `cwe`, the `platform`,
and a `confidence` (firm | tentative | heuristic) — the same honesty model as the
web SAST.

CLI:  python -m mobile_audit <path> [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

CRIT, HIGH, MED, LOW = "critical", "high", "medium", "low"

_ANDROID_CODE = {".java", ".kt"}
_IOS_CODE = {".swift", ".m", ".mm", ".h"}
_ALL_CODE = _ANDROID_CODE | _IOS_CODE
_SRC_EXT = _ALL_CODE | {".xml", ".plist"}
_SKIP_DIRS = {".git", "node_modules", "build", ".gradle", "Pods", "Carthage",
              "DerivedData", "vendor", "dist", "__pycache__"}


@dataclass
class MobileFinding:
    owasp: str          # OWASP Mobile Top 10 id, e.g. "M9"
    vrt: str
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    detail: str
    cwe: str = ""
    platform: str = ""  # android | ios | both
    confidence: str = "firm"

    def to_dict(self) -> dict:
        return asdict(self)


# ── rule tables: (owasp, rule, sev, cwe, title, regex, platform, confidence) ──

# AndroidManifest.xml misconfigurations (M8 / M9 / M5)
_MANIFEST_RULES = [
    ("M8", "MA-DEBUGGABLE", HIGH, "CWE-489", "Application is debuggable in release (android:debuggable=true)",
     re.compile(r'android:debuggable\s*=\s*"true"'), "android", "firm"),
    ("M9", "MA-BACKUP", LOW, "CWE-530", "Full app backup allowed (android:allowBackup=true)",
     re.compile(r'android:allowBackup\s*=\s*"true"'), "android", "tentative"),
    ("M5", "MA-CLEARTEXT", MED, "CWE-319", "Cleartext (HTTP) traffic permitted (usesCleartextTraffic=true)",
     re.compile(r'android:usesCleartextTraffic\s*=\s*"true"'), "android", "firm"),
    ("M8", "MA-EXPORTED", MED, "CWE-926", "Component exported to other apps (android:exported=true)",
     re.compile(r'android:exported\s*=\s*"true"'), "android", "tentative"),
]

# Android code (Java/Kotlin) — M4 / M5 / M8 / M9
_ANDROID_RULES = [
    ("M9", "MA-WORLD-RW", HIGH, "CWE-732", "Shared storage created world-readable/writable",
     re.compile(r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"), "android", "firm"),
    ("M8", "MA-JS-BRIDGE", HIGH, "CWE-749", "WebView addJavascriptInterface exposes native code to JS",
     re.compile(r"\.addJavascriptInterface\s*\("), "android", "tentative"),
    ("M8", "MA-WEBVIEW-JS", LOW, "CWE-79", "WebView JavaScript enabled (XSS surface)",
     re.compile(r"\.setJavaScriptEnabled\s*\(\s*true\s*\)"), "android", "tentative"),
    ("M8", "MA-WEBVIEW-FILE", MED, "CWE-200", "WebView allows file/universal access from file URLs",
     re.compile(r"\.setAllow(FileAccessFromFileURLs|UniversalAccessFromFileURLs)\s*\(\s*true\s*\)"), "android", "firm"),
    ("M5", "MA-TRUSTALL", HIGH, "CWE-295", "TLS trust manager / hostname verifier accepts all certificates",
     re.compile(r"ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|TrustManager\s*\[\s*\]\s*\{|setDefaultHostnameVerifier\s*\(", re.IGNORECASE), "android", "firm"),
    ("M9", "MA-EXT-STORAGE", LOW, "CWE-312", "Writing to external (shared) storage",
     re.compile(r"getExternalStorage(PublicDirectory|Directory)|Environment\.getExternalStorage"), "android", "tentative"),
    ("M9", "MA-LOG-SENSITIVE", MED, "CWE-532", "Sensitive value written to logcat",
     re.compile(r"Log\.[dviwe]\s*\([^)]*(password|passwd|token|secret|apikey|api_key|session|jwt|credit)", re.IGNORECASE), "android", "heuristic"),
]

# iOS Info.plist (M5)
_PLIST_RULES = [
    ("M5", "MA-IOS-ATS", HIGH, "CWE-319", "App Transport Security disabled (NSAllowsArbitraryLoads=true)",
     re.compile(r"NSAllowsArbitraryLoads(InWebContent|ForMedia)?</key>\s*<true\s*/?>", re.IGNORECASE), "ios", "firm"),
]

# iOS code (Swift/Obj-C) — M5 / M9 / M10
_IOS_RULES = [
    ("M9", "MA-IOS-USERDEFAULTS", MED, "CWE-312", "Sensitive value stored in UserDefaults (unencrypted)",
     re.compile(r"(NSUserDefaults|UserDefaults)[^\n]{0,80}(password|passwd|token|secret|apikey|api_key|jwt|creditcard)", re.IGNORECASE), "ios", "heuristic"),
    ("M5", "MA-IOS-PINNING-OFF", HIGH, "CWE-295", "TLS certificate validation bypassed",
     re.compile(r"allowsAnyHTTPSCertificate|kSecTrustResultProceed|continueWithoutCredentialForAuthenticationChallenge|\.serverTrust\b[^\n]{0,60}(credential|proceed)", re.IGNORECASE), "ios", "firm"),
    ("M8", "MA-IOS-UIWEBVIEW", LOW, "CWE-1104", "Deprecated UIWebView used (insecure, unmaintained)",
     re.compile(r"\bUIWebView\b"), "ios", "tentative"),
    ("M9", "MA-IOS-PASTEBOARD", LOW, "CWE-200", "Sensitive value copied to the general pasteboard",
     re.compile(r"UIPasteboard\.general[^\n]{0,60}(password|token|secret|otp)", re.IGNORECASE), "ios", "heuristic"),
]

# Cryptography (both platforms' code) — M10
_CRYPTO_RULES = [
    ("M10", "MA-WEAK-HASH", MED, "CWE-327", "Weak/broken hash for a security use (MD5/SHA1)",
     re.compile(r"\b(MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-?1)[\"']|CC_MD5|CC_SHA1|\.md5\b|MD5\(|Insecure\.MD5|Insecure\.SHA1)", re.IGNORECASE), "both", "tentative"),
    ("M10", "MA-WEAK-CIPHER", HIGH, "CWE-327", "Broken/weak cipher (DES/3DES/RC4 or ECB mode)",
     re.compile(r"\b(DES|DESede|3DES|RC4|ARC4)\b|/ECB/|kCCAlgorithmDES|kCCAlgorithm3DES|kCCOptionECBMode|Cipher\.getInstance\s*\(\s*[\"'][^\"']*ECB", re.IGNORECASE), "both", "firm"),
    ("M10", "MA-HARDCODE-KEY", HIGH, "CWE-321", "Hard-coded cryptographic key / IV in source",
     re.compile(r"(SecretKeySpec|IvParameterSpec|GCMParameterSpec)\s*\(\s*[\"']|(SecretKeySpec|IvParameterSpec)\s*\(\s*\w+\.getBytes|kCCKeySizeAES\d+[^\n]*[\"'][A-Za-z0-9]{8,}[\"']"), "both", "tentative"),
    ("M10", "MA-WEAK-RNG", LOW, "CWE-330", "Insecure RNG used for a security value",
     re.compile(r"\bnew\s+Random\s*\(|Math\.random\s*\(|\brandom\s*\(\s*\)|\brand\s*\(\s*\)|arc4random_uniform\s*\(\s*0"), "both", "tentative"),
]

# Hard-coded credentials / secrets (M1) — both platforms' code
_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|secret|password|passwd|pwd|auth[_-]?token|access[_-]?token|bearer|private[_-]?key|aws_secret)\b\s*[=:]\s*[\"']([^\"']{8,})[\"']")
_SECRET_PLACEHOLDER = re.compile(r"(?i)your|example|changeme|placeholder|xxxx|<[^>]+>|\$\{|todo|dummy|test123|000000")

# Android SQLi sinks (M4) — a raw query built by string concatenation
_SQLI_SINK = re.compile(r"\.(rawQuery|execSQL|rawQueryWithFactory)\s*\(")
_JAVA_CONCAT = re.compile(r"[\"']\s*\+|\+\s*[\"']")


def scan_code(text: str, file: str) -> list[MobileFinding]:
    findings: list[MobileFinding] = []
    suffix = Path(file).suffix.lower()
    name = Path(file).name.lower()
    is_manifest = name == "androidmanifest.xml" or (suffix == ".xml" and "manifest" in text[:400].lower())
    is_plist = suffix == ".plist"
    is_android_code = suffix in _ANDROID_CODE
    is_ios_code = suffix in _IOS_CODE
    is_code = suffix in _ALL_CODE

    rules: list = []
    if is_manifest:
        rules += _MANIFEST_RULES
    if is_android_code:
        rules += _ANDROID_RULES
    if is_plist:
        rules += _PLIST_RULES
    if is_ios_code:
        rules += _IOS_RULES
    if is_code:
        rules += _CRYPTO_RULES

    seen: set[tuple] = set()

    def add(f: MobileFinding) -> None:
        if (f.rule_id, f.line) in seen:
            return
        seen.add((f.rule_id, f.line))
        findings.append(f)

    for i, raw in enumerate(text.splitlines(), 1):
        line = raw
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "*", "/*", "#", "<!--")):
            continue

        for owasp, rule, sev, cwe, title, rx, platform, conf in rules:
            if rx.search(line):
                add(MobileFinding(owasp, _vrt_for(owasp, rule), rule, sev, title, file, i,
                                  f"{title}.", cwe, platform, conf))

        # M1 — hard-coded secret (code files only, skip obvious placeholders)
        if is_code:
            m = _SECRET_RE.search(line)
            if m and not _SECRET_PLACEHOLDER.search(m.group(2)):
                add(MobileFinding("M1", "insecure_data_storage.server_side_credentials_storage",
                                  "MA-SECRET", HIGH, f"Hard-coded {m.group(1)} in source",
                                  file, i, "Hard-coded credential/secret in source.", "CWE-798",
                                  "android" if is_android_code else "ios", "tentative"))

        # M4 — SQL injection via a concatenated raw query (Android)
        if is_android_code and _SQLI_SINK.search(line) and _JAVA_CONCAT.search(line):
            add(MobileFinding("M4", "server_side_injection.sql_injection", "MA-SQLI", HIGH,
                              "SQL query built by string concatenation (SQL injection)",
                              file, i, "Raw SQL assembled from concatenation — use parameterised "
                              "selectionArgs / bound parameters.", "CWE-89", "android", "firm"))

    return findings


_VRT_MAP = {
    "M1": "insecure_data_storage.server_side_credentials_storage",
    "M4": "server_side_injection.sql_injection",
    "M5": "insecure_data_transport.cleartext",
    "M8": "mobile_security_misconfiguration",
    "M9": "insecure_data_storage",
    "M10": "cryptographic_weakness.broken_cryptography",
}


def _vrt_for(owasp: str, rule: str) -> str:
    if rule in ("MA-JS-BRIDGE", "MA-WEBVIEW-JS", "MA-WEBVIEW-FILE"):
        return "mobile_security_misconfiguration"
    if rule in ("MA-TRUSTALL", "MA-IOS-PINNING-OFF"):
        return "insecure_data_transport.tls_verify_disabled"
    if rule == "MA-WEAK-HASH":
        return "cryptographic_weakness.weak_hash"
    if rule == "MA-WEAK-RNG":
        return "cryptographic_weakness.insufficient_entropy"
    return _VRT_MAP.get(owasp, "mobile_security_misconfiguration")


def scan_tree(root: str | Path) -> list[MobileFinding]:
    root = Path(root)
    out: list[MobileFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SRC_EXT:
            continue
        if any(p in _SKIP_DIRS for p in path.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        out.extend(scan_code(text, str(path.relative_to(root))))
    return out


def _main() -> int:
    ap = argparse.ArgumentParser(description="Mobile source SAST — OWASP Mobile Top 10 (Android + iOS).")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    p = Path(args.path)
    findings = scan_tree(p) if p.is_dir() else scan_code(p.read_text(errors="replace"), str(p))
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return 0
    for f in sorted(findings, key=lambda x: (x.severity, x.owasp)):
        print(f"  [{f.severity:8}] {f.owasp:3} {f.confidence:9} {f.rule_id:18} {f.file}:{f.line}  {f.title}")
    print(f"\n{len(findings)} findings")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
