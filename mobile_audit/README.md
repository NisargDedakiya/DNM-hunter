# mobile_audit — Mobile Source SAST (Android + iOS)

Static analysis of **mobile app source** — Java/Kotlin, Swift/Objective-C,
`AndroidManifest.xml` and `Info.plist` — mapped to the **OWASP Mobile Top 10
(2024)**. Where `mobile_scan` analyses a compiled `.apk` (needs androguard + the
binary), this reads source the way the web SAST does, so it runs inside a normal
repo scan with zero heavy dependencies.

## OWASP Mobile Top 10 coverage

| # | Category | Covered | Examples |
|---|----------|:---:|----------|
| M1 | Improper Credential Usage | ✅ | hard-coded API keys / passwords / tokens (`MA-SECRET`) |
| M2 | Inadequate Supply Chain | — | needs dependency/build analysis (not source) |
| M3 | Insecure Auth/Authorization | — | server-side behaviour (manual/runtime) |
| M4 | Insufficient Input/Output Validation | ✅ | concatenated `rawQuery`/`execSQL` (`MA-SQLI`), JS bridges |
| M5 | Insecure Communication | ✅ | cleartext traffic, trust-all TLS, `NSAllowsArbitraryLoads`, pinning off |
| M6 | Inadequate Privacy Controls | — | PII/consent review |
| M7 | Insufficient Binary Protections | — | checked on the compiled binary (`binary_audit`/`mobile_scan`) |
| M8 | Security Misconfiguration | ✅ | `debuggable`/`exported`/`allowBackup`, WebView file access, `UIWebView` |
| M9 | Insecure Data Storage | ✅ | world-readable prefs, plaintext `UserDefaults`, sensitive logs, pasteboard |
| M10 | Insufficient Cryptography | ✅ | MD5/SHA1/DES/ECB/RC4, hard-coded keys/IV, weak RNG |

**6 of 10** are decidable from source; M2/M3/M6/M7 need the binary, runtime, or
a manual review and are honestly marked out of scope (see `vrt/owasp.py`).

## Precision

- **Taint-lite SQLi**: `rawQuery`/`execSQL` only fires when the query is built by
  string concatenation; a parameterised `rawQuery("… ?", selectionArgs)` is not
  flagged.
- **Secret detection skips placeholders** (`YOUR_API_KEY`, `changeme`, `<...>`).
- **Confidence** on every finding: `firm` (definitive misconfig — `debuggable`,
  trust-all TLS, world-readable storage), `tentative` (context-dependent —
  `exported=true` may carry a permission), `heuristic` (a lead — a sensitive-
  looking value in a log/UserDefaults line).

## Usage

```bash
python -m mobile_audit path/to/app --json     # or: nh-mobile-audit
```

Also runs automatically inside `repo_scan` (kind `mobile-source`) and therefore
in the full `nh-scan` suite and the webapp's repo scan.

## Languages

`.java`, `.kt` (Android), `.swift`, `.m`, `.mm`, `.h` (iOS), plus
`AndroidManifest.xml` and `Info.plist`. Build/output dirs (`build`, `Pods`,
`DerivedData`, `.gradle`, …) are skipped.
