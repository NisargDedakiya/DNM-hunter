---
name: Mobile APK Static Analysis
description: Reference for static review of Android APKs — manifest hardening gaps, unprotected exported components, dangerous permission grants, and hardcoded secrets in the compiled DEX string pool.
---

# Mobile APK Static Analysis

Reference for static analysis of an in-scope Android application. Everything here is offline decompilation/introspection of the APK the client provided or that is otherwise legitimately obtainable (e.g. the client's own build artifact, or a Play Store download of their own listed app) — no device, emulator, or live app interaction is required for this pass. Dynamic testing (Frida hooking, runtime traffic interception) is a separate, deeper phase once static findings narrow the target.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Run the bundled scanner | `mobile_scan` module | `PROJECT_ID=... python mobile_scan/main.py`; reads every `.apk` uploaded for the project. |
| Pull findings from the graph | `query_graph` | `MATCH (a:MobileApp)-[:HAS_FINDING]->(f:MobileFinding) RETURN a, f`. |
| Manual manifest inspection | `execute_code` (androguard) | `from androguard.core.apk import APK; apk = APK(path)`. |
| Decompile to Java/Smali for deeper review | `kali_shell jadx` / `apktool` | `jadx -d out/ app.apk`; `apktool d app.apk -o out/`. |

## Attack matrix

### Manifest hardening

| Class | Signal | Impact |
|---|---|---|
| Debuggable build | `android:debuggable="true"` | Any device can attach a debugger and dump runtime state/memory, regardless of root |
| Backup not disabled | `android:allowBackup` unset or `true` | `adb backup` extracts app data on a debuggable or rooted device without exploiting anything else |
| Cleartext traffic | `android:usesCleartextTraffic="true"`, or `targetSdkVersion < 28` with no explicit Network Security Config | Plaintext HTTP is reachable, exposing traffic to on-path interception |
| Low `minSdkVersion` | `< 21` | Supports OS versions no longer receiving security patches — widens the realistic attack surface |

### Exported components

| Class | Signal | Impact |
|---|---|---|
| Unprotected exported activity/service/receiver | `android:exported="true"` (or implied by an `<intent-filter>` with no explicit `exported="false"`) and no `android:permission` | Any other app on the device can launch/bind/broadcast to it directly |
| Exported ContentProvider + `grantUriPermissions` | `exported="true"`, `grantUriPermissions="true"`, no `android:permission` | Classic path-traversal/arbitrary-file-read vector (cf. the historical StageFright-class provider bugs) — check `<path-permission>`/`<grant-uri-permission>` scoping carefully |

### Permissions

Flag dangerous individual grants (`READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, `CAMERA`, `RECORD_AUDIO`, `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`, `BIND_ACCESSIBILITY_SERVICE`), but weight *combinations* higher than any single grant — e.g. SMS read/receive permissions together with `INTERNET` is a textbook 2FA-interception/exfiltration pattern worth flagging even if each permission looks individually justifiable.

### Hardcoded secrets

Pull every string constant out of the DEX pool (`androguard`'s `DEX.get_strings()`) and pattern-match for:

- AWS access keys (`AKIA[0-9A-Z]{16}`)
- Google API keys (`AIza...`)
- Firebase database URLs (`*.firebaseio.com`) — often reachable with no auth if security rules were never configured
- Generic `api_key`/`secret`/`token` string assignments
- PEM private key headers
- Slack tokens (`xox[baprs]-...`)

Anything embedded in the compiled app is trivially recoverable by decompiling the APK — treat these as confirmed exposure, not "requires further validation."

## Validation shape

A clean mobile finding shows:

1. The exact manifest attribute or DEX string constant, with file/component name.
2. For exported components: whether the component was reached via explicit `exported="true"` or inferred from an intent-filter with no `exported="false"` override — state which, since it affects how confidently a fix can be scoped.
3. For secrets: the pattern matched and a truncated sample (never the full secret value in a shared report) plus the recommendation to treat it as compromised and rotate, since decompilation is trivial and unauthenticated.
4. Package name and app version so remediation can confirm the fix landed in the next build.

## False positives

- Exported activities that are intentionally public entry points (deep-link handlers, share targets) with no sensitive data path reachable from them — note as informational, not a vulnerability, unless a concrete data-exposure or privilege path is demonstrated.
- `allowBackup` unset on apps with `android:fullBackupOnly="false"` and no sensitive data ever written outside `EncryptedSharedPreferences`/Keystore-backed storage.
- String-pool matches on obvious test/placeholder values (`AKIAIOSFODNN7EXAMPLE` is AWS's own documented example key, not a real credential — always confirm a matched "secret" isn't a well-known placeholder before reporting it as critical).
- `usesCleartextTraffic` implied-default flags on apps whose `targetSdkVersion` is genuinely pinned low for legitimate device-compatibility reasons and that layer TLS pinning on top regardless — downgrade severity, don't drop the finding.

## Hand-off

```
mobile_scan/main.py -> Neo4j (MobileScan -> MobileApp -> MobileFinding)
Hardcoded secret -> cross-reference against trufflehog_scan/cloud_recon for the same org (was it also committed to a repo / does it unlock a real bucket?)
Exported component with a concrete data path -> dynamic verification phase (adb am start/broadcast, or Frida) once explicitly authorized
```
