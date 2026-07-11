"""Static analysis rules for Android APKs (permissions, manifest hardening, secrets)."""
import re

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Permissions considered high-risk when granted (data access / device control) —
# mirrors Android's own "dangerous" permission groups plus a few high-signal extras.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Read all SMS messages (2FA code interception risk).",
    "android.permission.RECEIVE_SMS": "Intercept incoming SMS messages (2FA code interception risk).",
    "android.permission.READ_CALL_LOG": "Read call history.",
    "android.permission.READ_CONTACTS": "Read the user's contact list.",
    "android.permission.ACCESS_FINE_LOCATION": "Access precise GPS location.",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Track location even when the app is not in use.",
    "android.permission.CAMERA": "Access the camera.",
    "android.permission.RECORD_AUDIO": "Record audio from the microphone.",
    "android.permission.READ_EXTERNAL_STORAGE": "Read shared/external storage.",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write shared/external storage.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Draw over other apps (overlay/tapjacking risk).",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Install other APKs (sideloading risk).",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Register as an Accessibility Service — can read screen content and inject input across all other apps (common malware vector).",
}

# Combinations that materially increase exfiltration risk when present together.
_SMS_PERMS = {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"}
_INTERNET_PERM = "android.permission.INTERNET"

_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Firebase URL", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("Generic Bearer/API token assignment", re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[\"']([A-Za-z0-9+/_\-]{20,})[\"']")),
    ("Private key header", re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
]

_MULTIDEX_STRING_SAMPLE_LIMIT = 20000


def check_manifest(app_name: str, package: str, debuggable: bool, allow_backup: bool | None,
                    uses_cleartext_traffic: bool | None, target_sdk: int | None,
                    min_sdk: int | None) -> list[dict]:
    findings = []

    if debuggable:
        findings.append(_finding("MOBILE-001", SEVERITY_CRITICAL, "Application is debuggable",
                                  f"{package}: android:debuggable=\"true\" in a release build allows attaching a debugger and dumping runtime state/memory on any device.",
                                  package))

    if allow_backup is not False:
        findings.append(_finding("MOBILE-002", SEVERITY_MEDIUM, "Backup not disabled",
                                  f"{package}: android:allowBackup is not explicitly set to false, allowing app data extraction via `adb backup` on debuggable/rooted devices.",
                                  package))

    if uses_cleartext_traffic:
        findings.append(_finding("MOBILE-003", SEVERITY_HIGH, "Cleartext traffic explicitly allowed",
                                  f"{package}: android:usesCleartextTraffic=\"true\" permits plaintext HTTP, exposing traffic to on-path interception.",
                                  package))
    elif uses_cleartext_traffic is None and target_sdk is not None and target_sdk < 28:
        findings.append(_finding("MOBILE-003b", SEVERITY_MEDIUM, "Cleartext traffic allowed by default (legacy targetSdk)",
                                  f"{package}: targetSdkVersion {target_sdk} is below 28, where cleartext HTTP is allowed by default absent an explicit Network Security Config.",
                                  package))

    if min_sdk is not None and min_sdk < 21:
        findings.append(_finding("MOBILE-007", SEVERITY_LOW, "Very low minSdkVersion",
                                  f"{package}: minSdkVersion {min_sdk} supports Android versions that no longer receive security patches.",
                                  package))

    return findings


def check_exported_components(package: str, components: list[dict]) -> list[dict]:
    """components: list of {kind, name, exported, has_intent_filter, permission, grant_uri_permissions}."""
    findings = []
    for c in components:
        is_exported = c["exported"] if c["exported"] is not None else c["has_intent_filter"]
        if not is_exported:
            continue
        if c.get("permission"):
            continue  # protected by a signature/custom permission — not flagged

        if c["kind"] == "provider" and c.get("grant_uri_permissions"):
            findings.append(_finding("MOBILE-008", SEVERITY_CRITICAL, "Exported ContentProvider grants URI permissions with no protection",
                                      f"{package}: provider {c['name']} is exported, sets grantUriPermissions, and requires no permission — a classic path-traversal/data-leak vector (cf. StageFright-class provider bugs).",
                                      c["name"]))
        else:
            severity = SEVERITY_HIGH if c["kind"] in ("provider", "service") else SEVERITY_MEDIUM
            findings.append(_finding("MOBILE-004", severity, f"Exported {c['kind']} with no permission requirement",
                                      f"{package}: {c['kind']} {c['name']} is exported (android:exported=\"true\"{' via intent-filter' if c['exported'] is None else ''}) and declares no android:permission, so any app on the device can invoke it.",
                                      c["name"]))
    return findings


def check_permissions(package: str, permissions: set[str]) -> list[dict]:
    findings = []
    for perm, desc in DANGEROUS_PERMISSIONS.items():
        if perm in permissions:
            findings.append(_finding("MOBILE-005", SEVERITY_LOW, f"Dangerous permission requested: {perm.split('.')[-1]}",
                                      f"{package}: requests {perm} — {desc}",
                                      perm))

    if (permissions & _SMS_PERMS) and _INTERNET_PERM in permissions:
        findings.append(_finding("MOBILE-005b", SEVERITY_MEDIUM, "SMS access combined with network access",
                                  f"{package}: requests SMS read/receive permissions together with INTERNET — a common pattern in SMS-stealing/2FA-interception malware; verify legitimate need.",
                                  package))

    return findings


def check_strings_for_secrets(strings: list[str], package: str) -> list[dict]:
    findings = []
    seen = set()
    for s in strings[:_MULTIDEX_STRING_SAMPLE_LIMIT]:
        for label, pattern in _SECRET_PATTERNS:
            m = pattern.search(s)
            if m:
                key = (label, m.group(0)[:40])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding("MOBILE-006", SEVERITY_CRITICAL, f"Hardcoded secret in app strings: {label}",
                                          f"{package}: a string constant embedded in the compiled app matches the {label} pattern — decompiling the APK trivially recovers it.",
                                          label, evidence=m.group(0)[:60]))
    return findings


def _finding(rule_id, severity, title, message, resource, evidence=None):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "message": message,
        "resource": resource,
        "evidence": evidence,
    }
