"""
APK static analysis via androguard.

Extracts manifest hardening flags, exported-component exposure, dangerous
permissions, and hardcoded secrets embedded in the compiled DEX string pool —
the same class of checks tools like MobSF/QARK perform.
"""
import logging

from mobile_scan.rules import check_manifest, check_exported_components, check_permissions, check_strings_for_secrets

logger = logging.getLogger(__name__)

_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def _ns(attr: str, ns: str) -> str:
    return f"{ns}{attr}"


def _bool_attr(el, attr: str, ns: str) -> bool | None:
    val = el.get(_ns(attr, ns))
    if val is None:
        return None
    return val.lower() == "true"


def _int_attr(el, attr: str, ns: str) -> int | None:
    val = el.get(_ns(attr, ns))
    try:
        return int(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def analyze_apk(apk_path: str) -> dict:
    """Run full static analysis on a single APK file. Returns a result dict with findings."""
    from androguard.core.apk import APK, NS_ANDROID

    apk = APK(apk_path)
    package = apk.get_package() or apk_path
    app_name = apk.get_app_name() or package

    manifest_root = apk.get_android_manifest_xml()
    findings: list[dict] = []

    application_el = manifest_root.find("application") if manifest_root is not None else None
    debuggable = bool(_bool_attr(application_el, "debuggable", NS_ANDROID)) if application_el is not None else False
    allow_backup = _bool_attr(application_el, "allowBackup", NS_ANDROID) if application_el is not None else None
    uses_cleartext = _bool_attr(application_el, "usesCleartextTraffic", NS_ANDROID) if application_el is not None else None

    target_sdk = apk.get_target_sdk_version()
    min_sdk = apk.get_min_sdk_version()
    try:
        target_sdk = int(target_sdk) if target_sdk is not None else None
    except (TypeError, ValueError):
        target_sdk = None
    try:
        min_sdk = int(min_sdk) if min_sdk is not None else None
    except (TypeError, ValueError):
        min_sdk = None

    findings.extend(check_manifest(app_name, package, debuggable, allow_backup, uses_cleartext, target_sdk, min_sdk))

    components = []
    if application_el is not None:
        for tag in _COMPONENT_TAGS:
            kind = "activity" if tag == "activity-alias" else tag
            for el in application_el.findall(tag):
                name = el.get(_ns("name", NS_ANDROID), "?")
                exported = _bool_attr(el, "exported", NS_ANDROID)
                has_intent_filter = el.find("intent-filter") is not None
                permission = el.get(_ns("permission", NS_ANDROID))
                grant_uri = _bool_attr(el, "grantUriPermissions", NS_ANDROID)
                components.append({
                    "kind": kind,
                    "name": name,
                    "exported": exported,
                    "has_intent_filter": has_intent_filter,
                    "permission": permission,
                    "grant_uri_permissions": bool(grant_uri),
                })
    findings.extend(check_exported_components(package, components))

    permissions = set(apk.get_permissions() or [])
    findings.extend(check_permissions(package, permissions))

    strings: list[str] = []
    try:
        for dex in apk.get_all_dex():
            from androguard.core.dex import DEX
            d = DEX(dex)
            strings.extend(d.get_strings())
    except Exception as e:
        logger.warning(f"Failed to extract DEX strings from {apk_path}: {e}")
    findings.extend(check_strings_for_secrets(strings, package))

    return {
        "apk_path": apk_path,
        "package": package,
        "app_name": app_name,
        "target_sdk": target_sdk,
        "min_sdk": min_sdk,
        "permissions": sorted(permissions),
        "components_analyzed": len(components),
        "findings": findings,
    }
