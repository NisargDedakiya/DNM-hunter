#!/usr/bin/env python3
"""
NisargHunter AI - Mobile APK Static Analysis Main Entry Point
======================================================
Analyzes every .apk uploaded for a project (via the webapp's
/api/mobile-scan/[projectId]/upload endpoint, backed by the shared
mobile-scan-uploads volume) for manifest hardening gaps, unprotected
exported components, dangerous permissions, and hardcoded secrets embedded
in the compiled DEX string pool.

Usage:
    PROJECT_ID=xxx WEBAPP_API_URL=http://localhost:3000 python mobile_scan/main.py
"""
import logging
import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

# androguard logs at DEBUG via loguru by default; keep scan output readable.
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(sys.stderr, level="WARNING")
except ImportError:
    pass

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from mobile_scan.project_settings import get_setting, load_project_settings
    from mobile_scan.analyzer import analyze_apk
except ImportError:
    from project_settings import get_setting, load_project_settings
    from analyzer import analyze_apk

PROJECT_ID = os.environ.get("PROJECT_ID", "")
UPLOAD_PATH = os.environ.get("MOBILE_SCAN_UPLOAD_PATH", "/data/mobile-scan-uploads")

logger = logging.getLogger(__name__)


def run_mobile_scan(project_id: str) -> dict:
    upload_dir = Path(UPLOAD_PATH) / project_id
    print("\n" + "=" * 70)
    print("           NisargHunter AI - Mobile APK Static Analysis")
    print("=" * 70)
    print(f"  Upload directory: {upload_dir}")
    print("=" * 70 + "\n")

    if not upload_dir.exists():
        return {"error": f"No uploads found for project {project_id}"}

    apk_paths = sorted(upload_dir.glob("*.apk"))
    if not apk_paths:
        return {"error": "No .apk files found for this project"}

    apps = []
    errors = []
    for apk_path in apk_paths:
        print(f"[*] Analyzing {apk_path.name}...")
        try:
            result = analyze_apk(str(apk_path))
            apps.append(result)
            print(f"    -> {result['package']}: {len(result['findings'])} findings")
        except Exception as e:
            logger.warning(f"Failed to analyze {apk_path.name}: {e}")
            errors.append(f"{apk_path.name}: {e}")

    total_findings = sum(len(a["findings"]) for a in apps)
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for app in apps:
        for f in app["findings"]:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    result = {
        "scan_metadata": {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "project_id": project_id,
            "apks_analyzed": len(apps),
        },
        "apps": apps,
        "statistics": {
            "apks_analyzed": len(apps),
            "total_findings": total_findings,
            "by_severity": by_severity,
            "errors": errors,
        },
    }

    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"mobile_scan_{project_id}.json"
    output_file.write_text(json.dumps(result, indent=2))

    print("\n" + "=" * 70)
    print("                    SCAN SUMMARY")
    print("=" * 70)
    print(f"  APKs analyzed:   {len(apps)}")
    print(f"  Total findings:  {total_findings}")
    print(f"  By severity:     {by_severity}")
    print("=" * 70 + "\n")

    user_id = os.environ.get("USER_ID", "")
    try:
        from graph_db import Neo4jClient

        print("[*] Updating Neo4j graph with mobile scan results...")
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                graph_client.update_graph_from_mobile_scan(result, user_id, project_id)
                print("[+] Graph database updated successfully")
            else:
                print("[!] Could not connect to Neo4j - skipping graph update")
    except ImportError:
        print("[!] Neo4j client not available - skipping graph update")
    except Exception as e:
        print(f"[!] Graph DB update failed (non-fatal): {e}")

    return {"findings_count": total_findings, "statistics": result["statistics"], "output_file": str(output_file)}


def main():
    if not PROJECT_ID:
        print("[!] ERROR: PROJECT_ID environment variable not set")
        return 1

    load_project_settings(PROJECT_ID)

    start_time = datetime.now()
    try:
        results = run_mobile_scan(project_id=PROJECT_ID)
        if "error" in results:
            print(f"\n[!] Scan failed: {results['error']}")
            return 1
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        raise

    duration = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Total scan time: {duration:.2f} seconds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
