#!/usr/bin/env python3
"""
NisargHunter AI - Cloud Storage Bucket Enumeration Main Entry Point
======================================================
Generates candidate bucket names from seed words and probes AWS S3, GCS, and
Azure Blob Storage with unauthenticated, read-only requests to detect public
exposure.

Usage:
    PROJECT_ID=xxx WEBAPP_API_URL=http://localhost:3000 python cloud_recon/main.py
"""
import os
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from cloud_recon.project_settings import get_setting, load_project_settings
    from cloud_recon.runner import CloudReconRunner
except ImportError:
    from project_settings import get_setting, load_project_settings
    from runner import CloudReconRunner

PROJECT_ID = os.environ.get("PROJECT_ID", "")


def run_cloud_recon(project_id: str) -> dict:
    seeds_raw = get_setting("CLOUD_RECON_SEEDS", "")
    providers_raw = get_setting("CLOUD_RECON_PROVIDERS", "aws_s3,gcs,azure_blob")

    seeds = [s.strip() for s in seeds_raw.split(",") if s.strip()]
    providers = [p.strip() for p in providers_raw.split(",") if p.strip()]

    print("\n" + "=" * 70)
    print("           NisargHunter AI - Cloud Storage Bucket Enumeration")
    print("=" * 70)
    print(f"  Seeds:     {seeds or '(none)'}")
    print(f"  Providers: {providers}")
    print("=" * 70 + "\n")

    if not seeds:
        print("[!] ERROR: No seed words configured")
        return {"error": "No seed words configured (set org/product/domain names in project settings)"}

    runner = CloudReconRunner(seeds=seeds, project_id=project_id, providers=providers)
    findings = runner.run()

    print("\n" + "=" * 70)
    print("                    SCAN SUMMARY")
    print("=" * 70)
    print(f"  Candidates checked: {runner.stats['candidates_checked']}")
    print(f"  Buckets found:      {runner.stats['buckets_found']}")
    print(f"  By exposure:        {runner.stats['by_exposure']}")
    print(f"  By provider:        {runner.stats['by_provider']}")
    print("=" * 70 + "\n")

    user_id = os.environ.get("USER_ID", "")
    if runner.output_file and Path(runner.output_file).exists():
        try:
            import json
            from graph_db import Neo4jClient

            with open(runner.output_file) as f:
                cloud_data = json.load(f)

            print("[*] Updating Neo4j graph with cloud recon results...")
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    graph_client.update_graph_from_cloud_recon(cloud_data, user_id, project_id)
                    print("[+] Graph database updated successfully")
                else:
                    print("[!] Could not connect to Neo4j - skipping graph update")
        except ImportError:
            print("[!] Neo4j client not available - skipping graph update")
        except Exception as e:
            print(f"[!] Graph DB update failed (non-fatal): {e}")

    return {
        "findings_count": len(findings),
        "statistics": runner.stats,
        "output_file": str(runner.output_file),
    }


def main():
    if not PROJECT_ID:
        print("[!] ERROR: PROJECT_ID environment variable not set")
        return 1

    load_project_settings(PROJECT_ID)

    start_time = datetime.now()
    try:
        results = run_cloud_recon(project_id=PROJECT_ID)
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
