#!/usr/bin/env python3
"""
NisargHunter AI - IaC/DevOps Configuration Scanner Main Entry Point
======================================================
Shallow-clones target GitHub repositories and runs offline static analysis
against Dockerfiles, docker-compose files, Kubernetes manifests, GitHub
Actions workflows, and Terraform for security misconfigurations.

Usage:
    PROJECT_ID=xxx WEBAPP_API_URL=http://localhost:3000 python iac_scan/main.py
"""
import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from iac_scan.project_settings import get_setting, load_project_settings
    from iac_scan.git_source import ClonedRepos, list_org_repos
    from iac_scan.runner import IacScanRunner
except ImportError:
    from project_settings import get_setting, load_project_settings
    from git_source import ClonedRepos, list_org_repos
    from runner import IacScanRunner

PROJECT_ID = os.environ.get("PROJECT_ID", "")


def run_iac_scan(project_id: str) -> dict:
    token = get_setting("GITHUB_ACCESS_TOKEN", "")
    target_org = get_setting("IAC_SCAN_GITHUB_ORG", "")
    target_repos = get_setting("IAC_SCAN_GITHUB_REPOS", "")

    print("\n" + "=" * 70)
    print("           NisargHunter AI - IaC/DevOps Configuration Scanner")
    print("=" * 70)
    print(f"  Target Org:   {target_org or '(not set)'}")
    print(f"  Target Repos: {target_repos or '(not set)'}")
    print("=" * 70 + "\n")

    if not target_org and not target_repos:
        print("[!] ERROR: No scan target configured (need org or repos)")
        return {"error": "No scan target configured (set org or repos)"}

    if target_repos:
        repos = [r.strip() for r in target_repos.split(",") if r.strip()]
    else:
        print(f"[*] Listing repositories for org {target_org}...")
        repos = list_org_repos(target_org, token)
        print(f"[*] Found {len(repos)} repositories")

    if not repos:
        return {"error": "No repositories resolved for the configured target"}

    all_findings: list[dict] = []
    aggregate_stats = {
        "files_scanned": 0,
        "total_findings": 0,
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_category": {"dockerfile": 0, "compose": 0, "kubernetes": 0, "github_actions": 0, "terraform": 0},
        "repositories_scanned": 0,
        "errors": [],
    }

    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    with ClonedRepos(repos, token) as checkouts:
        for repo_name, checkout_path in checkouts:
            print(f"[*] Scanning {repo_name}...")
            runner = IacScanRunner(str(checkout_path), project_id=project_id, output_dir=str(output_dir))
            findings = runner.run()
            for f in findings:
                f["repository"] = repo_name
            all_findings.extend(findings)
            aggregate_stats["repositories_scanned"] += 1
            aggregate_stats["files_scanned"] += runner.stats["files_scanned"]
            aggregate_stats["total_findings"] += runner.stats["total_findings"]
            for sev, count in runner.stats["by_severity"].items():
                aggregate_stats["by_severity"][sev] = aggregate_stats["by_severity"].get(sev, 0) + count
            for cat, count in runner.stats["by_category"].items():
                aggregate_stats["by_category"][cat] = aggregate_stats["by_category"].get(cat, 0) + count
            aggregate_stats["errors"].extend(runner.stats["errors"])
            print(f"    -> {runner.stats['total_findings']} findings")

    result = {
        "scan_metadata": {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "target_org": target_org,
            "target_repos": target_repos,
            "project_id": project_id,
        },
        "findings": all_findings,
        "statistics": aggregate_stats,
    }
    output_file = output_dir / f"iac_scan_aggregate_{project_id}.json"
    output_file.write_text(json.dumps(result, indent=2))

    print("\n" + "=" * 70)
    print("                    SCAN SUMMARY")
    print("=" * 70)
    print(f"  Repositories scanned: {aggregate_stats['repositories_scanned']}")
    print(f"  Total findings:       {aggregate_stats['total_findings']}")
    print(f"  Critical:             {aggregate_stats['by_severity']['critical']}")
    print(f"  High:                 {aggregate_stats['by_severity']['high']}")
    print(f"  Medium:               {aggregate_stats['by_severity']['medium']}")
    print(f"  Low:                  {aggregate_stats['by_severity']['low']}")
    print("=" * 70 + "\n")

    user_id = os.environ.get("USER_ID", "")
    try:
        from graph_db import Neo4jClient

        print("[*] Updating Neo4j graph with IaC scan results...")
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                graph_client.update_graph_from_iac_scan(result, user_id, project_id)
                print("[+] Graph database updated successfully")
            else:
                print("[!] Could not connect to Neo4j - skipping graph update")
    except ImportError:
        print("[!] Neo4j client not available - skipping graph update")
    except Exception as e:
        print(f"[!] Graph DB update failed (non-fatal): {e}")

    return {
        "findings_count": len(all_findings),
        "statistics": aggregate_stats,
        "output_file": str(output_file),
    }


def main():
    if not PROJECT_ID:
        print("[!] ERROR: PROJECT_ID environment variable not set")
        return 1

    load_project_settings(PROJECT_ID)

    start_time = datetime.now()
    try:
        results = run_iac_scan(project_id=PROJECT_ID)
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
