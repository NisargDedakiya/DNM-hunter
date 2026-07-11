"""IaC/DevOps scan graph updates (IacScan, IacRepository, IacFinding).

Follows the TrufflehogMixin scan -> repository -> finding hierarchy pattern
(graph_db/mixins/secret_mixin.py) so the graph model stays consistent across
scanner integrations.
"""
import hashlib


class IacScanMixin:
    def update_graph_from_iac_scan(self, iac_data: dict, user_id: str, project_id: str) -> dict:
        """
        Ingest IaC/DevOps scanner results into the graph.

        Graph structure:
        - Domain -[:HAS_IAC_SCAN]-> IacScan
        - IacScan -[:HAS_REPOSITORY]-> IacRepository
        - IacRepository -[:HAS_FINDING]-> IacFinding
        """
        stats = {
            "scan_created": 0,
            "repositories_created": 0,
            "findings_created": 0,
            "relationships_created": 0,
            "findings_deduplicated": 0,
            "errors": [],
        }

        findings = iac_data.get("findings", [])
        scan_meta = iac_data.get("scan_metadata", {})
        scan_stats = iac_data.get("statistics", {})

        with self.driver.session() as session:
            scan_id = f"iac-scan-{user_id}-{project_id}"
            scan_props = {
                "id": scan_id,
                "user_id": user_id,
                "project_id": project_id,
                "scan_timestamp": scan_meta.get("scan_timestamp", ""),
                "total_findings": scan_stats.get("total_findings", 0),
                "files_scanned": scan_stats.get("files_scanned", 0),
                "critical_count": scan_stats.get("by_severity", {}).get("critical", 0),
                "high_count": scan_stats.get("by_severity", {}).get("high", 0),
                "medium_count": scan_stats.get("by_severity", {}).get("medium", 0),
                "low_count": scan_stats.get("by_severity", {}).get("low", 0),
            }

            try:
                session.run(
                    "MERGE (s:IacScan {id: $id}) SET s += $props, s.updated_at = datetime()",
                    id=scan_id, props=scan_props,
                )
                stats["scan_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to create IacScan node: {e}")
                return stats

            try:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    MATCH (s:IacScan {id: $scan_id})
                    MERGE (d)-[:HAS_IAC_SCAN]->(s)
                    RETURN count(*) as linked
                    """,
                    uid=user_id, pid=project_id, scan_id=scan_id,
                )
                record = result.single()
                if record and record["linked"] > 0:
                    stats["relationships_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to link IacScan to Domain: {e}")

            seen = set()
            created_repos = set()

            for finding in findings:
                repository = finding.get("repository") or scan_meta.get("target_dir", "")
                file_path = finding.get("file_path", "")
                rule_id = finding.get("rule_id", "")
                resource = finding.get("resource") or ""

                if not rule_id:
                    continue

                dedup_key = f"{repository}:{file_path}:{rule_id}:{resource}"
                if dedup_key in seen:
                    stats["findings_deduplicated"] += 1
                    continue
                seen.add(dedup_key)

                repo_hash = hashlib.sha256(f"{user_id}:{project_id}:{repository}".encode()).hexdigest()[:16]
                repo_id = f"iac-repo-{repo_hash}"
                finding_hash = hashlib.sha256(dedup_key.encode()).hexdigest()[:16]
                finding_id = f"iac-finding-{finding_hash}"

                if repository not in created_repos:
                    try:
                        session.run(
                            "MERGE (r:IacRepository {id: $id}) SET r += $props, r.updated_at = datetime()",
                            id=repo_id,
                            props={"id": repo_id, "name": repository, "user_id": user_id, "project_id": project_id},
                        )
                        session.run(
                            """
                            MATCH (s:IacScan {id: $scan_id})
                            MATCH (r:IacRepository {id: $repo_id})
                            MERGE (s)-[:HAS_REPOSITORY]->(r)
                            """,
                            scan_id=scan_id, repo_id=repo_id,
                        )
                        created_repos.add(repository)
                        stats["repositories_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create IacRepository {repository}: {e}")
                        continue

                finding_props = {
                    "id": finding_id,
                    "user_id": user_id,
                    "project_id": project_id,
                    "rule_id": rule_id,
                    "category": finding.get("category", ""),
                    "severity": finding.get("severity", "medium"),
                    "title": finding.get("title", ""),
                    "message": finding.get("message", ""),
                    "file_path": file_path,
                    "line": finding.get("line"),
                    "resource": resource,
                }

                try:
                    session.run(
                        "MERGE (f:IacFinding {id: $id}) SET f += $props, f.updated_at = datetime()",
                        id=finding_id, props=finding_props,
                    )
                    session.run(
                        """
                        MATCH (r:IacRepository {id: $repo_id})
                        MATCH (f:IacFinding {id: $finding_id})
                        MERGE (r)-[:HAS_FINDING]->(f)
                        """,
                        repo_id=repo_id, finding_id=finding_id,
                    )
                    stats["findings_created"] += 1
                    stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Failed to create IacFinding {finding_id}: {e}")

        return stats
