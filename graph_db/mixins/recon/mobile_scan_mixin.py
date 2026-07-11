"""Mobile APK static analysis graph updates (MobileScan, MobileApp, MobileFinding)."""
import hashlib


class MobileScanMixin:
    def update_graph_from_mobile_scan(self, mobile_data: dict, user_id: str, project_id: str) -> dict:
        """
        Ingest mobile APK static analysis results into the graph.

        Graph structure:
        - Domain -[:HAS_MOBILE_SCAN]-> MobileScan
        - MobileScan -[:HAS_APP]-> MobileApp
        - MobileApp -[:HAS_FINDING]-> MobileFinding
        """
        stats = {
            "scan_created": 0,
            "apps_created": 0,
            "findings_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        apps = mobile_data.get("apps", [])
        scan_meta = mobile_data.get("scan_metadata", {})

        with self.driver.session() as session:
            scan_id = f"mobile-scan-{user_id}-{project_id}"
            try:
                session.run(
                    "MERGE (s:MobileScan {id: $id}) SET s += $props, s.updated_at = datetime()",
                    id=scan_id,
                    props={
                        "id": scan_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "scan_timestamp": scan_meta.get("scan_timestamp", ""),
                        "apps_scanned": len(apps),
                    },
                )
                stats["scan_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to create MobileScan node: {e}")
                return stats

            try:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    MATCH (s:MobileScan {id: $scan_id})
                    MERGE (d)-[:HAS_MOBILE_SCAN]->(s)
                    RETURN count(*) as linked
                    """,
                    uid=user_id, pid=project_id, scan_id=scan_id,
                )
                record = result.single()
                if record and record["linked"] > 0:
                    stats["relationships_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to link MobileScan to Domain: {e}")

            for app in apps:
                package = app.get("package", "")
                if not package:
                    continue

                app_hash = hashlib.sha256(f"{user_id}:{project_id}:{package}".encode()).hexdigest()[:16]
                app_id = f"mobile-app-{app_hash}"

                try:
                    session.run(
                        "MERGE (a:MobileApp {id: $id}) SET a += $props, a.updated_at = datetime()",
                        id=app_id,
                        props={
                            "id": app_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "package": package,
                            "app_name": app.get("app_name", ""),
                            "target_sdk": app.get("target_sdk"),
                            "min_sdk": app.get("min_sdk"),
                            "permissions": app.get("permissions", []),
                        },
                    )
                    session.run(
                        """
                        MATCH (s:MobileScan {id: $scan_id})
                        MATCH (a:MobileApp {id: $app_id})
                        MERGE (s)-[:HAS_APP]->(a)
                        """,
                        scan_id=scan_id, app_id=app_id,
                    )
                    stats["apps_created"] += 1
                    stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Failed to create MobileApp {package}: {e}")
                    continue

                for finding in app.get("findings", []):
                    rule_id = finding.get("rule_id", "")
                    resource = finding.get("resource", "")
                    if not rule_id:
                        continue

                    finding_hash = hashlib.sha256(f"{package}:{rule_id}:{resource}".encode()).hexdigest()[:16]
                    finding_id = f"mobile-finding-{finding_hash}"

                    try:
                        session.run(
                            "MERGE (f:MobileFinding {id: $id}) SET f += $props, f.updated_at = datetime()",
                            id=finding_id,
                            props={
                                "id": finding_id,
                                "user_id": user_id,
                                "project_id": project_id,
                                "rule_id": rule_id,
                                "severity": finding.get("severity", "low"),
                                "title": finding.get("title", ""),
                                "message": finding.get("message", ""),
                                "resource": resource,
                                "evidence": finding.get("evidence") or "",
                            },
                        )
                        session.run(
                            """
                            MATCH (a:MobileApp {id: $app_id})
                            MATCH (f:MobileFinding {id: $finding_id})
                            MERGE (a)-[:HAS_FINDING]->(f)
                            """,
                            app_id=app_id, finding_id=finding_id,
                        )
                        stats["findings_created"] += 1
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create MobileFinding {finding_id}: {e}")

        return stats
