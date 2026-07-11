"""Cloud storage bucket exposure graph updates (CloudReconScan, CloudBucketFinding)."""
import hashlib


class CloudReconMixin:
    def update_graph_from_cloud_recon(self, cloud_data: dict, user_id: str, project_id: str) -> dict:
        """
        Ingest cloud storage bucket enumeration results into the graph.

        Graph structure:
        - Domain -[:HAS_CLOUD_RECON_SCAN]-> CloudReconScan
        - CloudReconScan -[:HAS_BUCKET_FINDING]-> CloudBucketFinding
        """
        stats = {
            "scan_created": 0,
            "findings_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        findings = cloud_data.get("findings", [])
        scan_meta = cloud_data.get("scan_metadata", {})
        scan_stats = cloud_data.get("statistics", {})

        with self.driver.session() as session:
            scan_id = f"cloud-recon-scan-{user_id}-{project_id}"
            scan_props = {
                "id": scan_id,
                "user_id": user_id,
                "project_id": project_id,
                "scan_timestamp": scan_meta.get("scan_timestamp", ""),
                "candidates_generated": scan_meta.get("candidates_generated", 0),
                "buckets_found": scan_stats.get("buckets_found", 0),
            }
            try:
                session.run(
                    "MERGE (s:CloudReconScan {id: $id}) SET s += $props, s.updated_at = datetime()",
                    id=scan_id, props=scan_props,
                )
                stats["scan_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to create CloudReconScan node: {e}")
                return stats

            try:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    MATCH (s:CloudReconScan {id: $scan_id})
                    MERGE (d)-[:HAS_CLOUD_RECON_SCAN]->(s)
                    RETURN count(*) as linked
                    """,
                    uid=user_id, pid=project_id, scan_id=scan_id,
                )
                record = result.single()
                if record and record["linked"] > 0:
                    stats["relationships_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to link CloudReconScan to Domain: {e}")

            for finding in findings:
                bucket = finding.get("bucket", "")
                provider = finding.get("provider", "")
                if not bucket or not provider:
                    continue

                id_hash = hashlib.sha256(f"{user_id}:{project_id}:{provider}:{bucket}".encode()).hexdigest()[:16]
                finding_id = f"cloud-bucket-{id_hash}"

                finding_props = {
                    "id": finding_id,
                    "user_id": user_id,
                    "project_id": project_id,
                    "provider": provider,
                    "bucket": bucket,
                    "url": finding.get("url", ""),
                    "exposure": finding.get("exposure", ""),
                    "severity": finding.get("severity", "low"),
                    "detail": finding.get("detail", ""),
                    "sample_objects": finding.get("sample_objects", []),
                }

                try:
                    session.run(
                        "MERGE (f:CloudBucketFinding {id: $id}) SET f += $props, f.updated_at = datetime()",
                        id=finding_id, props=finding_props,
                    )
                    session.run(
                        """
                        MATCH (s:CloudReconScan {id: $scan_id})
                        MATCH (f:CloudBucketFinding {id: $finding_id})
                        MERGE (s)-[:HAS_BUCKET_FINDING]->(f)
                        """,
                        scan_id=scan_id, finding_id=finding_id,
                    )
                    stats["findings_created"] += 1
                    stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Failed to create CloudBucketFinding {finding_id}: {e}")

        return stats
