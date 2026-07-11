"""
Cloud storage bucket enumeration.

Generates candidate bucket/container names from seed words (org name, product
name, domain labels) and probes AWS S3, Google Cloud Storage, and Azure Blob
Storage with unauthenticated, read-only HTTP requests to detect public
exposure. No credentials are used or required — this only reads what an
anonymous internet user could already read.
"""
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from cloud_recon.permutations import generate_candidates
from cloud_recon.providers import aws_s3, gcs, azure_blob

logger = logging.getLogger(__name__)

_PROVIDERS = {
    "aws_s3": aws_s3.probe_bucket,
    "gcs": gcs.probe_bucket,
    "azure_blob": azure_blob.probe_bucket,
}


class CloudReconRunner:
    def __init__(self, seeds: list[str], project_id: str, providers: list[str] | None = None,
                 concurrency: int = 20, output_dir: str | None = None):
        self.seeds = seeds
        self.project_id = project_id
        self.providers = providers or list(_PROVIDERS.keys())
        self.concurrency = concurrency
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.output_file: Path | None = None
        self.stats = {
            "candidates_checked": 0,
            "buckets_found": 0,
            "by_exposure": {"public_list": 0, "public_object": 0, "exists_private": 0},
            "by_provider": {},
            "errors": [],
        }

    def run(self) -> list[dict]:
        candidates = generate_candidates(self.seeds)
        findings: list[dict] = []

        jobs = [(provider, candidate) for candidate in candidates for provider in self.providers]
        self.stats["candidates_checked"] = len(jobs)

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            future_map = {
                pool.submit(_PROVIDERS[provider], candidate): (provider, candidate)
                for provider, candidate in jobs
                if provider in _PROVIDERS
            }
            for future in as_completed(future_map):
                provider, candidate = future_map[future]
                try:
                    result = future.result()
                except Exception as e:
                    self.stats["errors"].append(f"{provider}:{candidate}: {e}")
                    continue
                if result:
                    findings.append(result)
                    self.stats["buckets_found"] += 1
                    self.stats["by_exposure"][result["exposure"]] = self.stats["by_exposure"].get(result["exposure"], 0) + 1
                    self.stats["by_provider"][provider] = self.stats["by_provider"].get(provider, 0) + 1

        findings.sort(key=lambda f: {"critical": 0, "medium": 1, "low": 2}.get(f["severity"], 3))

        result = {
            "scan_metadata": {
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "seeds": self.seeds,
                "project_id": self.project_id,
                "candidates_generated": len(candidates),
            },
            "findings": findings,
            "statistics": self.stats,
        }
        self.output_file = self.output_dir / f"cloud_recon_{self.project_id}.json"
        self.output_file.write_text(json.dumps(result, indent=2))
        return findings
