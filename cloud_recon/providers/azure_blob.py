"""Azure Blob Storage container existence + public-exposure probing (unauthenticated, read-only)."""
import re
import requests

TIMEOUT = 8


def probe_bucket(account_container: str) -> dict | None:
    """account_container is a candidate storage-account name; probes its default containers."""
    for container in ("public", "data", "backup", "files", "media", "assets", "$root"):
        url = f"https://{account_container}.blob.core.windows.net/{container}?restype=container&comp=list"
        try:
            resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "NisargHunter-CloudRecon/1.0"})
        except requests.ConnectionError:
            # DNS resolution failure means the storage account itself doesn't exist —
            # no point trying the remaining container name guesses.
            return None
        except requests.RequestException:
            continue

        body = resp.text or ""

        if resp.status_code == 200 and "<EnumerationResults" in body:
            names = re.findall(r"<Name>(.*?)</Name>", body)
            return {
                "provider": "azure_blob",
                "bucket": f"{account_container}/{container}",
                "url": url,
                "exposure": "public_list",
                "severity": "critical",
                "detail": f"Azure Blob container is publicly listable ({len(names)} entr(ies) visible).",
                "sample_objects": names[:10],
            }

        if resp.status_code == 403:
            return {
                "provider": "azure_blob",
                "bucket": f"{account_container}/{container}",
                "url": url,
                "exposure": "exists_private",
                "severity": "low",
                "detail": "Azure storage account resolves but container listing is denied (private).",
                "sample_objects": [],
            }

    return None
