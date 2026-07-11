"""Google Cloud Storage bucket existence + public-exposure probing (unauthenticated, read-only)."""
import requests

TIMEOUT = 8


def probe_bucket(bucket: str) -> dict | None:
    url = f"https://storage.googleapis.com/{bucket}/"
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "NisargHunter-CloudRecon/1.0"})
    except requests.RequestException:
        return None

    body = resp.text or ""

    if resp.status_code == 404:
        return None

    if resp.status_code == 200 and ("<ListBucketResult" in body or "<Contents>" in body):
        import re
        keys = re.findall(r"<Key>(.*?)</Key>", body)
        return {
            "provider": "gcs",
            "bucket": bucket,
            "url": url,
            "exposure": "public_list",
            "severity": "critical",
            "detail": f"GCS bucket is publicly listable ({len(keys)} object(s) visible in this page).",
            "sample_objects": keys[:10],
        }

    if resp.status_code == 403:
        return {
            "provider": "gcs",
            "bucket": bucket,
            "url": url,
            "exposure": "exists_private",
            "severity": "low",
            "detail": "GCS bucket exists but listing is denied — private IAM/ACL is in effect.",
            "sample_objects": [],
        }

    return None
