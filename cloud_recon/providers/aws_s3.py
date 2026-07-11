"""AWS S3 bucket existence + public-exposure probing (unauthenticated, read-only)."""
import re
import requests

TIMEOUT = 8


def probe_bucket(bucket: str) -> dict | None:
    """Return an exposure finding dict, or None if the bucket doesn't exist / isn't S3."""
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "NisargHunter-CloudRecon/1.0"})
    except requests.RequestException:
        return None

    body = resp.text or ""

    if resp.status_code == 404 and "NoSuchBucket" in body:
        return None

    if resp.status_code == 200 and "<ListBucketResult" in body:
        keys = re.findall(r"<Key>(.*?)</Key>", body)
        return {
            "provider": "aws_s3",
            "bucket": bucket,
            "url": url,
            "exposure": "public_list",
            "severity": "critical",
            "detail": f"Bucket is publicly listable ({len(keys)} object(s) visible in this page).",
            "sample_objects": keys[:10],
        }

    if resp.status_code == 403:
        return {
            "provider": "aws_s3",
            "bucket": bucket,
            "url": url,
            "exposure": "exists_private",
            "severity": "low",
            "detail": "Bucket exists but listing is denied (AccessDenied) — private ACL/policy is in effect.",
            "sample_objects": [],
        }

    if resp.status_code == 200:
        # Bucket resolved and returned content directly (e.g. static website hosting root object)
        return {
            "provider": "aws_s3",
            "bucket": bucket,
            "url": url,
            "exposure": "public_object",
            "severity": "medium",
            "detail": "Bucket root returned a readable object (public website/object access).",
            "sample_objects": [],
        }

    return None
