---
name: Cloud Storage Bucket Enumeration
description: Reference for discovering and assessing public exposure of AWS S3, Google Cloud Storage, and Azure Blob Storage via unauthenticated, read-only name-permutation probing.
---

# Cloud Storage Bucket Enumeration

Reference for finding and triaging exposed cloud storage tied to a target org, product, or domain. Every probe in this skill is an unauthenticated `GET`/`HEAD` request — the same access any anonymous internet user already has. No credentials are used, requested, or required. This is squarely passive/low-noise recon and is safe to run without a separate approval gate, but anything found still needs authorization before further action (downloading customer data, testing write access, etc. is a separate, higher-risk step).

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Run the bundled enumerator | `cloud_recon` module | `PROJECT_ID=... python cloud_recon/main.py`; seeds come from `CLOUD_RECON_SEEDS` in project settings. |
| Pull findings from the graph | `query_graph` | `MATCH (s:CloudReconScan)-[:HAS_BUCKET_FINDING]->(f:CloudBucketFinding) RETURN f`. |
| One-off manual probe | `execute_curl` | See per-provider requests below. |

## Discovery: name permutation

Seed from every name variant tied to the target: company name, product name, each label in the domain (`acme`, `acme-corp`, `acmeapp`), and known subsidiary/brand names. Combine with common separators (`-`, `_`, `.`, none) and a suffix/prefix wordlist:

```
{seed}, {seed}-prod, {seed}-dev, {seed}-staging, {seed}-backup, {seed}-backups,
{seed}-assets, {seed}-static, {seed}-media, {seed}-uploads, {seed}-data, {seed}-logs,
{seed}-public, {seed}-private, {seed}-internal, {seed}-files, {seed}-cdn,
www-{seed}, cdn-{seed}, static-{seed}, assets-{seed}, backup-{seed}
```

`cloud_recon/permutations.py` generates this automatically from seed words (capped at 400 candidates per run to keep probing bounded).

## Per-provider probing

### AWS S3

```
GET https://{bucket}.s3.amazonaws.com/
```

| Response | Meaning |
|---|---|
| `404` + `<Code>NoSuchBucket</Code>` | Bucket doesn't exist — not a finding |
| `403` + `<Code>AccessDenied</Code>` | Bucket exists, ACL/policy is private — confirms the name is real but not exposed |
| `200` + `<ListBucketResult>` | **Public listing** — full object enumeration, critical |
| `200` + arbitrary content | Public object/static-site root readable |

### Google Cloud Storage

```
GET https://storage.googleapis.com/{bucket}/
```
Same status-code semantics as S3 (`404` = doesn't exist, `403` = exists/private, `200` + `<ListBucketResult>`/`<Contents>` = public listing).

### Azure Blob Storage

```
GET https://{account}.blob.core.windows.net/{container}?restype=container&comp=list
```
Try common container names (`public`, `data`, `backup`, `files`, `media`, `assets`, `$root`) against each candidate storage-account name. A DNS resolution failure means the storage account itself doesn't exist — skip the remaining container guesses for that account. `200` + `<EnumerationResults>` is a public listing.

## Validation shape

A clean cloud-bucket finding shows:

1. The full URL probed and the exact HTTP status/response body that proves exposure (not just "the bucket exists").
2. For `public_list`: a sample of object keys/blob names actually returned (redact anything that looks like customer PII or a live credential in the report body — reference it, don't paste it).
3. Whether the exposure is listing-only (`public_list`) vs. content readable (`public_object`) vs. write-capable (only relevant if a separately authorized write test was performed — never attempt an unauthorized write).
4. The provider and exact bucket/account name so the finding is directly actionable for remediation (fix the ACL/IAM policy).

## False positives

- `403 AccessDenied` / equivalent — the name resolved but the bucket is private. This confirms the name guess was correct (useful for the report's "attack surface" section) but is **not** an exposure finding on its own.
- Deliberately public open-data buckets (AWS Open Data Registry, public CDN origins) — check whether the bucket is *supposed* to be public before flagging (e.g. a `-cdn` or `-static` bucket serving a public website's assets is working as intended).
- Azure storage accounts that exist but expose no listable containers under the common-name wordlist — the account name alone is not a finding.

## Hand-off

```
cloud_recon/main.py -> Neo4j (CloudReconScan -> CloudBucketFinding)
public_list with secrets/PII in sample_objects -> escalate severity, cross-check against trufflehog_scan for the same org
Terraform/IaC-declared bucket with a matching name -> /skill iac_devops (root-cause: which resource block set the public ACL)
```
