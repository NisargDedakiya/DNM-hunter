---
name: IaC / DevOps Config Security
description: Reference for auditing Dockerfiles, docker-compose, Kubernetes manifests, GitHub Actions workflows, and Terraform for misconfigurations — privileged containers, exposed secrets, open security groups, and CI/CD script injection.
---

# IaC / DevOps Config Security

Reference for static review of infrastructure-as-code and CI/CD configuration recovered from a target's repositories (via the `iac_scan` module, or ad-hoc when a repo is in scope). This is offline, source-level analysis — no live requests against the target's infrastructure are made by the scanner itself; live exploitation of anything it flags (an open security group, a leaked credential) is a separate, explicitly-authorized step.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Run the bundled misconfig scanner | `iac_scan` module | `PROJECT_ID=... python iac_scan/main.py`; reads `IAC_SCAN_GITHUB_ORG`/`IAC_SCAN_GITHUB_REPOS` from project settings. |
| Pull findings from the graph | `query_graph` | `MATCH (r:IacRepository)-[:HAS_FINDING]->(f:IacFinding) RETURN f`. |
| Manual repo grep | `execute_code` / `kali_shell` | `grep -rn "privileged: true" .`, `grep -rn "0.0.0.0/0" *.tf`. |
| Terraform plan review (if credentials are in scope) | `kali_shell terraform` | `terraform plan -out=plan.bin && terraform show -json plan.bin` for drift-aware review. |

## Attack matrix

### Dockerfiles / docker-compose

| Class | Signal | Impact |
|---|---|---|
| Root execution | No `USER` instruction, or `USER root` | Container-escape/RCE lands as root on the host UID namespace |
| Docker socket mount | `/var/run/docker.sock` volume | Full host compromise via the Docker API from inside the container |
| Privileged mode | `privileged: true`, `--privileged` | Bypasses all container isolation (devices, capabilities, seccomp) |
| Host networking | `network_mode: host` | Container shares the host's network namespace — no port isolation |
| Baked-in secrets | Literal value in `ENV`/`ARG` named `*PASSWORD*`/`*SECRET*`/`*TOKEN*`/`*KEY*` | Recoverable from any image layer via `docker history`/`docker save`, even after later `RUN rm` |
| Unverified remote code | `curl \| bash`, `ADD http://...` | Build-time RCE if the remote host is compromised or MITM'd |

### Kubernetes manifests

| Class | Signal | Impact |
|---|---|---|
| Privileged pod | `securityContext.privileged: true` | Full host device access |
| Host namespace sharing | `hostNetwork`/`hostPID`/`hostIPC: true` | Cross-workload visibility, node-level attack surface |
| hostPath mount | `volumes[].hostPath`, especially `/`, `/var/run/docker.sock`, `/proc`, `/etc` | Container escape via node filesystem |
| Dangerous capabilities | `capabilities.add: [SYS_ADMIN, NET_ADMIN, ...]` | Expands the kernel attack surface available inside the container |
| Default SA token | No `automountServiceAccountToken: false` + no dedicated `serviceAccountName` | A compromised pod gets a live Kubernetes API token for whatever the default SA can reach |
| Plaintext secret env | `env[].value` (not `valueFrom.secretKeyRef`) named like a credential | Visible in `kubectl describe pod`, etcd, and any log/audit sink that captures pod specs |

### GitHub Actions

| Class | Signal | Impact |
|---|---|---|
| Script injection | `${{ github.event.pull_request.title }}` (or `.body`, `.head.ref`, `issue.title`, `comment.body`) interpolated into a `run:` step | Attacker-controlled text becomes shell code executed by the runner |
| `pull_request_target` + untrusted checkout | Trigger is `pull_request_target` and a step checks out `github.event.pull_request.head.sha`/`ref` | Base-repo secrets and write token are exposed to code from an arbitrary fork PR |
| Unpinned third-party action | `uses: org/action@v1` (tag/branch, not a 40-char SHA) | A compromised or malicious upstream update runs with the workflow's permissions on the next trigger — classic supply-chain vector |
| Overbroad permissions | `permissions: write-all`, or `contents: write` on a `pull_request_target` job | Widens what a compromised step (or injected script) can do to the repo |
| Self-hosted + `pull_request_target` | `runs-on: self-hosted` on a fork-triggerable workflow | RCE on infrastructure the org controls, not an ephemeral GitHub-hosted VM |

### Terraform

| Class | Signal | Impact |
|---|---|---|
| Public S3 ACL | `acl = "public-read"`/`"public-read-write"` | Bucket contents readable/writable by anyone |
| Public access block disabled | `block_public_acls = false` (or sibling attrs) | Removes the account-level guard rail against accidental exposure |
| Open security group | `cidr_blocks = ["0.0.0.0/0"]` on ingress, especially on 22/3389/3306/5432/6379/27017/9200 | Direct internet exposure of an admin/database port |
| Public/unencrypted database | `publicly_accessible = true`, `storage_encrypted = false` | Direct internet-reachable DB; unencrypted data at rest |
| Wildcard IAM policy | `Action: "*"` + `Resource: "*"` | Full-admin-equivalent credentials if the associated identity is ever compromised |
| Hardcoded credential | Literal string in `password`/`secret_key`/`api_key`/`token` attributes | Recoverable from state files, VCS history, and CI logs |

## Validation shape

A clean IaC finding shows:

1. The exact file and line (or resource block) the misconfiguration lives in.
2. The literal offending value (`privileged: true`, the CIDR, the secret's variable name — never echo the secret's actual value in a report).
3. Why the surrounding context doesn't already mitigate it (e.g. no compensating `NetworkPolicy`, no WAF in front of the security group).
4. For CI/CD injection specifically: the exact `${{ }}` expression and the step it lands in, since that's what a reviewer needs to write the fix (switch to an `env:` intermediate variable).

## False positives

- `hostPath` mounts scoped to a genuinely ephemeral, node-local cache directory with no sensitive content.
- `pull_request_target` workflows that never check out PR head content (e.g. only used to post a comment via `github-script` with no attacker-controlled interpolation).
- Terraform security groups with `0.0.0.0/0` ingress on 80/443 for a public-facing load balancer — expected, not a finding.
- Third-party actions maintained by the same org/trust boundary (e.g. `./local-action`) — already excluded by the scanner, but worth restating in a report if a reviewer questions it.

## Hand-off

```
iac_scan/main.py -> Neo4j (IacScan -> IacRepository -> IacFinding)
Leaked credential in a Dockerfile/Terraform var -> cross-reference against trufflehog_scan findings for the same repo (live verification, not just static presence)
Open security group / public bucket -> /skill cloud_storage (confirm actual exposure) or manual authorized probe
Script injection in Actions -> proof-of-concept PR title/branch name, executed only with explicit written authorization
```
