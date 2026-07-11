"""
Kubernetes manifest static misconfiguration rules.

Operates on parsed YAML documents (dicts) for kinds that carry a PodSpec:
Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob.
"""
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"}


def _pod_spec_from(doc: dict) -> dict | None:
    kind = doc.get("kind", "")
    if kind == "Pod":
        return doc.get("spec")
    if kind == "CronJob":
        try:
            return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        except (KeyError, TypeError):
            return None
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        try:
            return doc["spec"]["template"]["spec"]
        except (KeyError, TypeError):
            return None
    return None


def _containers_of(pod_spec: dict) -> list[dict]:
    containers = list(pod_spec.get("containers") or [])
    containers += list(pod_spec.get("initContainers") or [])
    return containers


def check_kubernetes_doc(doc: dict, file_path: str, doc_index: int) -> list[dict]:
    if not isinstance(doc, dict) or "kind" not in doc:
        return []

    findings = []
    kind = doc.get("kind", "")
    name = (doc.get("metadata") or {}).get("name", f"unnamed-{doc_index}")
    resource = f"{kind}/{name}"

    pod_spec = _pod_spec_from(doc)
    if pod_spec is None:
        return findings

    if pod_spec.get("hostNetwork") is True:
        findings.append(_finding("K8S-001", SEVERITY_HIGH, "hostNetwork enabled",
                                  f"{resource} sets hostNetwork: true, giving the pod direct access to the node's network namespace.",
                                  file_path, resource))
    if pod_spec.get("hostPID") is True:
        findings.append(_finding("K8S-002", SEVERITY_HIGH, "hostPID enabled",
                                  f"{resource} sets hostPID: true, exposing all processes on the host to the pod.",
                                  file_path, resource))
    if pod_spec.get("hostIPC") is True:
        findings.append(_finding("K8S-003", SEVERITY_MEDIUM, "hostIPC enabled",
                                  f"{resource} sets hostIPC: true, sharing the host's IPC namespace with the pod.",
                                  file_path, resource))

    sa_token = pod_spec.get("automountServiceAccountToken")
    if sa_token is not False and not pod_spec.get("serviceAccountName"):
        findings.append(_finding("K8S-004", SEVERITY_LOW, "Default service account token auto-mounted",
                                  f"{resource} does not disable automountServiceAccountToken and uses no dedicated service account; a compromised container gets a live API token.",
                                  file_path, resource))

    for volume in pod_spec.get("volumes") or []:
        if isinstance(volume, dict) and "hostPath" in volume:
            path = (volume.get("hostPath") or {}).get("path", "?")
            findings.append(_finding("K8S-005", SEVERITY_HIGH, "hostPath volume mounted",
                                      f"{resource} mounts host path {path!r} into the pod, allowing container escape via the node filesystem.",
                                      file_path, resource))
            if path in ("/", "/var/run/docker.sock", "/proc", "/etc"):
                findings.append(_finding("K8S-006", SEVERITY_CRITICAL, "Sensitive hostPath mounted",
                                          f"{resource} mounts a highly sensitive host path ({path!r}) — typically equivalent to full node/host compromise.",
                                          file_path, resource))

    for container in _containers_of(pod_spec):
        cname = container.get("name", "?")
        cres = f"{resource}:{cname}"
        sec_ctx = container.get("securityContext") or {}
        pod_sec_ctx = pod_spec.get("securityContext") or {}

        if sec_ctx.get("privileged") is True:
            findings.append(_finding("K8S-007", SEVERITY_CRITICAL, "Privileged container",
                                      f"Container {cres} runs with privileged: true — full access to host devices, equivalent to root on the node.",
                                      file_path, cres))

        if sec_ctx.get("allowPrivilegeEscalation") is not False:
            findings.append(_finding("K8S-008", SEVERITY_MEDIUM, "allowPrivilegeEscalation not disabled",
                                      f"Container {cres} does not set allowPrivilegeEscalation: false, permitting setuid-style privilege gain inside the container.",
                                      file_path, cres))

        run_as_non_root = sec_ctx.get("runAsNonRoot", pod_sec_ctx.get("runAsNonRoot"))
        run_as_user = sec_ctx.get("runAsUser", pod_sec_ctx.get("runAsUser"))
        if run_as_non_root is not True and run_as_user in (0, None):
            findings.append(_finding("K8S-009", SEVERITY_MEDIUM, "Container may run as root",
                                      f"Container {cres} does not enforce runAsNonRoot and sets no non-zero runAsUser.",
                                      file_path, cres))

        caps = ((sec_ctx.get("capabilities") or {}).get("add")) or []
        dangerous = sorted(set(c.upper() for c in caps) & _DANGEROUS_CAPS)
        if dangerous:
            findings.append(_finding("K8S-010", SEVERITY_HIGH, "Dangerous Linux capability added",
                                      f"Container {cres} adds capabilities {dangerous} beyond the default set.",
                                      file_path, cres))

        if not container.get("resources", {}).get("limits"):
            findings.append(_finding("K8S-011", SEVERITY_LOW, "No resource limits set",
                                      f"Container {cres} has no CPU/memory limits; a single pod can exhaust node resources (noisy-neighbor / DoS risk).",
                                      file_path, cres))

        for env in container.get("env") or []:
            if isinstance(env, dict) and "value" in env:
                ename = str(env.get("name", ""))
                if any(tok in ename.upper() for tok in ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY")):
                    findings.append(_finding("K8S-012", SEVERITY_CRITICAL, "Secret passed as plaintext env var",
                                              f"Container {cres} sets {ename} directly in env (plaintext in the manifest/etcd) instead of via a Secret reference.",
                                              file_path, cres))

    return findings


def _finding(rule_id, severity, title, message, file_path, resource, line=None):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "message": message,
        "file_path": file_path,
        "line": line,
        "resource": resource,
    }
