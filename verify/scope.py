"""Authorisation scope gate.

Verification is *active* testing — it sends live payloads, times responses, and
solicits out-of-band callbacks. That is only lawful against targets you are
authorised to test. This guard makes authorisation an explicit, enforced
precondition: the engine refuses (verdict SKIPPED) to touch any host that is not
on the operator-supplied allowlist. Fail-closed by default — an empty allowlist
authorises nothing.
"""

from __future__ import annotations

from .http import host_of


class ScopeGuard:
    """Host allowlist for active verification.

    - `allow_hosts`: exact hostnames the operator has authorised (e.g.
      "staging.example.com").
    - `allow_subdomains`: when True, a host is in scope if it equals or is a
      subdomain of any allowed host ("api.example.com" ⊆ "example.com").
    """

    def __init__(self, allow_hosts: set[str] | list[str] | None = None,
                 allow_subdomains: bool = False):
        self.allow_hosts = {h.lower().strip() for h in (allow_hosts or []) if h.strip()}
        self.allow_subdomains = allow_subdomains

    def is_allowed(self, url: str) -> bool:
        host = host_of(url)
        if not host or not self.allow_hosts:
            return False
        if host in self.allow_hosts:
            return True
        if self.allow_subdomains:
            return any(host == a or host.endswith("." + a) for a in self.allow_hosts)
        return False

    def reason(self, url: str) -> str:
        if self.is_allowed(url):
            return "in scope"
        if not self.allow_hosts:
            return "no target is authorised (empty scope allowlist) — active testing refused"
        return f"host '{host_of(url)}' is not in the authorised scope — active testing refused"
