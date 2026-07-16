"""Azure Terraform misconfiguration rules.

Extends the IaC scanner to Azure (azurerm_*) resources, reusing the shared hcl2
helpers from terraform_rules. Covers CIS Azure Benchmark staples: public blob
storage, weak transport security, open network security rules, and public SQL.
"""
from .terraform_rules import (
    _iter_resources, _val, _strip_quotes, _finding,
    _OPEN_CIDR, _SENSITIVE_PORTS,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)

_OPEN_SOURCES = _OPEN_CIDR | {"*", "internet"}


def _tls_below_12(v) -> bool:
    s = str(v or "").upper().replace("_", "").replace(".", "")
    # accepts TLS1_2 / TLS1.2 / 1.2 etc. Flag anything that is 1.0 or 1.1.
    return s in ("TLS10", "TLS11", "10", "11")


def check_azure_doc(doc: dict, file_path: str) -> list[dict]:
    findings = []
    if not isinstance(doc, dict):
        return findings

    for rtype, rname, body in _iter_resources(doc):
        resource = f"{rtype}.{rname}"

        # AZURE-001/002: storage account — public blobs + weak transport.
        if rtype == "azurerm_storage_account":
            if _val(body.get("allow_nested_items_to_be_public")) is True or _val(body.get("allow_blob_public_access")) is True:
                findings.append(_finding("AZURE-001", SEVERITY_HIGH, "Storage account allows public blob access",
                                          f"{resource} permits public blob/container access; anonymous users may read stored objects.",
                                          file_path, resource))
            https_only = _val(body.get("enable_https_traffic_only"))
            if https_only is False:
                findings.append(_finding("AZURE-002", SEVERITY_MEDIUM, "Storage account allows plaintext HTTP",
                                          f"{resource} sets enable_https_traffic_only = false; data can be read/written over unencrypted HTTP.",
                                          file_path, resource))
            if _tls_below_12(_val(body.get("min_tls_version"))):
                findings.append(_finding("AZURE-003", SEVERITY_MEDIUM, "Storage account allows TLS < 1.2",
                                          f"{resource} sets a min_tls_version below TLS 1.2.",
                                          file_path, resource))

        # AZURE-004: network security rule open to the internet inbound.
        if rtype == "azurerm_network_security_rule":
            access = str(_val(body.get("access")) or "").lower()
            direction = str(_val(body.get("direction")) or "inbound").lower()
            src = str(_strip_quotes(_val(body.get("source_address_prefix"))) or "").lower()
            src_list = body.get("source_address_prefixes") or []
            if isinstance(src_list, dict):
                src_list = [src_list]
            flat_src = {src} | {str(_strip_quotes(x)).lower() for x in src_list if not isinstance(x, list)}
            if access == "allow" and direction == "inbound" and (flat_src & _OPEN_SOURCES):
                dport = str(_val(body.get("destination_port_range")) or "")
                sensitive = False
                try:
                    sensitive = int(dport.split("-")[0]) in _SENSITIVE_PORTS
                except (TypeError, ValueError):
                    pass
                findings.append(_finding("AZURE-004", SEVERITY_CRITICAL if sensitive else SEVERITY_HIGH,
                                          "Network security rule open to the internet",
                                          f"{resource} allows inbound traffic from any source (* / 0.0.0.0/0)" + (f" on sensitive port {dport}." if sensitive else "."),
                                          file_path, resource))

        # AZURE-005: SQL server firewall rule allowing all Azure/all IPs.
        if rtype == "azurerm_sql_firewall_rule" or rtype == "azurerm_mssql_firewall_rule":
            start = str(_strip_quotes(_val(body.get("start_ip_address"))) or "")
            end = str(_strip_quotes(_val(body.get("end_ip_address"))) or "")
            if start == "0.0.0.0" and end in ("0.0.0.0", "255.255.255.255"):
                findings.append(_finding("AZURE-005", SEVERITY_CRITICAL, "SQL firewall open to the internet",
                                          f"{resource} allows the IP range {start}-{end} — the database is publicly reachable.",
                                          file_path, resource))

        # AZURE-006: SQL/MSSQL server with public network access enabled.
        if rtype in ("azurerm_mssql_server", "azurerm_postgresql_server", "azurerm_mysql_server"):
            if str(_val(body.get("public_network_access_enabled"))).lower() == "true":
                findings.append(_finding("AZURE-006", SEVERITY_HIGH, "Managed database allows public network access",
                                          f"{resource} sets public_network_access_enabled = true; restrict to private endpoints/VNet.",
                                          file_path, resource))

    return findings
