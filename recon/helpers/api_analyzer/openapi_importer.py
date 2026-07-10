"""
OpenAPI / Swagger Importer
===========================
Discovers or accepts an OpenAPI 2.0 (Swagger) / 3.x spec, resolves $refs via
`prance.ResolvingParser` (the same dependency ai_surface_recon.py already
uses for AI-plugin spec parsing — see _parse_spec() there), and normalizes
every path+method into the endpoint dict shape merge.py expects.

This is deliberately parsing-only: it produces endpoints that flow into the
existing resource_enum -> graph -> nuclei/ffuf/vuln_scan pipeline through
merge_api_endpoints_into_by_base_url(), rather than standing up a separate
API-testing subsystem. "Testing" an imported API means the same scanners
that already test every other discovered endpoint now also see these.
"""

import json
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin

from recon.helpers.resource_enum.classification import classify_parameter

# Common paths where a spec might be self-hosted, tried in order.
DEFAULT_DISCOVERY_PATHS = [
    '/openapi.json', '/openapi.yaml',
    '/swagger.json', '/swagger.yaml',
    '/v2/swagger.json', '/v3/api-docs',
    '/api-docs', '/api-docs.json',
    '/swagger/v1/swagger.json',
    '/.well-known/openapi.json',
]

HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}


def discover_openapi_spec(base_url: str, settings: Optional[dict] = None, timeout: int = 10) -> Optional[str]:
    """Probe common paths for a self-hosted OpenAPI/Swagger spec. Returns the
    raw spec text if one is found, else None. Never raises."""
    settings = settings or {}
    verify_ssl = settings.get('OPENAPI_VERIFY_SSL', True)

    for path in DEFAULT_DISCOVERY_PATHS:
        url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
        try:
            resp = requests.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        text = resp.text.strip()
        if not text:
            continue
        # Cheap sanity check before handing to prance — must look like a spec.
        if '"openapi"' in text or '"swagger"' in text or text.lstrip().startswith(('openapi:', 'swagger:')):
            print(f"[+][OpenAPI] Found spec at {url}")
            return text

    return None


def parse_openapi_spec(spec_text: str) -> Optional[List[Dict]]:
    """Parse a raw OpenAPI/Swagger spec (JSON or YAML) into a normalized
    endpoint list. Returns None if the spec can't be parsed at all — callers
    should treat that as "no import happened", not crash the pipeline.
    """
    try:
        from prance import ResolvingParser
        spec = ResolvingParser(spec_string=spec_text, backend="openapi-spec-validator").specification
    except Exception as e:
        print(f"[!][OpenAPI] Failed to resolve spec via prance: {e}")
        try:
            spec = json.loads(spec_text)
        except Exception:
            print(f"[!][OpenAPI] Spec is not valid JSON either — giving up")
            return None

    paths = spec.get('paths')
    if not isinstance(paths, dict):
        print(f"[!][OpenAPI] Spec has no 'paths' object")
        return None

    # Global security schemes, used to flag auth-gated endpoints.
    global_security = bool(spec.get('security'))

    endpoints: List[Dict] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Path-level parameters apply to every method under this path.
        path_level_params = path_item.get('parameters') or []

        methods_for_path: List[str] = []
        query_params: Dict[str, Dict] = {}
        path_params: Dict[str, Dict] = {}
        body_params: Dict[str, Dict] = {}
        summary = ''
        requires_auth = False

        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            methods_for_path.append(method.upper())
            if not summary:
                summary = str(operation.get('summary') or operation.get('operationId') or '')[:200]
            # Per OpenAPI semantics: an operation's own `security` key, if
            # present, OVERRIDES the global default entirely -- an explicit
            # `security: []` means this specific operation is public even
            # when the spec requires auth everywhere else. Absence of the
            # key means "inherit the global default".
            op_security = operation.get('security', None)
            op_requires_auth = global_security if op_security is None else bool(op_security)
            if op_requires_auth:
                requires_auth = True

            all_params = path_level_params + (operation.get('parameters') or [])
            for param in all_params:
                if not isinstance(param, dict):
                    continue
                name = param.get('name')
                location = param.get('in')
                if not name or location not in ('query', 'path', 'header'):
                    continue
                target = {'query': query_params, 'path': path_params}.get(location)
                if target is not None and name not in target:
                    target[name] = {'name': name, 'category': classify_parameter(name), 'source': 'openapi'}

            # OpenAPI 3.x request body: pull top-level schema property names.
            request_body = operation.get('requestBody')
            if isinstance(request_body, dict):
                content = request_body.get('content') or {}
                for media_type in ('application/json', 'application/x-www-form-urlencoded'):
                    schema = (content.get(media_type) or {}).get('schema')
                    if isinstance(schema, dict):
                        for prop_name in (schema.get('properties') or {}).keys():
                            if prop_name not in body_params:
                                body_params[prop_name] = {
                                    'name': prop_name, 'category': classify_parameter(prop_name), 'source': 'openapi',
                                }
                        break
            # Swagger 2.0: body/formData params come through the `parameters` array with in='body'/'formData'.
            for param in all_params:
                if not isinstance(param, dict):
                    continue
                if param.get('in') in ('body', 'formData'):
                    name = param.get('name')
                    if name and name not in body_params:
                        body_params[name] = {'name': name, 'category': classify_parameter(name), 'source': 'openapi'}

        if not methods_for_path:
            continue

        endpoints.append({
            'path': path,
            'methods': methods_for_path,
            'parameters': {
                'query': list(query_params.values()),
                'path': list(path_params.values()),
                'body': list(body_params.values()),
            },
            'summary': summary,
            'requires_auth': requires_auth,
        })

    print(f"[+][OpenAPI] Parsed {len(endpoints)} endpoints from spec")
    return endpoints
