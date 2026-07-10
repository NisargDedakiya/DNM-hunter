"""
API Analyzer — shared merge-into-by_base_url helper.

Both the OpenAPI/Swagger importer and the Postman collection importer parse
their source into the same normalized endpoint list shape, then hand it to
`merge_api_endpoints_into_by_base_url()` here. This mirrors the merge
convention every other resource_enum source (Kiterunner, GAU, ParamSpider,
Arjun) already uses, so imported API endpoints flow into the exact same
Endpoint/Parameter graph nodes — and the same downstream nuclei/ffuf/vuln_scan
passes — as every other discovery source, instead of living in a separate
side channel.

Normalized endpoint dict shape (what parsers must produce):
    {
        "path": "/api/users/{id}",
        "methods": ["GET", "POST"],
        "parameters": {
            "query": [{"name": ..., "category": ..., "source": <label>}],
            "path":  [{"name": ..., "category": ..., "source": <label>}],
            "body":  [{"name": ..., "category": ..., "source": <label>}],
        },
        "summary": "optional human-readable description",
    }
"""

from typing import Dict, List, Tuple
from urllib.parse import urlparse

from recon.helpers.resource_enum.classification import classify_endpoint


def merge_api_endpoints_into_by_base_url(
    endpoints: List[Dict],
    by_base_url: Dict,
    base_url: str,
    source_label: str,
) -> Tuple[Dict, Dict[str, int]]:
    """Merge a normalized endpoint list (from OpenAPI or Postman parsing)
    into the existing by_base_url structure, under `base_url`.

    Mirrors merge_kiterunner_into_by_base_url()'s contract exactly: same
    endpoint dict shape, same sources-array convention, same summary
    bookkeeping — so the rest of resource_enum.py treats imported API
    endpoints identically to every other source.
    """
    stats = {f"{source_label}_total": len(endpoints), f"{source_label}_new": 0, f"{source_label}_overlap": 0}

    try:
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else base_url.rstrip('/')
    except Exception:
        base = base_url.rstrip('/')

    if base not in by_base_url:
        by_base_url[base] = {
            'base_url': base,
            'endpoints': {},
            'summary': {'total_endpoints': 0, 'total_parameters': 0, 'methods': {}, 'categories': {}},
        }

    endpoints_map = by_base_url[base]['endpoints']

    for ep in endpoints:
        path = ep.get('path', '')
        methods = ep.get('methods') or ['GET']
        if not path:
            continue

        if path in endpoints_map:
            stats[f"{source_label}_overlap"] += 1
            existing = endpoints_map[path]
            existing_sources = existing.get('sources', [])
            if not existing_sources:
                old_source = existing.pop('source', '')
                existing_sources = [old_source] if old_source else []
            if source_label not in existing_sources:
                existing_sources.append(source_label)
            existing['sources'] = existing_sources

            existing_methods = set(existing.get('methods', []))
            for method in methods:
                if method not in existing_methods:
                    existing.setdefault('methods', []).append(method)
                    by_base_url[base]['summary']['methods'][method] = \
                        by_base_url[base]['summary']['methods'].get(method, 0) + 1

            for position in ('query', 'path', 'body'):
                existing_params = existing.setdefault('parameters', {}).setdefault(position, [])
                existing_names = {p.get('name') if isinstance(p, dict) else p for p in existing_params}
                for param in (ep.get('parameters', {}) or {}).get(position, []):
                    if param.get('name') not in existing_names:
                        existing_params.append(param)
            if ep.get('summary') and not existing.get('summary'):
                existing['summary'] = ep['summary']
            continue

        stats[f"{source_label}_new"] += 1
        parameters = ep.get('parameters') or {'query': [], 'path': [], 'body': []}
        param_names = {
            (p.get('name') if isinstance(p, dict) else p)
            for pos in ('query', 'path', 'body')
            for p in parameters.get(pos, [])
        }
        category = classify_endpoint(path, methods, {'query': parameters.get('query', []), 'body': [], 'path': []})

        entry = {
            'methods': methods,
            'parameters': parameters,
            'sources': [source_label],
            'category': category,
            'status_code': 0,
            'parameter_count': {
                'query': len(parameters.get('query', [])),
                'path': len(parameters.get('path', [])),
                'body': len(parameters.get('body', [])),
                'total': len(param_names),
            },
        }
        if ep.get('summary'):
            entry['summary'] = ep['summary']
        endpoints_map[path] = entry

        summ = by_base_url[base]['summary']
        summ['total_endpoints'] += 1
        summ['total_parameters'] += len(param_names)
        summ['categories'][category] = summ['categories'].get(category, 0) + 1
        for method in methods:
            summ['methods'][method] = summ['methods'].get(method, 0) + 1

    return by_base_url, stats
