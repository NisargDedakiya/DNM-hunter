"""
Postman Collection Importer
=============================
Parses a Postman Collection v2.0/v2.1 export (the format Postman's own
"Export" button produces) into the same normalized endpoint list shape the
OpenAPI importer produces, via merge.py's shared merge_api_endpoints_into_by_base_url().

Collections nest requests inside folders (`item` arrays containing more
`item` arrays), so this walks the tree recursively rather than assuming a
flat list.
"""

import json
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from recon.helpers.resource_enum.classification import classify_parameter


def _extract_url_parts(url_field) -> tuple[str, str, list]:
    """Postman's `request.url` is either a raw string or a structured object
    with `raw`, `host`, `path`, `query`. Returns (base_url, path, query_params).
    """
    if isinstance(url_field, str):
        raw = url_field
    elif isinstance(url_field, dict):
        raw = url_field.get('raw', '')
    else:
        return '', '', []

    # Postman variables like {{baseUrl}}/{{version}}/users are common —
    # leave them as literal path segments rather than guessing substitutions.
    try:
        parsed = urlparse(raw)
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ''
        path = parsed.path or '/'
        query_names = list(parse_qs(parsed.query).keys())
    except Exception:
        base, path, query_names = '', raw, []

    # Structured form gives explicit query param names even when raw parsing
    # above misses them (e.g. Postman variable-only queries).
    if isinstance(url_field, dict):
        for q in (url_field.get('query') or []):
            if isinstance(q, dict) and q.get('key') and q['key'] not in query_names:
                query_names.append(q['key'])

    return base, path or '/', query_names


def _extract_body_param_names(body_field) -> List[str]:
    if not isinstance(body_field, dict):
        return []
    mode = body_field.get('mode')
    names = []
    if mode == 'urlencoded':
        for item in (body_field.get('urlencoded') or []):
            if isinstance(item, dict) and item.get('key'):
                names.append(item['key'])
    elif mode == 'formdata':
        for item in (body_field.get('formdata') or []):
            if isinstance(item, dict) and item.get('key'):
                names.append(item['key'])
    elif mode == 'raw':
        raw = body_field.get('raw', '')
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                names = list(parsed.keys())
        except (json.JSONDecodeError, ValueError):
            pass
    return names


def _walk_items(items: List[Dict], collected: List[Dict]) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        # Folders have a nested `item` array and no `request` of their own.
        if 'item' in item and isinstance(item['item'], list):
            _walk_items(item['item'], collected)
            continue

        request = item.get('request')
        if not isinstance(request, dict):
            continue

        method = str(request.get('method') or 'GET').upper()
        base_url, path, query_names = _extract_url_parts(request.get('url'))
        body_names = _extract_body_param_names(request.get('body'))
        auth = request.get('auth')

        collected.append({
            'name': item.get('name', ''),
            'method': method,
            'base_url': base_url,
            'path': path,
            'query_params': query_names,
            'body_params': body_names,
            'requires_auth': bool(auth),
        })


def parse_postman_collection(collection_json: str) -> Optional[List[Dict]]:
    """Parse a Postman Collection export into a normalized endpoint list,
    grouped by base_url (since a collection can span multiple hosts/environments).

    Returns a dict of {base_url: [endpoint, ...]} so callers can merge each
    group into the right by_base_url entry, or None if the JSON is invalid
    or doesn't look like a Postman collection.
    """
    try:
        collection = json.loads(collection_json)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!][Postman] Invalid JSON: {e}")
        return None

    if not isinstance(collection, dict) or 'item' not in collection:
        print(f"[!][Postman] Doesn't look like a Postman collection (no top-level 'item')")
        return None

    raw_requests: List[Dict] = []
    _walk_items(collection.get('item') or [], raw_requests)

    grouped: Dict[str, Dict[str, Dict]] = {}
    for req in raw_requests:
        base = req['base_url'] or '(unknown host)'
        path_map = grouped.setdefault(base, {})
        entry = path_map.setdefault(req['path'], {
            'path': req['path'], 'methods': [], 'parameters': {'query': [], 'path': [], 'body': []},
            'summary': req['name'][:200], 'requires_auth': False,
        })
        if req['method'] not in entry['methods']:
            entry['methods'].append(req['method'])
        entry['requires_auth'] = entry['requires_auth'] or req['requires_auth']

        existing_query = {p['name'] for p in entry['parameters']['query']}
        for name in req['query_params']:
            if name not in existing_query:
                entry['parameters']['query'].append({'name': name, 'category': classify_parameter(name), 'source': 'postman'})
                existing_query.add(name)

        existing_body = {p['name'] for p in entry['parameters']['body']}
        for name in req['body_params']:
            if name not in existing_body:
                entry['parameters']['body'].append({'name': name, 'category': classify_parameter(name), 'source': 'postman'})
                existing_body.add(name)

    total = sum(len(v) for v in grouped.values())
    print(f"[+][Postman] Parsed {total} endpoints across {len(grouped)} host(s)")
    return {base: list(paths.values()) for base, paths in grouped.items()}
