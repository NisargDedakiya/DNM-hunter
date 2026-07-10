"""
Tests for the API Analyzer (Phase 06): OpenAPI/Swagger importer, Postman
collection importer, and the shared by_base_url merge helper.
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.api_analyzer.openapi_importer import parse_openapi_spec
from recon.helpers.api_analyzer.postman_importer import parse_postman_collection
from recon.helpers.api_analyzer.merge import merge_api_endpoints_into_by_base_url


# ---------------------------------------------------------------------------
# OpenAPI / Swagger
# ---------------------------------------------------------------------------

def _openapi3_fixture():
    return {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0"},
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users/{id}": {
                "parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}],
                "get": {
                    "summary": "Get user",
                    "parameters": [{"name": "expand", "in": "query", "schema": {"type": "string"}}],
                },
                "delete": {"summary": "Delete user", "security": []},
            },
            "/users": {
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "content": {"application/json": {"schema": {"properties": {
                            "email": {"type": "string"}, "password": {"type": "string"},
                        }}}}
                    },
                }
            },
            "/health": {"get": {"summary": "Health check", "security": []}},
        },
    }


def test_openapi3_parses_all_paths_and_methods():
    endpoints = parse_openapi_spec(json.dumps(_openapi3_fixture()))
    assert endpoints is not None
    paths = {e["path"] for e in endpoints}
    assert paths == {"/users/{id}", "/users", "/health"}

    by_path = {e["path"]: e for e in endpoints}
    assert set(by_path["/users/{id}"]["methods"]) == {"GET", "DELETE"}
    assert by_path["/users"]["methods"] == ["POST"]


def test_openapi3_query_and_path_params_extracted():
    endpoints = parse_openapi_spec(json.dumps(_openapi3_fixture()))
    by_path = {e["path"]: e for e in endpoints}
    users_id = by_path["/users/{id}"]
    assert [p["name"] for p in users_id["parameters"]["query"]] == ["expand"]
    assert [p["name"] for p in users_id["parameters"]["path"]] == ["id"]


def test_openapi3_request_body_json_schema_becomes_body_params():
    endpoints = parse_openapi_spec(json.dumps(_openapi3_fixture()))
    by_path = {e["path"]: e for e in endpoints}
    body_names = {p["name"] for p in by_path["/users"]["parameters"]["body"]}
    assert body_names == {"email", "password"}
    # password should classify as an auth-relevant param, not "other"
    pw = next(p for p in by_path["/users"]["parameters"]["body"] if p["name"] == "password")
    assert pw["category"] == "auth_params"


def test_openapi3_explicit_empty_security_overrides_global_default():
    """An operation with `security: []` is explicitly public even though the
    spec has a global `security` requirement -- must not be flagged as
    requiring auth."""
    endpoints = parse_openapi_spec(json.dumps(_openapi3_fixture()))
    by_path = {e["path"]: e for e in endpoints}
    assert by_path["/health"]["requires_auth"] is False
    # /users inherits the global security requirement (no override)
    assert by_path["/users"]["requires_auth"] is True
    # /users/{id} requires auth because GET inherits the global default,
    # even though DELETE explicitly opts out
    assert by_path["/users/{id}"]["requires_auth"] is True


def test_swagger2_formdata_params_become_body_params():
    swagger2 = {
        "swagger": "2.0",
        "info": {"title": "Legacy API", "version": "1.0"},
        "paths": {
            "/login": {
                "post": {
                    "summary": "Login",
                    "parameters": [
                        {"name": "username", "in": "formData", "type": "string"},
                        {"name": "password", "in": "formData", "type": "string"},
                    ],
                }
            }
        },
    }
    endpoints = parse_openapi_spec(json.dumps(swagger2))
    assert endpoints is not None
    login = endpoints[0]
    body_names = {p["name"] for p in login["parameters"]["body"]}
    assert body_names == {"username", "password"}


def test_openapi_spec_without_paths_returns_none():
    assert parse_openapi_spec(json.dumps({"openapi": "3.0.0", "info": {}})) is None


def test_openapi_invalid_json_returns_none():
    assert parse_openapi_spec("{not valid json") is None


# ---------------------------------------------------------------------------
# Postman
# ---------------------------------------------------------------------------

def _postman_fixture():
    return {
        "info": {"name": "Test Collection", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [
            {
                "name": "Auth folder",
                "item": [
                    {
                        "name": "Login",
                        "request": {
                            "method": "POST",
                            "header": [],
                            "body": {"mode": "urlencoded", "urlencoded": [
                                {"key": "username", "value": ""}, {"key": "password", "value": ""},
                            ]},
                            "url": {"raw": "https://api.acme.example/v1/login"},
                        },
                    },
                ],
            },
            {
                "name": "Get order",
                "request": {
                    "method": "GET",
                    "auth": {"type": "bearer"},
                    "url": {
                        "raw": "https://api.acme.example/v1/orders/123?expand=items",
                        "query": [{"key": "expand", "value": "items"}],
                        "path": ["v1", "orders", "123"],
                    },
                },
            },
            {
                "name": "Create item (raw JSON)",
                "request": {
                    "method": "POST",
                    "body": {"mode": "raw", "raw": '{"name": "widget", "price": 9.99}'},
                    "url": {"raw": "https://api.acme.example/v1/items"},
                },
            },
        ],
    }


def test_postman_walks_nested_folders():
    result = parse_postman_collection(json.dumps(_postman_fixture()))
    assert result is not None
    paths = {e["path"] for e in result["https://api.acme.example"]}
    assert paths == {"/v1/login", "/v1/orders/123", "/v1/items"}


def test_postman_urlencoded_body_params_extracted():
    result = parse_postman_collection(json.dumps(_postman_fixture()))
    login = next(e for e in result["https://api.acme.example"] if e["path"] == "/v1/login")
    body_names = {p["name"] for p in login["parameters"]["body"]}
    assert body_names == {"username", "password"}


def test_postman_raw_json_body_params_extracted():
    result = parse_postman_collection(json.dumps(_postman_fixture()))
    create_item = next(e for e in result["https://api.acme.example"] if e["path"] == "/v1/items")
    body_names = {p["name"] for p in create_item["parameters"]["body"]}
    assert body_names == {"name", "price"}


def test_postman_query_params_from_structured_url():
    result = parse_postman_collection(json.dumps(_postman_fixture()))
    order = next(e for e in result["https://api.acme.example"] if e["path"] == "/v1/orders/123")
    assert [p["name"] for p in order["parameters"]["query"]] == ["expand"]


def test_postman_auth_field_sets_requires_auth():
    result = parse_postman_collection(json.dumps(_postman_fixture()))
    order = next(e for e in result["https://api.acme.example"] if e["path"] == "/v1/orders/123")
    login = next(e for e in result["https://api.acme.example"] if e["path"] == "/v1/login")
    assert order["requires_auth"] is True
    assert login["requires_auth"] is False


def test_postman_not_a_collection_returns_none():
    assert parse_postman_collection(json.dumps({"foo": "bar"})) is None


def test_postman_invalid_json_returns_none():
    assert parse_postman_collection("{not valid") is None


# ---------------------------------------------------------------------------
# Merge into by_base_url
# ---------------------------------------------------------------------------

def test_merge_creates_new_base_url_entry_when_none_exists():
    endpoints = parse_openapi_spec(json.dumps({
        "openapi": "3.0.0", "info": {},
        "paths": {"/ping": {"get": {"summary": "ping"}}},
    }))
    by_base_url, stats = merge_api_endpoints_into_by_base_url(endpoints, {}, "https://api.acme.example", "openapi")
    assert stats == {"openapi_total": 1, "openapi_new": 1, "openapi_overlap": 0}
    entry = by_base_url["https://api.acme.example"]["endpoints"]["/ping"]
    assert entry["sources"] == ["openapi"]
    assert entry["methods"] == ["GET"]


def test_merge_overlapping_path_appends_source_and_merges_methods():
    by_base_url = {
        "https://api.acme.example": {
            "base_url": "https://api.acme.example",
            "endpoints": {
                "/users": {
                    "methods": ["GET"], "parameters": {"query": [], "path": [], "body": []},
                    "sources": ["katana"], "category": "other", "status_code": 200,
                    "parameter_count": {"query": 0, "path": 0, "body": 0, "total": 0},
                },
            },
            "summary": {"total_endpoints": 1, "total_parameters": 0, "methods": {"GET": 1}, "categories": {"other": 1}},
        }
    }
    endpoints = parse_openapi_spec(json.dumps({
        "openapi": "3.0.0", "info": {},
        "paths": {"/users": {"post": {"summary": "create"}}},
    }))
    result, stats = merge_api_endpoints_into_by_base_url(endpoints, by_base_url, "https://api.acme.example", "openapi")
    entry = result["https://api.acme.example"]["endpoints"]["/users"]
    assert stats["openapi_overlap"] == 1
    assert set(entry["methods"]) == {"GET", "POST"}
    assert entry["sources"] == ["katana", "openapi"]


def test_merge_does_not_duplicate_existing_parameter_names():
    by_base_url = {
        "https://api.acme.example": {
            "base_url": "https://api.acme.example",
            "endpoints": {
                "/search": {
                    "methods": ["GET"],
                    "parameters": {"query": [{"name": "q", "category": "search_params", "source": "gau"}], "path": [], "body": []},
                    "sources": ["gau"], "category": "other", "status_code": 200,
                    "parameter_count": {"query": 1, "path": 0, "body": 0, "total": 1},
                },
            },
            "summary": {"total_endpoints": 1, "total_parameters": 1, "methods": {"GET": 1}, "categories": {"other": 1}},
        }
    }
    endpoints = parse_openapi_spec(json.dumps({
        "openapi": "3.0.0", "info": {},
        "paths": {"/search": {"get": {"summary": "search", "parameters": [
            {"name": "q", "in": "query", "schema": {"type": "string"}},
            {"name": "page", "in": "query", "schema": {"type": "integer"}},
        ]}}},
    }))
    result, _ = merge_api_endpoints_into_by_base_url(endpoints, by_base_url, "https://api.acme.example", "openapi")
    query_names = [p["name"] for p in result["https://api.acme.example"]["endpoints"]["/search"]["parameters"]["query"]]
    assert query_names == ["q", "page"]  # 'q' not duplicated, 'page' added
