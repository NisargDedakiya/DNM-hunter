"""Integration tests for the request-id correlation middleware (Phase 16).

Uses fastapi.testclient with a patched lifespan so the import doesn't spin a
real orchestrator / Neo4j / kali-sandbox — same pattern as
test_agent_cors_and_baseurl_endpoint.py.

Run with: python -m unittest tests.test_request_id_middleware -v
"""

import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


class _AppTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module
            from fastapi.testclient import TestClient
            cls.client = TestClient(api_module.app)


class RequestIdMiddlewareTests(_AppTestBase):
    def test_response_always_carries_an_x_request_id(self):
        resp = self.client.get("/health")
        self.assertIn("x-request-id", resp.headers)
        self.assertTrue(resp.headers["x-request-id"])

    def test_no_incoming_header_generates_a_fresh_id(self):
        resp = self.client.get("/health")
        request_id = resp.headers["x-request-id"]
        self.assertNotEqual(request_id, "-")
        self.assertEqual(len(request_id), 12)

    def test_incoming_x_request_id_is_echoed_back_unchanged(self):
        resp = self.client.get("/health", headers={"X-Request-ID": "webapp-trace-12345"})
        self.assertEqual(resp.headers["x-request-id"], "webapp-trace-12345")

    def test_two_requests_without_a_header_get_different_generated_ids(self):
        resp1 = self.client.get("/health")
        resp2 = self.client.get("/health")
        self.assertNotEqual(resp1.headers["x-request-id"], resp2.headers["x-request-id"])

    def test_the_context_var_is_reset_between_requests(self):
        from logging_config import get_request_id

        self.client.get("/health", headers={"X-Request-ID": "leaked-id-should-not-persist"})
        # Outside of any request (here, in the test process itself, after the
        # TestClient call has returned), the contextvar must be back to "-".
        self.assertEqual(get_request_id(), "-")

    def test_existing_endpoint_behavior_is_unaffected(self):
        # The middleware must be transparent: /health's own response body/
        # status is unchanged by adding request-id tracking.
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
