"""Tests for plugin health probing (Phase 16e).

Run with: python -m unittest tests.test_plugin_health -v
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.plugin_catalog import check_plugins_health  # noqa: E402


class TestPluginHealth(unittest.TestCase):
    def test_builtin_and_webapp_subsystem_report_active_without_network(self):
        plugins = [
            {"id": "a", "kind": "builtin"},
            {"id": "b", "kind": "webapp-subsystem"},
        ]
        with patch("asyncio.open_connection", side_effect=AssertionError("should not be called")):
            results = asyncio.run(check_plugins_health(plugins))
        by_id = {r["id"]: r for r in results}
        self.assertEqual(by_id["a"]["health"], "active")
        self.assertEqual(by_id["b"]["health"], "active")

    def test_mcp_server_missing_manifest_fields_reports_unknown(self):
        plugins = [{"id": "c", "kind": "mcp-server"}]
        results = asyncio.run(check_plugins_health(plugins))
        self.assertEqual(results[0]["health"], "unknown")

    def test_mcp_server_reachable_reports_healthy(self):
        plugins = [{"id": "d", "kind": "mcp-server", "dockerService": "kali-sandbox", "mcpPort": 8002}]

        class FakeWriter:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def fake_open_connection(host, port):
            self.assertEqual(host, "kali-sandbox")
            self.assertEqual(port, 8002)
            return None, FakeWriter()

        with patch("asyncio.open_connection", side_effect=fake_open_connection):
            results = asyncio.run(check_plugins_health(plugins))
        self.assertEqual(results[0]["health"], "healthy")
        self.assertIsNotNone(results[0]["latencyMs"])

    def test_mcp_server_unreachable_reports_unreachable_not_an_exception(self):
        plugins = [{"id": "e", "kind": "mcp-server", "dockerService": "kali-sandbox", "mcpPort": 9999}]

        async def fake_open_connection(host, port):
            raise ConnectionRefusedError("nope")

        with patch("asyncio.open_connection", side_effect=fake_open_connection):
            results = asyncio.run(check_plugins_health(plugins))
        self.assertEqual(results[0]["health"], "unreachable")
        self.assertIn("ConnectionRefusedError", results[0]["detail"])

    def test_one_bad_plugin_does_not_take_down_the_batch(self):
        plugins = [
            {"id": "ok", "kind": "builtin"},
            {"id": "bad", "kind": "mcp-server", "dockerService": "kali-sandbox", "mcpPort": 9999},
        ]

        async def fake_open_connection(host, port):
            raise OSError("timeout")

        with patch("asyncio.open_connection", side_effect=fake_open_connection):
            results = asyncio.run(check_plugins_health(plugins))
        by_id = {r["id"]: r for r in results}
        self.assertEqual(by_id["ok"]["health"], "active")
        self.assertEqual(by_id["bad"]["health"], "unreachable")


if __name__ == "__main__":
    unittest.main()
