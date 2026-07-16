"""Tests for the dynamic live-HTTP security scanner (web_probe).

The pure analyzer is tested with synthetic responses (no network). A single
end-to-end test spins up a local HTTP server with deliberately bad headers.

Run: python -m unittest web_probe.tests.test_web_probe -v
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from web_probe import analyze_response, probe_url


def rules(f):
    return {x.rule_id for x in f}


class TestAnalyzer(unittest.TestCase):
    def test_missing_headers_flagged(self):
        got = rules(analyze_response(200, {"Content-Type": "text/html"}, "<html></html>",
                                     "https://x.example"))
        for r in ("WP-HSTS", "WP-CSP", "WP-XCTO", "WP-XFO"):
            self.assertIn(r, got)

    def test_all_headers_present_quiet(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        got = rules(analyze_response(200, headers, "<html></html>", "https://x.example"))
        for r in ("WP-HSTS", "WP-CSP", "WP-XCTO", "WP-XFO"):
            self.assertNotIn(r, got)

    def test_csp_frame_ancestors_satisfies_clickjacking(self):
        headers = {"Content-Security-Policy": "frame-ancestors 'none'"}
        self.assertNotIn("WP-XFO", rules(analyze_response(200, headers, "", "https://x.example")))

    def test_insecure_session_cookie(self):
        headers = {"Set-Cookie": "sessionid=abc; Path=/"}
        got = analyze_response(200, headers, "", "https://x.example")
        r = rules(got)
        self.assertIn("WP-COOKIE-SECURE", r)
        self.assertIn("WP-COOKIE-HTTPONLY", r)
        self.assertIn("WP-COOKIE-SAMESITE", r)
        # session cookie → medium severity
        self.assertTrue(any(x.rule_id == "WP-COOKIE-HTTPONLY" and x.severity == "medium" for x in got))

    def test_secure_cookie_quiet(self):
        headers = {"Set-Cookie": "sessionid=abc; Secure; HttpOnly; SameSite=Strict"}
        self.assertFalse(rules(analyze_response(200, headers, "", "https://x.example"))
                         & {"WP-COOKIE-SECURE", "WP-COOKIE-HTTPONLY", "WP-COOKIE-SAMESITE"})

    def test_cors_wildcard_with_credentials_is_high(self):
        headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        got = analyze_response(200, headers, "", "https://x.example")
        self.assertTrue(any(x.rule_id == "WP-CORS-WILDCARD-CREDS" and x.severity == "high" for x in got))

    def test_unsafe_methods_from_allow(self):
        got = rules(analyze_response(200, {}, "", "https://x.example", method_allow="GET, POST, TRACE, PUT"))
        self.assertIn("WP-METHOD-TRACE", got)
        self.assertIn("WP-METHOD-PUT", got)

    def test_banner_and_debug_and_dirlist(self):
        headers = {"Server": "Apache/2.4.29", "X-Powered-By": "PHP/7.2.1"}
        body = "<title>Index of /uploads</title> Traceback (most recent call last): boom"
        got = rules(analyze_response(200, headers, body, "https://x.example"))
        self.assertIn("WP-BANNER-SERVER", got)
        self.assertIn("WP-BANNER-XPB", got)
        self.assertIn("WP-DIRLIST", got)
        self.assertIn("WP-DEBUG-PAGE", got)

    def test_cleartext_http_flagged(self):
        self.assertIn("WP-CLEARTEXT", rules(analyze_response(200, {}, "", "http://x.example")))


class _BadHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Set-Cookie", "sessionid=xyz; Path=/")
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")


class TestLive(unittest.TestCase):
    def test_probe_local_server(self):
        srv = HTTPServer(("127.0.0.1", 0), _BadHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            got = rules(probe_url(f"http://127.0.0.1:{port}/"))
        finally:
            srv.shutdown()
        # cleartext + missing headers + banner + insecure cookie
        self.assertIn("WP-CLEARTEXT", got)
        self.assertIn("WP-CSP", got)
        self.assertIn("WP-BANNER-SERVER", got)
        self.assertIn("WP-COOKIE-HTTPONLY", got)


if __name__ == "__main__":
    unittest.main()
