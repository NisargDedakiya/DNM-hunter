---
name: HTTP Request Smuggling
description: Reference for HTTP/1.1 request smuggling (CL.TE, TE.CL, TE.TE desync) detection and exploitation across front-end/back-end server chains, including safe black-box confirmation before any exploitation attempt.
---

# HTTP Request Smuggling

Tactical reference for finding and exploiting desync bugs between a front-end (proxy/load balancer/CDN) and a back-end server that disagree about where one HTTP/1.1 request ends and the next begins. Pull this in when a target sits behind a reverse proxy or CDN (nearly everything does) and you want to check whether that boundary is exploitable.

> **Distinct from CRLF injection** (`/skill crlf_injection`), which is response-header injection on a single request/response. Smuggling is a transport-layer desync across *multiple* requests sharing a connection.

> **Higher blast radius than most probes here.** A successful desync can smuggle a fragment of *your* request onto the front of the *next real user's* request on that connection — on shared production infrastructure that means potentially reading or corrupting another user's traffic, not just your own. Confirm with the safe timing technique below before attempting anything that queues a real payload. Get explicit operator sign-off before any exploitation step, not just detection.

## Why normal HTTP clients can't test this

`requests`, `httpx`, `curl`, and every well-behaved HTTP library will refuse to send a request with both a `Content-Length` and a `Transfer-Encoding` header, or will normalize/reject malformed chunked bodies — exactly the malformed input smuggling requires. Testing this needs a raw TCP socket where you control every byte, including deliberately "invalid" framing.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Raw socket request with exact byte control | `execute_code` | Python `socket`/`ssl` — see template below. Never use `requests`/`httpx` for the probe itself. |
| Timing-based detection (safe, non-destructive) | `execute_code` | Single request, measure response latency; no second request is ever sent through the poisoned connection. |
| TLS handshake for HTTPS targets | `execute_code` | `ssl.wrap_socket` / `ssl.SSLContext` around the raw socket, SNI set explicitly. |
| Differential confirmation via HTTP/2 downgrade | `execute_code` | If the front-end speaks HTTP/2 to clients but HTTP/1.1 upstream, the request-line/header smuggling surface shifts to H2->H1 desync — same socket-level approach, H2 framing instead of chunked encoding. |
| Verify a candidate front-end/back-end pair exists | `query_graph` | Look for CDN/WAF markers (`is_cdn`, `cdn_name`) on the IP plus a distinct `Server` header banner on the HTTP response — a mismatch is the precondition for this class. |

## The three classic desync shapes

Both `Content-Length` (CL) and `Transfer-Encoding: chunked` (TE) can indicate where a request body ends. When a request carries **both** headers, RFC 7230 says `Transfer-Encoding` wins and `Content-Length` must be ignored — but many real implementations get this wrong, and that disagreement is the bug.

| Shape | Front-end uses | Back-end uses | Effect |
|---|---|---|---|
| **CL.TE** | `Content-Length` | `Transfer-Encoding` | Back-end treats the body as chunked, finds the terminating `0\r\n\r\n` early, and treats the leftover bytes as the start of the *next* request. |
| **TE.CL** | `Transfer-Encoding` | `Content-Length` | Front-end forwards the whole chunked body; back-end only reads `Content-Length` bytes of it, leaving a chunk-encoded remainder to be misread as the next request's start. |
| **TE.TE** | `Transfer-Encoding` (obfuscated) | `Transfer-Encoding` | Both honor TE, but one of them can be tricked into *not* recognizing an obfuscated `Transfer-Encoding` header (case, whitespace, or tab tricks below), effectively downgrading it to the CL.TE or TE.CL case. |

### TE obfuscation variants worth trying for TE.TE

One of the two servers needs to fail to recognize the header as `Transfer-Encoding` while the other does. Try each independently:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding: chunked           (trailing tab, not space)
Transfer-Encoding: cow
Transfer-Encoding:[tab]chunked
X: X[\n]Transfer-Encoding: chunked   (line-wrapped injection)
 Transfer-Encoding: chunked          (leading space, header continuation lie)
Transfer-Encoding
 : chunked
```

## Detection: the safe timing technique first

Never start with a two-request exploitation attempt on shared infrastructure — start with a single request that only causes a delay if the back-end is left waiting for more data. This confirms the desync without ever smuggling a real fragment onto another connection.

**CL.TE probe** — send a request whose declared `Content-Length` is longer than the actual body, with an unterminated chunk. If the back-end honors `Transfer-Encoding` (ignoring the correct `Content-Length`), it finishes reading the chunked body immediately; if it's *not* vulnerable and honors `Content-Length` here, it will hang waiting for the extra declared byte:

```
execute_code language: python
import socket, ssl, time

HOST, PORT = "target.tld", 443

def send_raw(payload: bytes, host=HOST, port=PORT, tls=True, timeout=10) -> tuple[bytes, float]:
    raw = socket.create_connection((host, port), timeout=timeout)
    s = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if tls else raw
    start = time.monotonic()
    s.sendall(payload)
    try:
        s.settimeout(timeout)
        data = s.recv(65536)
    except socket.timeout:
        data = b"<TIMEOUT>"
    elapsed = time.monotonic() - start
    s.close()
    return data, elapsed

# CL.TE probe: declares Content-Length: 4 but the chunked body's terminator
# is followed by one extra byte the front-end will forward as part of THIS
# request's declared length, but the back-end (reading by TE) has already
# terminated on "0\r\n\r\n" -- if vulnerable, response comes back fast anyway;
# a non-vulnerable back-end reading by CL will hang waiting for that byte.
body = "1\r\nA\r\n0\r\n\r\nX"  # note trailing X with no following blank line
req = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"\r\n"
    f"{body}"
).encode()

resp, elapsed = send_raw(req)
print(f"elapsed={elapsed:.2f}s resp={resp[:200]!r}")
# elapsed significantly higher than a normal baseline request (~1x RTT) is
# the CL.TE signal. Run a baseline (ordinary GET /) first for comparison.
```

**TE.CL probe** — mirror image: send a `Content-Length` that's short, with a chunked body the front-end will forward in full. If the back-end reads by `Content-Length` only, it responds immediately and leaves the chunk remainder unread on the socket (confirm by sending a second, differently-shaped request next on the *same connection* and observing a mangled/mismatched response — but only do this once timing already suggests a hit).

Always run a same-shaped baseline request first (well-formed, no ambiguity) and compare timing/behavior — a slow network alone will produce false positives without a baseline.

## Exploitation categories, once confirmed

- **Front-end security control bypass** — smuggle a request path that the front-end's WAF/auth-gate would normally block, prefixed onto a request the front-end considers benign, so only the back-end ever parses the smuggled portion.
- **Session/response hijacking** — poison the next request on a shared connection (common with front-ends that reuse back-end connections across different clients) so another user's request gets *your* smuggled response, or your smuggled request gets appended to *their* session.
- **Cache poisoning via smuggling** — combine with `/skill web_cache_poisoning`: smuggle a request whose response gets cached under a shared cache key, poisoning it for every subsequent visitor.
- **Request queue desync at scale** — repeated smuggled prefixes can desync the entire connection pool between front-end and back-end, affecting many concurrent users; this is squarely in "notify the operator before attempting" territory.

## Reporting

Capture the exact raw request bytes sent (not a reconstructed cURL command — smuggling payloads rely on framing curl would normalize away), the timing delta vs. baseline, and — where you went further than detection — the smuggled artifact actually observed (a fragment of another session, a bypassed control, a poisoned cache entry). CVSS and impact should reflect the shared-infrastructure blast radius, not just the single request that triggered it.
