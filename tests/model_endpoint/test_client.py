"""CONF-MEQ-001A: the client over socket.socketpair() with an in-thread fake HTTP/1.1 responder; never TCP, loopback
included (the verify sandbox denies it; MEQ-CLIENT-0 dossier, section 2). The default connection factory is patched to
fail in every test. Public-address vectors are documentation addresses (RFC 5737).
"""
import ast
import json
import os
import socket
import threading
import time
import unittest
import http.client
from pathlib import Path
from unittest import mock

import _client

HERE = Path(__file__).resolve().parent
BASE = "http://127.0.0.1:11434"
PROFILE = "dev-macos-arm64"
GUARDED = ("http", "127.0.0.1", 11434, 2.0)
HOLD = object()
PUBLIC_PROXY = "http://192.0.2.10:3128"
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
ALLOWED_IMPORTS = {"http.client", "ipaddress", "json", "socket", "time"}


def response(status, body=b"", reason="OK", headers=(), length=True):
    lines = ["HTTP/1.1 %d %s" % (status, reason)] + ["%s: %s" % pair for pair in headers]
    if length:
        lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def json_response(value, status=200):
    return response(status, json.dumps(value).encode("ascii"), headers=(("Content-Type", "application/json"),))


def chunked(pieces, content_type="text/event-stream"):
    out = ("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
           % content_type).encode("ascii")
    for piece in pieces:
        out += b"%x\r\n%s\r\n" % (len(piece), piece)
    return out + b"0\r\n\r\n"


def stream(body):
    return response(200, body, headers=(("Content-Type", "text/event-stream"),))


def read_request(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


class Fake:
    """One in-thread responder per connection, each on its own socketpair end; replies are served in order."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []
        self.requests = []
        self.eof = []
        self.threads = []

    def factory(self, scheme, address, port, connect_timeout):
        self.calls.append((scheme, address, port, connect_timeout))
        if not self.replies:
            raise AssertionError("an unexpected further connection")
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        client_end, server_end = socket.socketpair()
        thread = threading.Thread(target=self.serve, args=(server_end, reply), daemon=True)
        self.threads.append(thread)
        thread.start()
        return client_end

    def serve(self, sock, reply):
        with sock:
            sock.settimeout(10)
            try:
                self.requests.append(read_request(sock))
                if reply is not HOLD:
                    sock.sendall(reply)
                    sock.shutdown(socket.SHUT_WR)
                while sock.recv(65536):
                    pass
                self.eof.append(True)
            except OSError:
                self.eof.append(False)

    def join(self):
        for thread in self.threads:
            thread.join(15)


def _forbidden(name):
    def call(*args, **kwargs):
        raise AssertionError(name + " was called")
    return call


class ClientCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(_client, "default_connection_factory", _forbidden("the default connection factory"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake(self, *replies):
        fake = Fake(*replies)
        self.addCleanup(fake.join)
        return fake

    def client(self, fake, base=BASE, profile=PROFILE, request_timeout_s=5.0):
        return _client.MeqClient(base, profile, factory=fake.factory, request_timeout_s=request_timeout_s)

    def error(self, call):
        with self.assertRaises(_client.MeqError) as caught:
            call()
        return caught.exception


class RoundTripTests(ClientCase):
    def test_json_get_round_trip(self):
        fake = self.fake(json_response({"object": "list", "data": [{"id": "m1"}]}))
        self.assertEqual(self.client(fake).get_json("/v1/models"), {"object": "list", "data": [{"id": "m1"}]})
        fake.join()
        self.assertEqual(fake.calls, [GUARDED])
        request = fake.requests[0]
        self.assertTrue(request.startswith(b"GET /v1/models HTTP/1.1\r\n"))
        for header in (b"Host: 127.0.0.1:11434", b"Accept: application/json", b"Connection: close"):
            self.assertIn(b"\r\n" + header + b"\r\n", request)
        self.assertEqual(fake.eof, [True])

    def test_the_base_path_and_an_ipv6_literal(self):
        fake = self.fake(json_response({"ok": True}))
        self.assertEqual(self.client(fake, base="http://[::1]:8080/v1/").get_json("/models"), {"ok": True})
        fake.join()
        self.assertEqual(fake.calls, [("http", "::1", 8080, 2.0)])
        self.assertTrue(fake.requests[0].startswith(b"GET /v1/models HTTP/1.1\r\n"))
        self.assertIn(b"\r\nHost: [::1]:8080\r\n", fake.requests[0])

    def test_json_post_round_trip(self):
        payload = {"model": "m1", "messages": [{"role": "user", "content": "Say ok."}], "stream": False}
        fake = self.fake(json_response({"choices": [{"message": {"content": "ok"}}]}))
        self.assertEqual(self.client(fake).post_json("/v1/chat/completions", payload),
                         {"choices": [{"message": {"content": "ok"}}]})
        fake.join()
        head, _, body = fake.requests[0].partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"POST /v1/chat/completions HTTP/1.1\r\n"))
        self.assertIn(b"\r\nContent-Type: application/json", head + b"\r\n")
        self.assertEqual(body, json.dumps(payload, separators=(",", ":")).encode("ascii"))

    def test_sse_streaming_up_to_done(self):
        frames = [b'data: {"choices":[{"delta":{"content":"o"}}]}\n\n', b": keep-alive\n\n",
                  b'event: message\nid: 2\nretry: 10\ndata: {"choices":[{"delta":{"content":"k"}}]}\n\n',
                  b'data: {"choices":[],"usage":{"total_tokens":3}}\n\n', b"data: [DONE]\n\n"]
        expected = [{"choices": [{"delta": {"content": "o"}}]}, {"choices": [{"delta": {"content": "k"}}]},
                    {"choices": [], "usage": {"total_tokens": 3}}]
        for name, reply in (("content-length", stream(b"".join(frames))), ("chunked", chunked(frames)),
                            ("crlf", stream(b"".join(frames).replace(b"\n", b"\r\n")))):
            with self.subTest(framing=name):
                fake = self.fake(reply)
                self.assertEqual(self.client(fake).post_stream("/v1/chat/completions", {"stream": True}), expected)
                fake.join()
                self.assertIn(b"\r\nAccept: text/event-stream\r\n", fake.requests[0])
                self.assertEqual(fake.calls, [GUARDED])

    def test_one_request_per_connection(self):
        fake = self.fake(json_response({"n": 1}), json_response({"n": 2}))
        client = self.client(fake)
        self.assertEqual([client.get_json("/v1/models"), client.get_json("/v1/models")], [{"n": 1}, {"n": 2}])
        fake.join()
        self.assertEqual(fake.calls, [GUARDED, GUARDED])
        self.assertEqual(fake.eof, [True, True])
        self.assertTrue(all(b"\r\nConnection: close\r\n" in request for request in fake.requests))


class RefusalTests(ClientCase):
    def test_a_redirect_to_a_public_address_is_refused_and_never_followed(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                fake = self.fake(response(status, reason="Moved", headers=(("Location", "http://198.51.100.7/v1/models"),)),
                                 json_response({"followed": True}))
                error = self.error(lambda: self.client(fake).get_json("/v1/models"))
                self.assertEqual((error.code, error.status), ("MEQ_REDIRECT_REFUSED", status))
                fake.join()
                self.assertEqual(fake.calls, [GUARDED])
                self.assertEqual(len(fake.replies), 1)

    def test_proxy_environment_variables_have_no_effect(self):
        environment = {name: PUBLIC_PROXY for name in PROXY_VARIABLES}
        environment.update({"NO_PROXY": "", "no_proxy": ""})
        frames = b'data: {"a":1}\n\ndata: [DONE]\n\n'
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(socket, "create_connection", _forbidden("socket.create_connection")), \
                mock.patch.object(socket, "getaddrinfo", _forbidden("socket.getaddrinfo")), \
                mock.patch.object(socket.socket, "connect", _forbidden("socket.socket.connect")), \
                mock.patch.object(http.client.HTTPConnection, "connect", _forbidden("HTTPConnection.connect")):
            for base, scheme in ((BASE, "http"), ("https://127.0.0.1:11434", "https")):
                with self.subTest(scheme=scheme):
                    fake = self.fake(json_response({"a": 1}), json_response({"b": 2}), stream(frames))
                    client = self.client(fake, base=base)
                    self.assertEqual(client.get_json("/v1/models"), {"a": 1})
                    self.assertEqual(client.post_json("/v1/embeddings", {"input": "x"}), {"b": 2})
                    self.assertEqual(client.post_stream("/v1/chat/completions", {"stream": True}), [{"a": 1}])
                    fake.join()
                    self.assertEqual(fake.calls, [(scheme, "127.0.0.1", 11434, 2.0)] * 3)
                    # Origin-form request targets only: a proxied request would carry the absolute URL.
                    self.assertEqual([request.split(b"\r\n", 1)[0] for request in fake.requests],
                                     [b"GET /v1/models HTTP/1.1", b"POST /v1/embeddings HTTP/1.1",
                                      b"POST /v1/chat/completions HTTP/1.1"])
                    self.assertFalse([request for request in fake.requests if b"192.0.2.10" in request])

    def test_http_client_and_server_errors_carry_the_status_and_a_parsed_body(self):
        cases = ((404, "MEQ_HTTP_CLIENT_ERROR", json_response({"error": {"message": "model not found"}}, 404),
                  {"error": {"message": "model not found"}}),
                 (400, "MEQ_HTTP_CLIENT_ERROR", response(400, b"not json", reason="Bad Request"), None),
                 (500, "MEQ_HTTP_SERVER_ERROR", json_response({"error": {"message": "boom"}}, 500),
                  {"error": {"message": "boom"}}),
                 (503, "MEQ_HTTP_SERVER_ERROR", response(503, reason="Unavailable"), None))
        for status, code, reply, body in cases:
            with self.subTest(status=status):
                fake = self.fake(reply)
                error = self.error(lambda: self.client(fake).get_json("/v1/models"))
                self.assertEqual((error.code, error.status, error.body), (code, status, body))

    def test_connect_failure_and_connect_timeout(self):
        for raised, code in ((ConnectionRefusedError(), "MEQ_CONNECT_FAILED"), (OSError(), "MEQ_CONNECT_FAILED"),
                             (TimeoutError(), "MEQ_CONNECT_TIMEOUT")):
            with self.subTest(code=code, raised=type(raised).__name__):
                fake = self.fake(raised)
                self.assertEqual(self.error(lambda: self.client(fake).get_json("/v1/models")).code, code)
                self.assertEqual(fake.calls, [GUARDED])

    def test_a_read_timeout(self):
        fake = self.fake(HOLD)
        started = time.monotonic()
        error = self.error(lambda: self.client(fake, request_timeout_s=0.2).get_json("/v1/models"))
        self.assertEqual(error.code, "MEQ_READ_TIMEOUT")
        self.assertLess(time.monotonic() - started, 5)
        fake.join()
        self.assertEqual(fake.eof, [True])

    def test_an_oversize_body(self):
        declared = ("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                    % (_client.MAX_RESPONSE_BYTES + 1)).encode("ascii")
        fake = self.fake(declared)
        self.assertEqual(self.error(lambda: self.client(fake).get_json("/v1/models")).code, "MEQ_OVERSIZE")
        with mock.patch.object(_client, "MAX_RESPONSE_BYTES", 1024):
            for name, reply in (("close-delimited", response(200, b"[" + b"0," * 1200 + b"0]", length=False)),
                                ("chunked", chunked([b"[" + b"0," * 600, b"0," * 600 + b"0]"], "application/json"))):
                with self.subTest(framing=name):
                    fake = self.fake(reply)
                    self.assertEqual(self.error(lambda: self.client(fake).get_json("/v1/models")).code, "MEQ_OVERSIZE")

    def test_an_oversize_event_line_and_stream(self):
        with mock.patch.object(_client, "MAX_SSE_LINE_BYTES", 64):
            fake = self.fake(stream(b'data: {"x":"' + b"y" * 200 + b'"}\n\ndata: [DONE]\n\n'))
            self.assertEqual(self.error(lambda: self.client(fake).post_stream("/v1/x", {})).code, "MEQ_OVERSIZE")
        with mock.patch.object(_client, "MAX_SSE_TOTAL_BYTES", 256):
            fake = self.fake(stream(b'data: {"x":1}\n\n' * 40 + b"data: [DONE]\n\n"))
            self.assertEqual(self.error(lambda: self.client(fake).post_stream("/v1/x", {})).code, "MEQ_OVERSIZE")

    def test_malformed_json(self):
        for body in (b"{", b'{"a": NaN}', b'{"a": Infinity}', b"\xff\xfe", b""):
            with self.subTest(body=body):
                fake = self.fake(response(200, body))
                self.assertEqual(self.error(lambda: self.client(fake).get_json("/v1/models")).code, "MEQ_MALFORMED_JSON")
        fake = self.fake(stream(b"data: not json\n\ndata: [DONE]\n\n"))
        self.assertEqual(self.error(lambda: self.client(fake).post_stream("/v1/x", {})).code, "MEQ_MALFORMED_JSON")

    def test_a_broken_sse_frame(self):
        for name, body in (("no field", b"garbage\n\ndata: [DONE]\n\n"), ("unknown field", b"bogus: 1\n\ndata: [DONE]\n\n"),
                           ("no done", b'data: {"a":1}\n\n'), ("mid-line end", b'data: {"a":1}'),
                           ("bare carriage return", b'data: {"a":1}\rdata: [DONE]\n\n'),
                           ("not utf-8", b"data: \xff\n\ndata: [DONE]\n\n")):
            with self.subTest(frame=name):
                fake = self.fake(stream(body))
                self.assertEqual(self.error(lambda: self.client(fake).post_stream("/v1/x", {})).code, "MEQ_SSE_FRAMING")

    def test_a_protocol_error_and_a_lost_connection(self):
        for name, reply, code in (("garbage status line", b"NOT HTTP\r\n\r\n", "MEQ_PROTOCOL_ERROR"),
                                  ("status class 6xx", response(600, reason="Odd"), "MEQ_PROTOCOL_ERROR"),
                                  ("closed without an answer", b"", "MEQ_CONNECTION_LOST"),
                                  ("short body", response(200, b'{"a":1}')[:-3], "MEQ_CONNECTION_LOST")):
            with self.subTest(case=name):
                fake = self.fake(reply)
                self.assertEqual(self.error(lambda: self.client(fake).get_json("/v1/models")).code, code)

    def test_cancellation_closes_the_connection(self):
        polls = []

        def cancel():
            polls.append(1)
            return len(polls) > 2

        frames = b'data: {"a":1}\n\ndata: {"a":2}\n\ndata: [DONE]\n\n'
        fake = self.fake(stream(frames))
        self.assertEqual(self.error(lambda: self.client(fake).post_stream("/v1/x", {}, cancel=cancel)).code,
                         "MEQ_CANCELLED")
        fake.join()
        self.assertEqual(len(polls), 3)
        self.assertEqual(fake.eof, [True])

    def test_invalid_configuration(self):
        fake = self.fake()
        for name, call in (("unknown profile", lambda: _client.MeqClient(BASE, "dev-macos-x86", factory=fake.factory)),
                           ("timeout above the profile's", lambda: self.client(fake, request_timeout_s=30.5)),
                           ("zero timeout", lambda: self.client(fake, request_timeout_s=0)),
                           ("text timeout", lambda: self.client(fake, request_timeout_s="5")),
                           ("factory not callable", lambda: _client.MeqClient(BASE, PROFILE, factory="tcp")),
                           ("relative path", lambda: self.client(fake).get_json("v1/models")),
                           ("dot-dot path", lambda: self.client(fake).get_json("/v1/../admin")),
                           ("query path", lambda: self.client(fake).get_json("/v1/models?x=1")),
                           ("absolute path", lambda: self.client(fake).get_json("//192.0.2.10/v1")),
                           ("non-finite payload", lambda: self.client(fake).post_json("/v1/x", {"x": float("nan")})),
                           ("unencodable payload", lambda: self.client(fake).post_json("/v1/x", {"x": object()})),
                           ("cancel not callable", lambda: self.client(fake).post_stream("/v1/x", {}, cancel=True))):
            with self.subTest(case=name):
                self.assertEqual(self.error(call).code, "MEQ_CONFIG_INVALID")
        self.assertEqual(fake.calls, [])


class ParameterTests(ClientCase):
    def test_fixed_parameters(self):
        self.assertEqual(_client.CONNECT_TIMEOUT_S, 2.0)
        self.assertEqual(_client.REQUEST_TIMEOUT_S, {"dev-macos-arm64": 30.0, "linux-amd64-cpu": 600.0,
                                                     "linux-amd64-nvidia": 30.0})
        self.assertEqual(_client.MAX_RESPONSE_BYTES, 8 * 1024 * 1024)
        self.assertEqual(_client.MAX_SSE_TOTAL_BYTES, _client.MAX_RESPONSE_BYTES)
        self.assertEqual(_client.MAX_SSE_LINE_BYTES, 1024 * 1024)
        for profile, timeout in _client.REQUEST_TIMEOUT_S.items():
            with self.subTest(profile=profile):
                client = _client.MeqClient(BASE, profile, factory=Fake().factory)
                self.assertEqual(client.request_timeout_s, timeout)

    def test_the_default_factory_is_reached_only_without_injection(self):
        # setUp patched it to fail: an uninjected client reaches it, so no injected test could have used it.
        with self.assertRaisesRegex(AssertionError, "the default connection factory"):
            _client.MeqClient(BASE, PROFILE).get_json("/v1/models")

    def test_the_error_set_is_closed_and_frozen(self):
        codes = list(_client.ERROR_CODES)
        self.assertEqual(len(codes), len(set(codes)))
        self.assertTrue(all(code.startswith("MEQ_") and code.isupper() for code in codes))
        self.assertTrue({"MEQ_CONNECT_FAILED", "MEQ_CONNECT_TIMEOUT", "MEQ_READ_TIMEOUT", "MEQ_REDIRECT_REFUSED",
                         "MEQ_HTTP_CLIENT_ERROR", "MEQ_HTTP_SERVER_ERROR", "MEQ_MALFORMED_JSON", "MEQ_OVERSIZE",
                         "MEQ_SSE_FRAMING", "MEQ_CANCELLED"} <= set(codes))
        with self.assertRaises(TypeError):
            _client.ERROR_CODES["MEQ_NEW"] = "x"
        with self.assertRaises(AttributeError):
            _client.ERROR_CODES._pairs = ()
        with self.assertRaises(ValueError):
            _client.MeqError("MEQ_NOT_IN_THE_SET")
        # Each code carries the PI-D1 placeholder comment, and no mapping data exists yet.
        source = (HERE / "_client.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("# PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands."), len(codes))
        self.assertNotIn("PI_D1", source)

    def test_the_client_imports_only_its_five_standard_modules_and_never_reads_the_environment(self):
        source = (HERE / "_client.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertEqual(imported, ALLOWED_IMPORTS)
        for token in ("urllib", "os.environ", "getenv", "set_tunnel", "getaddrinfo", "gethostbyname", "getheader"):
            with self.subTest(token=token):
                self.assertNotIn(token, source)
        # The Location header is never read: no string constant names it.
        self.assertFalse([node for node in ast.walk(tree) if isinstance(node, ast.Constant) and type(node.value) is str
                          and node.value.lower() == "location"])


class ReachabilityTests(ClientCase):
    def test_every_error_code_is_reachable(self):
        def get(reply, **kwargs):
            return lambda: self.client(self.fake(reply), **kwargs).get_json("/v1/models")

        def events(body):
            return lambda: self.client(self.fake(stream(body))).post_stream("/v1/x", {})

        def guard(url):
            return lambda: _client.MeqClient(url, PROFILE, factory=Fake().factory)

        scenarios = {
            "MEQ_GUARD_MALFORMED": guard("http://[::1/"),
            "MEQ_GUARD_SCHEME": guard("ftp://127.0.0.1/"),
            "MEQ_GUARD_EMPTY_HOST": guard("http:///v1"),
            "MEQ_GUARD_USERINFO": guard("http://user@127.0.0.1/"),
            "MEQ_GUARD_QUERY": guard("http://127.0.0.1/?a=1"),
            "MEQ_GUARD_FRAGMENT": guard("http://127.0.0.1/#a"),
            "MEQ_GUARD_PORT": guard("http://127.0.0.1:65536/"),
            "MEQ_GUARD_NAME": guard("http://engine.example/"),
            "MEQ_GUARD_LINK_LOCAL": guard("http://169.254.169.254/"),
            "MEQ_GUARD_METADATA": guard("http://[" + "fd20" + ":" + "ce" + "::" + "254" + "]/"),
            "MEQ_GUARD_HOST_CLASS": guard("http://192.0.2.10/"),
            "MEQ_CONFIG_INVALID": lambda: _client.MeqClient(BASE, "linux-arm64", factory=Fake().factory),
            "MEQ_CONNECT_FAILED": get(ConnectionRefusedError()),
            "MEQ_CONNECT_TIMEOUT": get(TimeoutError()),
            "MEQ_READ_TIMEOUT": get(HOLD, request_timeout_s=0.2),
            "MEQ_CONNECTION_LOST": get(b""),
            "MEQ_PROTOCOL_ERROR": get(b"NOT HTTP\r\n\r\n"),
            "MEQ_REDIRECT_REFUSED": get(response(307, reason="Moved", headers=(("Location", "http://203.0.113.5/"),))),
            "MEQ_HTTP_CLIENT_ERROR": get(response(404, reason="Not Found")),
            "MEQ_HTTP_SERVER_ERROR": get(response(502, reason="Bad Gateway")),
            "MEQ_MALFORMED_JSON": get(response(200, b"{")),
            "MEQ_OVERSIZE": get(("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n"
                                 % (_client.MAX_RESPONSE_BYTES + 1)).encode("ascii")),
            "MEQ_SSE_FRAMING": events(b'data: {"a":1}\n\n'),
            "MEQ_CANCELLED": lambda: self.client(self.fake(stream(b"data: [DONE]\n\n"))).post_stream(
                "/v1/x", {}, cancel=lambda: True),
        }
        self.assertEqual(set(scenarios), set(_client.ERROR_CODES))
        for code, call in scenarios.items():
            with self.subTest(code=code):
                self.assertEqual(self.error(call).code, code)


if __name__ == "__main__":
    unittest.main()
