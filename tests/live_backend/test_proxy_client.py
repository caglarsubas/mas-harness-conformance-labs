"""Codec and refused-entry tests. No certificates issued or live TLS attempted."""
from copy import deepcopy
import base64
import importlib
import json
import ssl
import sys
from types import SimpleNamespace
import unittest
from time import perf_counter as _wall_clock
from unittest.mock import Mock, patch

from _fixtures import ROOT
import harness_conformance
from harness_conformance.canonical import byte_digest
from harness_conformance.errors import ConformanceError

VECTORS = json.loads((ROOT / "fixtures/live-backend/proxy-vectors.json").read_bytes())


def setUpModule():
    # Diagnostic only: do not intercept TestCase.run, discovery or any guard.
    global _module_started
    _module_started = _wall_clock()


def tearDownModule():
    print(f"CONF-LIVE-003 module-timing module={__name__} "
          f"elapsedSeconds={_wall_clock() - _module_started:.6f} evidenceClass=DIAGNOSTIC_ONLY", flush=True)


def load_proxy_modules():
    """Load real code without leaking discovery state into predecessor fixtures.

    The accepted custody tests install their own explicit module-seam adapters.
    Python also caches a submodule as a parent-package attribute; restoring only
    sys.modules would leave those historical fixtures observing our real module
    instead of their adapter. Restore both surfaces, never any runtime guard,
    predecessor test, test selection, loader metadata or verification result.
    """
    names = ("live_proxy_client", "live_proxy_server")
    absent = object()
    previous_modules = {name: sys.modules.get("harness_conformance." + name, absent) for name in names}
    previous_attributes = {name: vars(harness_conformance).get(name, absent) for name in names}
    try:
        return tuple(importlib.import_module("harness_conformance." + name) for name in names)
    finally:
        for name in names:
            if previous_modules[name] is absent:
                sys.modules.pop("harness_conformance." + name, None)
            else:
                sys.modules["harness_conformance." + name] = previous_modules[name]
            if previous_attributes[name] is absent:
                vars(harness_conformance).pop(name, None)
            else:
                setattr(harness_conformance, name, previous_attributes[name])


client, _server_module = load_proxy_modules()


def der(tag, value):
    """Deliberately unsigned DER-shaped codec data, not a usable certificate."""
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([128 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + value


def identity_data(client_identity=True):
    profile = deepcopy(VECTORS["proxy"]["positive"])
    binding = profile["binding"]
    endpoint = {"endpointId": binding["endpointId"], "tls": {"serverName": "proxy.unit", "serverSpkiDigest": ""}}
    name = "urn:planeon:campaign-proxy:" + ":".join(binding[k] for k in ("tenantId", "environmentId", "runNonce", "endpointId"))
    san = der(0x86 if client_identity else 0x82, (name if client_identity else "proxy.unit").encode())
    eku = bytes.fromhex("2b06010505070302" if client_identity else "2b06010505070301")
    extension = lambda oid, value: der(0x30, der(6, bytes.fromhex(oid)) + der(4, value))
    extensions = der(0xA3, der(0x30, extension("551d13", der(0x30, b"")) +
                    extension("551d25", der(0x30, der(6, eku))) + extension("551d11", der(0x30, san))))
    spki = der(0x30, der(0x30, b"") + der(3, b"\x00unit-not-a-key"))
    algorithm = der(0x30, der(6, b"\x2b\x65\x70"))
    tbs = der(0x30, b"\xa0\x03\x02\x01\x02" + der(2, b"\x01") + algorithm + der(0x30, b"") +
              der(0x30, der(0x17, b"260908000000Z") + der(0x17, b"260908001000Z")) +
              der(0x30, b"") + spki + extensions)
    raw = der(0x30, tbs + algorithm + der(3, b"\x00not-a-signature"))
    profile["capacityEntries"]["credentialIdentities"][0].update(certificateDigest=byte_digest(raw), clientSpkiDigest=byte_digest(spki))
    endpoint["tls"]["serverSpkiDigest"] = byte_digest(spki)
    return raw, profile, endpoint


class ProxyClientTests(unittest.TestCase):
    def test_discovery_import_restores_both_package_attributes_and_module_cache(self):
        names = ("live_proxy_client", "live_proxy_server")
        previous = [(vars(harness_conformance).get(name), sys.modules.get("harness_conformance." + name)) for name in names]
        modules = load_proxy_modules()
        self.assertEqual([module.__name__ for module in modules], ["harness_conformance." + name for name in names])
        self.assertEqual(previous, [(vars(harness_conformance).get(name), sys.modules.get("harness_conformance." + name)) for name in names])

    def test_foreign_context_refused_before_any_resource_or_transport(self):
        for context in (None, {}, SimpleNamespace(_owner=object()), Mock()):
            with self.subTest(context=type(context).__name__), patch.object(client.socket, "socket") as socket_factory:
                with self.assertRaises(ConformanceError):
                    client.execute_protected({}, context, 10)
                socket_factory.assert_not_called()

    def test_authentication_guard_cannot_manufacture_context(self):
        with patch.object(client.socket, "socket") as sockets, self.assertRaises(ConformanceError):
            client._require_current_credential_policy({}, 10)
        sockets.assert_not_called()

    def test_ten_exact_post_targets_and_framing(self):
        for case in client.CASES:
            first = "POST /v1/linux-baseline/" + case.lower().replace("_", "-") + " HTTP/1.1"
            raw = client.http_message(first, b"{}", "proxy.unit")
            headers = raw[:-2]
            self.assertEqual(client.parse_headers(headers, False, "proxy.unit"), (first.encode(), 2))

    def test_redirect_host_port_query_method_and_unknown_header_refused(self):
        first = "POST /v1/linux-baseline/host-isolation-negatives HTTP/1.1"
        headers = client.http_message(first, b"{}", "proxy.unit")[:-2]
        for old, new in ((b"POST ", b"GET "), (b"HTTP/1.1", b"HTTP/2"), (b"proxy.unit", b"proxy.unit:443"),
                         (b" HTTP/1.1", b"?x=1 HTTP/1.1"), (b"/v1/", b"https://proxy.unit/v1/"),
                         (b"Connection: close", b"Connection: keep-alive"),
                         (b"Content-Type: application/json", b"Content-Type: application/json\r\nX-Override: true")):
            with self.subTest(new=new), self.assertRaises(ConformanceError):
                client.parse_headers(headers.replace(old, new), False, "proxy.unit")

    def test_content_length_duplicate_casefold_smuggling_and_surplus_headers(self):
        headers = client.http_message("HTTP/1.1 200 OK", b"{}").split(b"{}", 1)[0]
        for replacement in (b"Content-Length: 02", b"Content-Length: +2", b"Content-Length: -1",
                            b"Content-Length: 0", b"Content-Length: 4194305", b"Content-Length: 2\r\ncontent-length: 2",
                            b"Content-Length: 2\r\nTransfer-Encoding: chunked", b"Content-Length: 2\r\nContent-Encoding: gzip",
                            b"Content-Length: 2\r\n continuation", b"Content-Length: 2\r\nHost: proxy.unit"):
            with self.subTest(replacement=replacement), self.assertRaises(ConformanceError):
                client.parse_headers(headers.replace(b"Content-Length: 2", replacement), True)
        for status in (b"301 Moved Permanently", b"302 Found", b"204 No Content", b"500 Error"):
            with self.subTest(status=status), self.assertRaises(ConformanceError):
                client.parse_headers(headers.replace(b"200 OK", status), True)

    def test_response_body_fragmentation_and_authenticated_close(self):
        tls = SimpleNamespace(deadline=100, ssl=Mock(), read=Mock(side_effect=[b"HTTP/1.1 200 OK\r\n", b"Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n", b"{", b"}", b""]))
        tls.ssl.pending.return_value = 0
        with patch.object(client.time, "monotonic", return_value=1):
            self.assertEqual(client.read_http(tls, True), (b"HTTP/1.1 200 OK", b"{}"))

    def test_response_surplus_pipelining_and_truncation_refused(self):
        good = client.http_message("HTTP/1.1 200 OK", b"{}")
        for chunks, pending in (([good + b"X"], 0), ([good, b"X"], 0), ([good], 1), ([good[:-1], b""], 0), ([b""], 0)):
            tls = SimpleNamespace(deadline=100, ssl=Mock(), read=Mock(side_effect=chunks))
            tls.ssl.pending.return_value = pending
            with self.subTest(chunks=chunks), patch.object(client.time, "monotonic", return_value=1), self.assertRaises(ConformanceError):
                client.read_http(tls, True)

    def test_header_injection_and_oversize_refused(self):
        with self.assertRaises(ConformanceError):
            client.http_message("HTTP/1.1 200 OK\r\nX: yes", b"{}")
        with self.assertRaises(ConformanceError):
            client.http_message("HTTP/1.1 200 OK", b"{}", "proxy\r\nX: yes")
        with self.assertRaises(ConformanceError):
            client.parse_headers(b"X" * 16384 + b"\r\n\r\n", True)

    def test_der_length_and_tag_encodings_are_strict(self):
        self.assertEqual(client._der_one(der(4, b"x" * 128), 4), b"x" * 128)
        for raw in (b"\x30\x80", b"\x30\x81\x00", b"\x30\x82\x00\x80", b"\x30\x01", b"\x3f\x00", b"\x30\x00\x30\x00"):
            with self.subTest(raw=raw), self.assertRaises(ConformanceError):
                client._der_one(raw, 0x30)

    def test_unsigned_identity_codec_does_not_verify_a_signature(self):
        for mode in (True, False):
            raw, profile, endpoint = identity_data(mode)
            identity = client._check_certificate(raw, profile, endpoint, mode)
            self.assertEqual(identity["leaf"], byte_digest(raw))
            self.assertNotIn("verified", identity)
            self.assertNotIn("nativeAcceptance", identity)
            self.assertIn(b"not-a-signature", raw)

    def test_client_leaf_spki_san_purpose_and_expiry_pins(self):
        raw, profile, endpoint = identity_data()
        for kind in ("leaf", "spki", "scope", "purpose", "expiry", "server-eku"):
            current = deepcopy(profile)
            if kind in ("leaf", "spki"):
                current["capacityEntries"]["credentialIdentities"][0]["certificateDigest" if kind == "leaf" else "clientSpkiDigest"] = "sha256:" + "0" * 64
            elif kind == "scope":
                current["binding"]["tenantId"] = "foreign"
            elif kind == "purpose":
                current["capacityEntries"]["credentialIdentities"][0]["purpose"] = "KUBERNETES_PROXY_SERVER_MTLS"
            elif kind == "expiry":
                current["binding"]["expiresAt"] = "2026-09-08T00:10:01Z"
            with self.subTest(kind=kind), self.assertRaises(ConformanceError):
                client._check_certificate(raw, current, endpoint, kind != "server-eku")

    def test_one_key_and_bounded_chain_pem_structure_only(self):
        raw, _, _ = identity_data()
        cert = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(raw) + b"\n-----END CERTIFICATE-----\n"
        # Empty DER SEQUENCE is not a usable key. No cryptographic generation.
        key = b"-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n"
        self.assertEqual(client.credential_leaf(cert + key), raw)
        for invalid in (cert, key, cert + key + key, cert * 9 + key, b"untrusted\n" + cert + key,
                        (cert + key).replace(b"PRIVATE KEY", b"ENCRYPTED PRIVATE KEY")):
            with self.subTest(size=len(invalid)), self.assertRaises(ConformanceError):
                client.credential_leaf(invalid)

    def test_tls_config_has_no_defaults_resumption_keylog_or_prompt(self):
        for server in (False, True):
            context = Mock(options=0, verify_flags=0)
            with patch.object(client.ssl, "SSLContext", return_value=context) as factory:
                self.assertIs(client.tls_context(b"UNIT CA DATA", 55, server), context)
            factory.assert_called_once_with(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
            self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_3)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(context.check_hostname, not server)
            self.assertIs(context.hostname_checks_common_name, False)
            self.assertIsNone(context.keylog_filename)
            self.assertTrue(context.options & ssl.OP_NO_TICKET)
            context.load_default_certs.assert_not_called()
            context.set_default_verify_paths.assert_not_called()
            context.load_verify_locations.assert_called_once_with(cadata="UNIT CA DATA")
            context.load_cert_chain.assert_called_once_with("/proc/self/fd/55", password=client._no_password)
        with self.assertRaises(ConformanceError):
            client._no_password()

    def test_tls_guard_checks_owner_before_wait_and_rejects_clock_rollback(self):
        context, socket, owner = Mock(), Mock(), Mock()
        with patch.object(client.time, "monotonic", return_value=10):
            tls = client._TLS(socket, context, {"tls": {"serverName": "proxy.unit"}}, owner, 30)
        for now in (9, 30, 31):
            with self.subTest(now=now), patch.object(client.time, "monotonic", return_value=now), self.assertRaises(ConformanceError):
                tls.check(30)
        self.assertEqual(owner._transport_check.call_count, 3)
        socket.settimeout.assert_not_called()

    def test_tls_handshake_requires_no_resumption_and_exact_alpn(self):
        for field, bad in (("version", "TLSv1.2"), ("selected_alpn_protocol", None), ("session_reused", True)):
            context, socket, owner = Mock(), Mock(), Mock()
            engine = context.wrap_bio.return_value
            engine.version.return_value = "TLSv1.3"
            engine.selected_alpn_protocol.return_value = "http/1.1"
            engine.session_reused = False
            if field == "session_reused":
                engine.session_reused = bad
            else:
                getattr(engine, field).return_value = bad
            with patch.object(client.time, "monotonic", return_value=1):
                tls = client._TLS(socket, context, {"tls": {"serverName": "proxy.unit"}}, owner, 20)
                with self.subTest(field=field), self.assertRaises(ConformanceError):
                    tls.handshake({}, {})
            engine.getpeercert.assert_not_called()

    def test_request_rejects_buffered_encrypted_records_without_waiting_for_eof(self):
        first = "POST /v1/linux-baseline/host-isolation-negatives HTTP/1.1"
        good = client.http_message(first, b"{}", "proxy.unit")
        for pending in (0, 1, 65536):
            tls = SimpleNamespace(deadline=100, ssl=Mock(), incoming=SimpleNamespace(pending=pending),
                                  read=Mock(return_value=good))
            tls.ssl.pending.return_value = 0
            with self.subTest(pending=pending), patch.object(client.time, "monotonic", return_value=1):
                if pending:
                    with self.assertRaises(ConformanceError):
                        client.read_http(tls, False, "proxy.unit")
                else:
                    self.assertEqual(client.read_http(tls, False, "proxy.unit"), (first.encode(), b"{}"))
            tls.read.assert_called_once()  # do not deadlock waiting for client EOF

    def make_transport(self, clock, deadline=100):
        context, sock, owner = Mock(), Mock(), Mock()
        with patch.object(client.time, "monotonic", side_effect=lambda: clock[0]):
            tls = client._TLS(sock, context, {"tls": {"serverName": "proxy.unit"}}, owner, deadline)
        return tls, context.wrap_bio.return_value, sock, owner

    def test_tls_receive_timeouts_poll_same_stream_without_retrying_request(self):
        clock = [0]
        tls, engine, sock, owner = self.make_transport(clock)
        engine.read.side_effect = [ssl.SSLWantReadError()] * 4 + [b"receipt"]
        reads = []
        def receive(maximum):
            reads.append(maximum)
            clock[0] += 2
            if len(reads) < 4:
                raise TimeoutError()
            return b"unit ciphertext; SSL engine mocked"
        sock.recv.side_effect = receive
        with patch.object(client.time, "monotonic", side_effect=lambda: clock[0]):
            self.assertEqual(tls.read(100), b"receipt")
        self.assertEqual(reads, [65536] * 4)
        self.assertEqual(tls.deadline, 100)
        self.assertTrue(all(0 < call.args[0] <= 2 for call in sock.settimeout.call_args_list))
        self.assertGreaterEqual(owner._transport_check.call_count, 8)
        sock.connect.assert_not_called()
        sock.send.assert_not_called()
        sock.close.assert_not_called()

    def test_tls_receive_poll_cannot_extend_absolute_budget(self):
        clock = [0]
        tls, engine, sock, owner = self.make_transport(clock, deadline=5)
        engine.read.side_effect = ssl.SSLWantReadError()
        def receive(maximum):
            clock[0] += 2
            raise TimeoutError()
        sock.recv.side_effect = receive
        with patch.object(client.time, "monotonic", side_effect=lambda: clock[0]), self.assertRaises(ConformanceError):
            tls.read(10)
        self.assertEqual(sock.recv.call_count, 3)
        self.assertEqual(tls.deadline, 5)
        self.assertEqual(sock.settimeout.call_args_list[-1].args, (1,))

    def test_tls_post_io_policy_timeout_is_not_a_read_poll(self):
        clock = [0]
        tls, engine, sock, owner = self.make_transport(clock)
        sock.recv.return_value = b"data"
        owner._transport_check.side_effect = [None, TimeoutError("unit observer timeout")]
        with patch.object(client.time, "monotonic", return_value=0), self.assertRaises(TimeoutError):
            tls.receive(100)
        sock.recv.assert_called_once_with(65536)
        self.assertEqual(tls.incoming.pending, 0)

    def test_tls_failed_send_and_connect_still_check_custody_and_never_retry(self):
        for operation in ("send", "connect"):
            clock = [0]
            tls, engine, sock, owner = self.make_transport(clock)
            function = getattr(sock, operation)
            function.side_effect = TimeoutError()
            argument = b"request" if operation == "send" else ("127.0.0.1", 443)
            with self.subTest(operation=operation), patch.object(client.time, "monotonic", return_value=0):
                with self.assertRaises(TimeoutError):
                    tls.network_call(function, 10, argument)
            function.assert_called_once_with(argument)
            self.assertEqual(owner._transport_check.call_count, 2)
            sock.close.assert_not_called()

    def test_tls_guard_refusal_prevents_network_and_post_read_refusal_discards_bytes(self):
        for post in (False, True):
            clock = [0]
            tls, engine, sock, owner = self.make_transport(clock)
            owner._transport_check.side_effect = [None, ConformanceError("UNIT", "revoked")] if post else ConformanceError("UNIT", "revoked")
            sock.recv.return_value = b"not accepted"
            with self.subTest(post=post), patch.object(client.time, "monotonic", return_value=0), self.assertRaises(ConformanceError):
                tls.receive(100)
            self.assertEqual(sock.recv.call_count, int(post))
            self.assertEqual(tls.incoming.pending, 0)

    def test_tls_receive_detects_clock_rollback_after_socket_returns(self):
        clock = [10]
        tls, engine, sock, owner = self.make_transport(clock)
        def receive(maximum):
            clock[0] = 9
            return b"discard"
        sock.recv.side_effect = receive
        with patch.object(client.time, "monotonic", side_effect=lambda: clock[0]), self.assertRaises(ConformanceError):
            tls.receive(100)
        self.assertEqual(tls.incoming.pending, 0)

    def test_tls_raw_eof_and_ciphertext_budget_refuse_before_bio_input(self):
        for received, already in ((b"", 0), (b"x", 8388608)):
            clock = [0]
            tls, engine, sock, owner = self.make_transport(clock)
            engine.read.side_effect = ssl.SSLWantReadError()
            tls.network_bytes = already
            sock.recv.return_value = received
            with self.subTest(already=already), patch.object(client.time, "monotonic", return_value=0), self.assertRaises(ConformanceError):
                tls.read(10)
            self.assertEqual(tls.incoming.pending, 0)
            sock.recv.assert_called_once()

    def test_tls_partial_writes_keep_exact_suffix_and_guard_each_send(self):
        clock = [0]
        tls, engine, sock, owner = self.make_transport(clock)
        tls.outgoing.write(b"abc")
        sock.send.side_effect = [1, 2]
        with patch.object(client.time, "monotonic", return_value=0):
            tls.flush(100)
        self.assertEqual(sock.send.call_args_list, [unittest.mock.call(b"abc"), unittest.mock.call(b"bc")])
        self.assertEqual(owner._transport_check.call_count, 4)
        self.assertEqual(tls.outgoing.pending, 0)
