"""Fixed installed campaign transport. Authentication never authorizes effects.

No network or credential activity at import; no URL/backend/FD injection API.
Private codec helpers are data mechanisms, not native eligibility factories.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import ipaddress
import re
import socket
import ssl
import time

from .canonical import byte_digest, canonical_bytes, require_canonical_document
from .errors import ConformanceError
from .linux_readiness import CASES, build_probe_request, require_time
from .live_mutation_admission import require, retained_profile, _time


def _client_inputs(context, deadline):
    from .live_supervisor import InstalledContext, NativeSupervisor, _NativeChannel
    require(type(context) is InstalledContext and type(context._owner) is NativeSupervisor,
            "CLIENT_NATIVE_CONTEXT_REQUIRED")
    owner = context._owner
    require(owner._context is context and type(owner._boundary) is _NativeChannel
            and owner._boundary.context is context and owner._active is not None
            and not owner._closed and deadline == context._deadline == owner._active["deadline"],
            "CLIENT_NATIVE_SESSION_REQUIRED")
    owner._boundary.check_peer()
    resource = context._late_resources
    resource.check()
    require(resource.state == "IO_ACTIVE" and resource.operation in CASES
            and owner._active["reserved"] and owner._active["session"]["state"] == "RUNNING"
            and resource.operation not in owner._active["done"], "CLIENT_FIXED_OPERATION_REQUIRED")
    release = require_canonical_document(context._bytes[context._envelope["campaignReleaseFileReference"]])
    inputs = retained_profile(context._envelope, context._capacity, context._plan, release, context._kit)
    profile = inputs[0]
    require(require_time(context._binding["notBefore"], "start") <= _time(profile["binding"]["validFrom"])
            and _time(profile["binding"]["expiresAt"]) <= require_time(context._binding["notAfter"], "end"),
            "CLIENT_PROFILE_TRUST_WINDOW")
    instant = require_time(owner._clock(), "now")
    require(_time(profile["binding"]["validFrom"]) <= instant < _time(profile["binding"]["expiresAt"]),
            "CLIENT_PROFILE_EXPIRED")
    owner._boundary.check_peer()
    return inputs


def _require_current_credential_policy(context, deadline):
    """MET-REPAIR-013: local authentication eligibility, NOT remote observation.

    Called by the existing owned-resource guard. Never acquire a resource,
    connect, recurse into that guard, or manufacture a server observation.
    """
    _client_inputs(context, deadline)


def _der_items(raw):
    require(type(raw) is bytes and len(raw) <= 262144, "TLS_DER_SIZE")
    offset, rows = 0, []
    while offset < len(raw):
        require(len(rows) < 256 and offset + 2 <= len(raw), "TLS_DER_INVALID")
        start, tag, length = offset, raw[offset], raw[offset + 1]
        require(tag & 31 != 31, "TLS_DER_TAG")
        offset += 2
        if length & 128:
            count = length & 127
            require(1 <= count <= 3 and offset + count <= len(raw) and raw[offset] != 0, "TLS_DER_LENGTH")
            length = int.from_bytes(raw[offset:offset + count], "big")
            require(length >= 128, "TLS_DER_LENGTH")
            offset += count
        require(offset + length <= len(raw), "TLS_DER_TRUNCATED")
        end = offset + length
        rows.append((tag, raw[offset:end], raw[start:end]))
        offset = end
    return rows


def _der_one(raw, tag):
    rows = _der_items(raw)
    require(len(rows) == 1 and rows[0][0] == tag, "TLS_DER_STRUCTURE")
    return rows[0][1]


def certificate_identity(der):
    """Bounded DER identity extraction, NOT certificate signature verification.

    OpenSSL independently verifies chain/signature/hostname in the TLS handshake.
    Capacity-signed exact leaf/SPKI pins and strict extensions add scope checks.
    """
    cert = _der_items(_der_one(der, 0x30))
    require(len(cert) == 3 and [r[0] for r in cert] == [0x30, 0x30, 3], "TLS_CERT_STRUCTURE")
    tbs = _der_items(cert[0][1])
    require(len(tbs) == 8 and tbs[0][2] == b"\xa0\x03\x02\x01\x02"
            and [r[0] for r in tbs[1:7]] == [2, 0x30, 0x30, 0x30, 0x30, 0x30]
            and tbs[7][0] == 0xa3 and tbs[2][2] == cert[1][2], "TLS_CERT_STRUCTURE")
    validity = _der_items(tbs[4][1])
    require(len(validity) == 2, "TLS_CERT_VALIDITY")
    def instant(row):
        tag, raw, _ = row
        require(tag in (0x17, 0x18) and re.fullmatch(b"[0-9]{12}Z" if tag == 0x17 else b"[0-9]{14}Z", raw),
                "TLS_CERT_VALIDITY")
        text = raw.decode("ascii")
        if tag == 0x17:
            text = ("19" if int(text[:2]) >= 50 else "20") + text
        return datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    extensions = {}
    for entry in _der_items(_der_one(tbs[7][1], 0x30)):
        require(entry[0] == 0x30, "TLS_CERT_EXTENSION")
        parts = _der_items(entry[1])
        require(len(parts) in (2, 3) and parts[0][0] == 6 and parts[-1][0] == 4
                and (len(parts) == 2 or parts[1][2] == b"\x01\x01\xff"), "TLS_CERT_EXTENSION")
        oid = parts[0][1]
        require(oid not in extensions, "TLS_CERT_DUPLICATE_EXTENSION")
        extensions[oid] = parts[-1][1]
    require(all(oid in extensions for oid in (b"\x55\x1d\x13", b"\x55\x1d\x25", b"\x55\x1d\x11")),
            "TLS_CERT_EXTENSION_MISSING")
    require(_der_one(extensions[b"\x55\x1d\x13"], 0x30) == b"", "TLS_LEAF_CA_FORBIDDEN")
    eku = _der_items(_der_one(extensions[b"\x55\x1d\x25"], 0x30))
    require(eku and all(r[0] == 6 for r in eku) and len({r[1] for r in eku}) == len(eku), "TLS_CERT_EKU")
    sans = _der_items(_der_one(extensions[b"\x55\x1d\x11"], 0x30))
    require(sans and len(sans) <= 32 and all(r[0] in (0x82, 0x86, 0x87) for r in sans), "TLS_CERT_SAN")
    return {"leaf": byte_digest(der), "spki": byte_digest(tbs[6][2]),
            "notBefore": instant(validity[0]), "notAfter": instant(validity[1]),
            "eku": tuple(r[1] for r in eku), "sans": tuple((r[0], r[1]) for r in sans)}


def _check_certificate(der, profile, endpoint, client):
    identity = certificate_identity(der)
    start, end = _time(profile["binding"]["validFrom"]), _time(profile["binding"]["expiresAt"])
    require(identity["notBefore"] <= start < end <= identity["notAfter"], "TLS_CERT_WINDOW")
    eku = bytes.fromhex("2b06010505070302" if client else "2b06010505070301")
    require(identity["eku"] == (eku,), "TLS_CERT_EKU")
    if client:
        rows = [r for r in profile["capacityEntries"]["credentialIdentities"] if r["endpointId"] == endpoint["endpointId"]]
        require(len(rows) == 1, "TLS_CREDENTIAL_ENROLLMENT")
        row, scope = rows[0], profile["binding"]
        prefix = "campaign-proxy" if row["purpose"] == "CAMPAIGN_PROXY_CLIENT_MTLS" else "capacity-proxy"
        san = ("urn:planeon:" + prefix + ":" + ":".join(scope[k] for k in ("tenantId", "environmentId", "runNonce"))
               + ":" + endpoint["endpointId"]).encode("ascii")
        require(identity["leaf"] == row["certificateDigest"] and identity["spki"] == row["clientSpkiDigest"]
                and identity["sans"] == ((0x86, san),), "TLS_CLIENT_IDENTITY")
    else:
        name = endpoint["tls"]["serverName"].encode("ascii")
        require(identity["spki"] == endpoint["tls"]["serverSpkiDigest"]
                and (0x82, name) in identity["sans"]
                and all(b"*" not in raw for tag, raw in identity["sans"]), "TLS_SERVER_IDENTITY")
    return identity


def credential_leaf(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 262144, "TLS_PEM_SIZE")
    pattern = rb"-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END \1-----"
    matches, end, certs, keys = list(re.finditer(pattern, raw)), 0, [], 0
    for match in matches:
        require(not raw[end:match.start()].strip(), "TLS_PEM_INVALID")
        payload = base64.b64decode(re.sub(rb"[\r\n]", b"", match[2]), validate=True)
        require(payload, "TLS_PEM_INVALID")
        if match[1] == b"CERTIFICATE":
            certs.append(payload)
        else:
            _der_one(payload, 0x30)
            keys += 1
        end = match.end()
    require(not raw[end:].strip() and 1 <= len(certs) <= 8 and keys == 1, "TLS_PEM_INVALID")
    return certs[0]


def _no_password():
    raise ConformanceError("TLS_ENCRYPTED_KEY_FORBIDDEN", "interactive credential prompts are forbidden")


def tls_context(ca, memfd, server=False):
    # No default CA paths or environment-derived key logger. This helper itself
    # grants no file ownership: its sole production callers own sealed memfds.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = not server
    context.hostname_checks_common_name = False
    context.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION
    if server:
        context.num_tickets = 0
    context.keylog_filename = None
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.set_alpn_protocols(["http/1.1"])
    require(type(ca) is bytes and b"PRIVATE KEY" not in ca and type(memfd) is int and memfd > 2,
            "TLS_CUSTODY_REQUIRED")
    context.load_verify_locations(cadata=ca.decode("ascii"))
    context.load_cert_chain("/proc/self/fd/" + str(memfd), password=_no_password)
    return context


class _TLS:
    """MemoryBIO codec: never owns/closes/adopts the native owner's raw socket."""
    def __init__(self, sock, context, endpoint, owner, deadline, server=False):
        self.sock, self.owner, self.deadline = sock, owner, deadline
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.ssl = context.wrap_bio(self.incoming, self.outgoing, server_side=server,
                                   server_hostname=None if server else endpoint["tls"]["serverName"])
        self.network_bytes = 0
        self.last = time.monotonic()

    def check(self, deadline):
        self.owner._transport_check()
        now = time.monotonic()
        require(now >= self.last and now < min(deadline, self.deadline), "TLS_DEADLINE")
        self.last = now
        self.sock.settimeout(min(deadline, self.deadline) - now)

    def flush(self, deadline):
        while self.outgoing.pending:
            data = self.outgoing.read()
            while data:
                self.check(deadline)
                n = self.sock.send(data)
                self.check(deadline)
                require(type(n) is int and 0 < n <= len(data), "TLS_SHORT_WRITE")
                data = data[n:]

    def call(self, function, deadline):
        while True:
            self.check(deadline)
            try:
                result = function()
                self.flush(deadline)
                self.check(deadline)
                return result
            except ssl.SSLWantWriteError:
                self.flush(deadline)
            except ssl.SSLWantReadError:
                self.flush(deadline)
                self.check(deadline)
                data = self.sock.recv(65536)
                self.check(deadline)
                require(data and self.network_bytes + len(data) <= 8388608, "TLS_EOF_OR_SIZE")
                self.network_bytes += len(data)
                self.incoming.write(data)

    def handshake(self, profile, endpoint, server=False):
        self.call(self.ssl.do_handshake, min(self.deadline, time.monotonic() + 10))
        require(self.ssl.version() == "TLSv1.3" and not self.ssl.session_reused
                and self.ssl.selected_alpn_protocol() == "http/1.1", "TLS_PROTOCOL_INVALID")
        _check_certificate(self.ssl.getpeercert(binary_form=True), profile, endpoint, client=server)

    def write(self, data):
        while data:
            n = self.call(lambda: self.ssl.write(data), self.deadline)
            require(type(n) is int and 0 < n <= len(data), "TLS_SHORT_WRITE")
            data = data[n:]

    def read(self, maximum, deadline=None):
        return self.call(lambda: self.ssl.read(maximum), self.deadline if deadline is None else deadline)

    def notify_close(self):
        self.check(self.deadline)
        try:
            self.ssl.unwrap()
        except ssl.SSLWantReadError:
            pass  # one-way close_notify; never reuse this connection
        self.flush(self.deadline)


def http_message(first, body, host=None):
    require(type(first) is str and "\r" not in first and "\n" not in first
            and type(body) is bytes, "HTTP_MESSAGE_INVALID")
    headers = [first, "Content-Type: application/json", "Content-Length: " + str(len(body)), "Connection: close"]
    if host is not None:
        require(type(host) is str and re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host), "HTTP_HOST_INVALID")
        headers.append("Host: " + host)
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body


def parse_headers(raw, response, host=None):
    require(type(raw) is bytes and len(raw) <= 16384 and raw.endswith(b"\r\n\r\n"), "HTTP_HEADERS_INVALID")
    lines = raw[:-4].split(b"\r\n")
    require(lines and len(lines) <= 32, "HTTP_HEADERS_INVALID")
    fields = {}
    for line in lines[1:]:
        require(b": " in line and not line.startswith((b" ", b"\t")), "HTTP_HEADERS_INVALID")
        name, value = line.split(b": ", 1)
        name = name.lower()
        require(name in (b"host", b"content-type", b"content-length", b"connection") and name not in fields
                and value and all(32 <= n <= 126 for n in value), "HTTP_HEADER_FORBIDDEN")
        fields[name] = value
    expected = {b"content-type", b"content-length", b"connection"} | (set() if response else {b"host"})
    require(set(fields) == expected and fields[b"content-type"] == b"application/json"
            and fields[b"connection"] == b"close" and re.fullmatch(b"0|[1-9][0-9]{0,6}", fields[b"content-length"]),
            "HTTP_HEADERS_INVALID")
    length = int(fields[b"content-length"])
    require(0 < length <= (4194304 if response else 16384), "HTTP_BODY_SIZE")
    if response:
        require(lines[0] == b"HTTP/1.1 200 OK", "HTTP_STATUS_INVALID")
    else:
        paths = {("POST /v1/linux-baseline/" + case.lower().replace("_", "-") + " HTTP/1.1").encode(): case for case in CASES}
        require(lines[0] in paths and fields[b"host"] == host.encode("ascii"), "HTTP_REQUEST_TARGET")
    return lines[0], length


def read_http(tls, response, host=None):
    data = bytearray()
    header_deadline = min(tls.deadline, time.monotonic() + 10)
    while b"\r\n\r\n" not in data:
        require(len(data) < 16384, "HTTP_HEADERS_SIZE")
        part = tls.read(min(4096, 16384 - len(data)), header_deadline)
        require(part, "HTTP_TRUNCATED_HEADERS")
        data.extend(part)
    headers, body = bytes(data).split(b"\r\n\r\n", 1)
    first, size = parse_headers(headers + b"\r\n\r\n", response, host)
    require(len(body) <= size, "HTTP_SURPLUS")
    while len(body) < size:
        part = tls.read(min(65536, size + 1 - len(body)))
        require(part, "HTTP_TRUNCATED_BODY")
        body += part
        require(len(body) <= size, "HTTP_SURPLUS")
    require(tls.ssl.pending() == 0, "HTTP_PIPELINING")
    if response:
        require(tls.read(1) == b"", "HTTP_SURPLUS")
    return first, body


class _ClientOperation:
    def __init__(self, context, deadline):
        self.context, self.deadline = context, deadline

    def _transport_check(self):
        _require_current_credential_policy(self.context, self.deadline)


def execute_protected(request, context, deadline):
    """Only the existing NativeChannel frame can acquire owned transport."""
    profile, _, endpoint, ca = _client_inputs(context, deadline)
    operation = context._late_resources.operation
    require(type(request) is dict and request == build_probe_request(context._envelope, context._capacity,
                                                                    context._plan, operation), "CLIENT_REQUEST_INVALID")
    resources = context._late_resources
    raw = resources.credential_bytes()
    _check_certificate(credential_leaf(raw), profile, endpoint, client=True)
    fd = resources.tls_memfd()
    try:
        tls_config = tls_context(ca, fd)
    finally:
        resources.close_memfd()
    sock = resources.transport()
    owner = _ClientOperation(context, deadline)
    owner._transport_check()
    address = ipaddress.ip_address(endpoint["ipAddress"])
    target = (str(address), endpoint["port"]) if address.version == 4 else (str(address), endpoint["port"], 0, 0)
    connect_deadline = min(deadline, time.monotonic() + 10)
    sock.settimeout(connect_deadline - time.monotonic())
    sock.connect(target)
    owner._transport_check()
    require(time.monotonic() < connect_deadline and sock.getpeername() == target, "CLIENT_PEER_MISMATCH")
    tls = _TLS(sock, tls_config, endpoint, owner, deadline)
    tls.handshake(profile, endpoint)
    tls.write(http_message("POST " + request["path"] + " HTTP/1.1", canonical_bytes(request), endpoint["tls"]["serverName"]))
    _, receipt = read_http(tls, response=True)
    owner._transport_check()
    # NativeChannel performs exact receipt validation and closes owned I/O.
    # No transport success is converted into a native or tenant PASS here.
    return receipt
