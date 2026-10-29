"""CONF-MEQ-001A: the MEQ probe client core of MODEL-EXIST-QUAL-001 (test-local; this packet contacts no endpoint).

The client speaks HTTP/1.1 to the owner's engine listener through http.client alone. The base-URL guard parses the URL
itself and admits only loopback or private-range IP literals and the name localhost, which it maps to 127.0.0.1 without
any resolver call (owner decision Q-MEQ-SCOPE; lane-monitor ruling MON-R12-MEQC, Q-MEQC-4 (a)). Every connection comes
from an injectable connection factory, and one request runs per connection. Proxy environment variables have no effect
and no redirect is followed. Every failure is a MeqError carrying one code of the closed set ERROR_CODES.

The tests drive the client over socket.socketpair() with an in-thread fake responder: the verify sandbox denies TCP,
loopback included (MEQ-CLIENT-0 dossier, section 2). A later packet may move this module into src/, so it imports only
http.client, ipaddress, json, socket and time.
"""
import http.client
import ipaddress
import json
import socket
import time

# Fixed client parameters (run plan rev 3, section 5): they are client limits, not service objectives.
CONNECT_TIMEOUT_S = 2.0
REQUEST_TIMEOUT_S = {"dev-macos-arm64": 30.0, "linux-amd64-cpu": 600.0, "linux-amd64-nvidia": 30.0}
# Response bound. The largest legitimate body is a model list, a non-streamed completion of a fixed prompt or an embedding
# batch of fixed inputs: eight inputs of 4,096 dimensions at no more than 24 bytes per JSON number is under 1 MiB. 8 MiB
# leaves ample headroom for any such answer while a runaway or hostile listener cannot grow this process past it.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
# A streamed answer is bounded the same way in total; one server-sent-event line (one chunk) gets 1 MiB.
MAX_SSE_TOTAL_BYTES = MAX_RESPONSE_BYTES
MAX_SSE_LINE_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
LOCALHOST_ADDRESS = "127.0.0.1"


class _FrozenCodes:
    """A read-only mapping of error codes to descriptions, held as a tuple of pairs."""

    __slots__ = ("_pairs",)

    def __init__(self, pairs):
        object.__setattr__(self, "_pairs", tuple(pairs))

    def __setattr__(self, name, value):
        raise AttributeError("ERROR_CODES is frozen")

    def __delattr__(self, name):
        raise AttributeError("ERROR_CODES is frozen")

    def __getitem__(self, key):
        for code, description in self._pairs:
            if code == key:
                return description
        raise KeyError(key)

    def __contains__(self, key):
        return any(code == key for code, _ in self._pairs)

    def __iter__(self):
        return iter([code for code, _ in self._pairs])

    def __len__(self):
        return len(self._pairs)

    def keys(self):
        return [code for code, _ in self._pairs]

    def items(self):
        return list(self._pairs)


# The closed error set. Each code's PI-D1 normalised class is a placeholder, mapped when MEQ-CAMPAIGN-CONTRACT lands;
# no mapping data exists yet (lane-monitor ruling MON-R12-MEQC, Q-MEQC-5 (a)).
ERROR_CODES = _FrozenCodes((
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_MALFORMED", "the base URL is not a plain ASCII URL the guard can parse"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_SCHEME", "the base URL's scheme is not http or https"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_EMPTY_HOST", "the base URL names no host"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_USERINFO", "the base URL carries userinfo"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_QUERY", "the base URL carries a query"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_FRAGMENT", "the base URL carries a fragment"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_PORT", "the base URL's port is not an integer from 1 to 65535"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_NAME", "the base URL names a host other than localhost; no resolver is called"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_LINK_LOCAL", "the base URL's address is link-local (169.254.0.0/16 or fe80::/10)"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_GUARD_HOST_CLASS", "the base URL's address is neither loopback nor in a private range"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_CONFIG_INVALID", "an unknown profile, a timeout above the profile's, a bad request path, payload or cancel hook"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_CONNECT_FAILED", "the connection could not be opened"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_CONNECT_TIMEOUT", "the connection was not opened within the connect timeout"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_READ_TIMEOUT", "the exchange did not finish within the request timeout"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_CONNECTION_LOST", "the connection failed or closed early after it was opened"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_PROTOCOL_ERROR", "the answer is not well-formed HTTP/1.1 or has an unexpected status class"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_REDIRECT_REFUSED", "the answer is a 3xx redirect; its Location is never followed"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_HTTP_CLIENT_ERROR", "the answer has a 4xx status"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_HTTP_SERVER_ERROR", "the answer has a 5xx status"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_MALFORMED_JSON", "a body or event payload is not strict UTF-8 JSON"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_OVERSIZE", "a body, an event line or a stream exceeds its bound"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_SSE_FRAMING", "the event stream is not well-framed or ends before its [DONE] event"),
    # PI-D1 class: mapped when MEQ-CAMPAIGN-CONTRACT lands.
    ("MEQ_CANCELLED", "the caller cancelled the stream; the connection was closed"),
))


class MeqError(Exception):
    """A coded failure. `status` is the HTTP status where one was read; `body` is a bounded, parsed error body or None."""

    def __init__(self, code, *, status=None, body=None):
        if code not in ERROR_CODES:
            raise ValueError("unknown MEQ error code")
        super().__init__(code)
        self.code = code
        self.status = status
        self.body = body


class Target:
    """The guarded connection target: the scheme, the IP address text, the port and the base path (no trailing /)."""

    __slots__ = ("scheme", "address", "port", "base_path")

    def __init__(self, scheme, address, port, base_path):
        self.scheme = scheme
        self.address = address
        self.port = port
        self.base_path = base_path


_SCHEME_PORTS = {"http": 80, "https": 443}
_ADMITTED = tuple(ipaddress.ip_network(net) for net in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                        "::1/128", "fc00::/7"))
_LINK_LOCAL = tuple(ipaddress.ip_network(net) for net in ("169.254.0.0/16", "fe80::/10"))
_DIGITS = frozenset("0123456789")
_PATH_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/")


def _plain_path(path):
    """A path of unreserved characters and '/', with no empty, '.' or '..' segment after its leading '/'."""
    if not path.startswith("/") or any(ch not in _PATH_CHARS for ch in path):
        return False
    return all(segment not in ("", ".", "..") for segment in path[1:].split("/"))


def guard_base_url(base_url):
    """Parse and admit a base URL, or raise MeqError with the refusal's own code. Never calls a resolver."""
    if type(base_url) is not str or not base_url or "\\" in base_url or any(not "!" <= ch <= "~" for ch in base_url):
        raise MeqError("MEQ_GUARD_MALFORMED")
    marker = base_url.find("://")
    scheme = base_url[:marker].lower() if marker > 0 else ""
    if scheme not in _SCHEME_PORTS:
        raise MeqError("MEQ_GUARD_SCHEME")
    rest = base_url[marker + 3:]
    end = min([index for index in (rest.find("/"), rest.find("?"), rest.find("#")) if index != -1] + [len(rest)])
    authority, tail = rest[:end], rest[end:]
    if "#" in tail:
        raise MeqError("MEQ_GUARD_FRAGMENT")
    if "?" in tail:
        raise MeqError("MEQ_GUARD_QUERY")
    if "@" in authority:
        raise MeqError("MEQ_GUARD_USERINFO")
    if "%" in authority:
        raise MeqError("MEQ_GUARD_MALFORMED")
    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            raise MeqError("MEQ_GUARD_MALFORMED")
        host, after = authority[1:close], authority[close + 1:]
        if after and not after.startswith(":"):
            raise MeqError("MEQ_GUARD_MALFORMED")
        port_text = after[1:] if after else None
        bracketed = True
    else:
        if authority.count(":") > 1:
            raise MeqError("MEQ_GUARD_MALFORMED")
        host, separator, port_text = authority.partition(":")
        port_text = port_text if separator else None
        bracketed = False
    if host == "":
        raise MeqError("MEQ_GUARD_EMPTY_HOST")
    if "[" in host or "]" in host:
        raise MeqError("MEQ_GUARD_MALFORMED")
    port = _SCHEME_PORTS[scheme]
    if port_text is not None:
        if not port_text or len(port_text) > 5 or any(ch not in _DIGITS for ch in port_text):
            raise MeqError("MEQ_GUARD_PORT")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise MeqError("MEQ_GUARD_PORT")
    if bracketed:
        try:
            address = ipaddress.IPv6Address(host)
        except ValueError:
            raise MeqError("MEQ_GUARD_MALFORMED") from None
    elif host.lower() == "localhost":
        # The one admitted name, mapped to loopback here: no resolver, hosts file or DNS is consulted.
        address = ipaddress.IPv4Address(LOCALHOST_ADDRESS)
    else:
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError:
            # Every other name is refused as written; it is never resolved.
            raise MeqError("MEQ_GUARD_NAME") from None
    if any(address in network for network in _LINK_LOCAL):
        raise MeqError("MEQ_GUARD_LINK_LOCAL")
    if not any(address in network for network in _ADMITTED):
        raise MeqError("MEQ_GUARD_HOST_CLASS")
    base_path = tail.rstrip("/")
    if base_path and not _plain_path(base_path):
        raise MeqError("MEQ_GUARD_MALFORMED")
    return Target(scheme, str(address), port, base_path)


def default_connection_factory(scheme, address, port, connect_timeout):
    """Open the real connection (TCP, or TLS for https) to the guarded address and hand over its socket.

    http.client's own connect() is used: it reads no proxy environment variable, and no tunnel is ever set.
    """
    if scheme == "https":
        connection = http.client.HTTPSConnection(address, port, timeout=connect_timeout)
    else:
        connection = http.client.HTTPConnection(address, port, timeout=connect_timeout)
    connection.connect()
    sock, connection.sock = connection.sock, None
    return sock


def _refuse_constant(name):
    raise ValueError("non-finite JSON number")


def _parse_json(raw):
    try:
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        return json.loads(text, parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise MeqError("MEQ_MALFORMED_JSON") from None


def _encode(payload):
    try:
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise MeqError("MEQ_CONFIG_INVALID") from None


def _io_code(error):
    """The code of a transport failure after the connection was opened."""
    if isinstance(error, TimeoutError):
        return "MEQ_READ_TIMEOUT"
    if isinstance(error, (http.client.RemoteDisconnected, http.client.IncompleteRead)):
        return "MEQ_CONNECTION_LOST"
    if isinstance(error, http.client.HTTPException):
        return "MEQ_PROTOCOL_ERROR"
    return "MEQ_CONNECTION_LOST"


class _Exchange:
    """One request on one connection: the socket, the response and the request deadline."""

    def __init__(self, sock, deadline):
        self.sock = sock
        self.deadline = deadline
        self.response = None

    def arm(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise MeqError("MEQ_READ_TIMEOUT")
        # http.client really closes the socket once a response is complete; a closed socket needs no timeout.
        if self.sock.fileno() != -1:
            self.sock.settimeout(remaining)

    def close(self, abort=False):
        if abort:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.response is not None:
            try:
                self.response.close()
            except (OSError, http.client.HTTPException):
                pass
        try:
            self.sock.close()
        except OSError:
            pass


class MeqClient:
    """The probe client for one guarded base URL and one profile. Each call opens, uses and closes one connection."""

    def __init__(self, base_url, profile_id, *, factory=None, request_timeout_s=None):
        self.target = guard_base_url(base_url)
        if profile_id not in REQUEST_TIMEOUT_S:
            raise MeqError("MEQ_CONFIG_INVALID")
        limit = REQUEST_TIMEOUT_S[profile_id]
        if request_timeout_s is None:
            request_timeout_s = limit
        if type(request_timeout_s) not in (int, float) or not 0 < request_timeout_s <= limit:
            raise MeqError("MEQ_CONFIG_INVALID")
        if factory is not None and not callable(factory):
            raise MeqError("MEQ_CONFIG_INVALID")
        self.profile_id = profile_id
        self.request_timeout_s = float(request_timeout_s)
        self._factory = factory

    def get_json(self, path):
        """GET base_path + path and return the parsed JSON body."""
        return self._json("GET", path, None)

    def post_json(self, path, payload):
        """POST a JSON payload and return the parsed JSON body."""
        return self._json("POST", path, _encode(payload))

    def post_stream(self, path, payload, cancel=None):
        """POST a JSON payload and read server-sent events up to the terminal [DONE]; return the parsed event payloads.

        `cancel`, if given, is polled before each line is read; when it returns true the connection is shut down and
        closed and MEQ_CANCELLED is raised.
        """
        if cancel is not None and not callable(cancel):
            raise MeqError("MEQ_CONFIG_INVALID")
        exchange = self._open("POST", path, _encode(payload), "text/event-stream")
        try:
            return self._events(exchange, cancel)
        except MeqError as error:
            exchange.close(abort=error.code == "MEQ_CANCELLED")
            raise
        finally:
            exchange.close()

    def _json(self, method, path, body):
        exchange = self._open(method, path, body, "application/json")
        try:
            return _parse_json(self._body(exchange))
        finally:
            exchange.close()

    def _open(self, method, path, body, accept):
        if type(path) is not str or not _plain_path(path):
            raise MeqError("MEQ_CONFIG_INVALID")
        target = self.target
        deadline = time.monotonic() + self.request_timeout_s
        factory = self._factory if self._factory is not None else default_connection_factory
        try:
            sock = factory(target.scheme, target.address, target.port, CONNECT_TIMEOUT_S)
        except TimeoutError:
            raise MeqError("MEQ_CONNECT_TIMEOUT") from None
        except OSError:
            raise MeqError("MEQ_CONNECT_FAILED") from None
        exchange = _Exchange(sock, deadline)
        try:
            connection = http.client.HTTPConnection(target.address, target.port, timeout=self.request_timeout_s)
            # The factory's socket is the connection's socket, as http.client allows; connect() is never called.
            connection.sock = sock
            headers = {"Accept": accept, "Connection": "close"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            exchange.arm()
            connection.request(method, target.base_path + path, body=body, headers=headers)
            exchange.arm()
            exchange.response = connection.getresponse()
            status = exchange.response.status
            if 300 <= status <= 399:
                # Never followed: the Location header is not read.
                raise MeqError("MEQ_REDIRECT_REFUSED", status=status)
            if 200 <= status <= 299:
                return exchange
            error_body = None
            try:
                error_body = _parse_json(self._body(exchange))
            except MeqError:
                pass
            if 400 <= status <= 499:
                raise MeqError("MEQ_HTTP_CLIENT_ERROR", status=status, body=error_body)
            if 500 <= status <= 599:
                raise MeqError("MEQ_HTTP_SERVER_ERROR", status=status, body=error_body)
            raise MeqError("MEQ_PROTOCOL_ERROR", status=status)
        except MeqError:
            exchange.close()
            raise
        except (OSError, http.client.HTTPException) as error:
            exchange.close()
            raise MeqError(_io_code(error)) from None

    def _body(self, exchange):
        response = exchange.response
        if response.length is not None and response.length > MAX_RESPONSE_BYTES:
            raise MeqError("MEQ_OVERSIZE", status=response.status)
        data = bytearray()
        while True:
            exchange.arm()
            try:
                chunk = response.read(min(READ_CHUNK_BYTES, MAX_RESPONSE_BYTES + 1 - len(data)))
            except (OSError, http.client.HTTPException) as error:
                raise MeqError(_io_code(error)) from None
            if not chunk:
                if response.length:
                    # http.client returns an empty read, not an error, when a Content-Length body is cut short.
                    raise MeqError("MEQ_CONNECTION_LOST", status=response.status)
                return bytes(data)
            data += chunk
            if len(data) > MAX_RESPONSE_BYTES:
                raise MeqError("MEQ_OVERSIZE", status=response.status)

    def _events(self, exchange, cancel):
        response = exchange.response
        events, data_lines, total = [], [], 0
        while True:
            if cancel is not None and cancel():
                raise MeqError("MEQ_CANCELLED")
            exchange.arm()
            try:
                line = response.readline(MAX_SSE_LINE_BYTES + 1)
            except (OSError, http.client.HTTPException) as error:
                raise MeqError(_io_code(error)) from None
            total += len(line)
            if total > MAX_SSE_TOTAL_BYTES or len(line) > MAX_SSE_LINE_BYTES:
                raise MeqError("MEQ_OVERSIZE")
            if not line.endswith(b"\n"):
                # The stream ended (or broke off mid-line) before its terminal [DONE] event.
                raise MeqError("MEQ_SSE_FRAMING")
            try:
                text = line[:-1].decode("utf-8")
            except UnicodeDecodeError:
                raise MeqError("MEQ_SSE_FRAMING") from None
            if text.endswith("\r"):
                text = text[:-1]
            if "\r" in text:
                raise MeqError("MEQ_SSE_FRAMING")
            if text == "":
                if not data_lines:
                    continue
                data, data_lines = "\n".join(data_lines), []
                if data == "[DONE]":
                    return events
                events.append(_parse_json(data))
                continue
            if text.startswith(":"):
                continue
            field, separator, value = text.partition(":")
            if not separator:
                raise MeqError("MEQ_SSE_FRAMING")
            if value.startswith(" "):
                value = value[1:]
            if field == "data":
                data_lines.append(value)
            elif field not in ("event", "id", "retry"):
                raise MeqError("MEQ_SSE_FRAMING")
