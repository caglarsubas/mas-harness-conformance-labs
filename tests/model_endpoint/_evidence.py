"""CONF-MEQ-001A: the per-profile evidence record of MODEL-EXIST-QUAL-001 (shape only; no row has a pass rule yet).

One record per profile id, never pooled (run plan rev 3, sections 2 and 6; owner decision Q-MEQ-PROFILES). Each record
names its profile and backend role and carries one row per probe row of run plan section 5, in that order. A row's status
is exactly PASS, FAIL, NOT_SERVED or NOT_RUN_ENV_UNAVAILABLE. A row may carry a short fixed `detail`; every string
outside the shape's own vocabulary is scanned by leak_class, which detects the classes listed in its docstring. The
rows' pass rules, the PI-D1 mapping and the events binding wait for MEQ-CAMPAIGN-CONTRACT.

Records are serialized as sorted-key, compact, ASCII JSON plus a trailing newline.
"""
import ipaddress
import json

SCHEMA = "r12.meq-profile-evidence/v1"
# Profile id -> backend role (run plan rev 3, section 2).
PROFILES = {"dev-macos-arm64": "planeon.ollama",
            "linux-amd64-cpu": "planeon.llamacpp",
            "linux-amd64-nvidia": "planeon.vllm"}
# The closed row list, in run plan rev 3 section 5 order: the network-disabled-startup row, then the probe table's rows.
ROW_IDS = ("network-disabled-startup", "local-weights", "streaming", "embeddings", "cancellation", "context-at-limit",
           "context-over-limit", "structured-output", "no-network-pulls", "hosted-fallback", "tunnel", "errors-and-usage")
STATUSES = ("PASS", "FAIL", "NOT_SERVED", "NOT_RUN_ENV_UNAVAILABLE")
RECORD_FIELDS = {"schemaVersion", "profileId", "backendRole", "rows"}
ROW_FIELDS = {"id", "profileId", "status"}
ROW_OPTIONAL_FIELDS = {"detail"}
MAX_DETAIL_CHARS = 200
# Fixed vocabulary of the shape itself; every other string is scanned for leaks.
_VOCABULARY = frozenset({SCHEMA, *PROFILES, *PROFILES.values(), *ROW_IDS, *STATUSES, *RECORD_FIELDS, *ROW_FIELDS,
                         *ROW_OPTIONAL_FIELDS})
_CREDENTIAL_MARKERS = ("bearer ", "basic ", "-----begin", "password", "passwd", "secret", "api_key", "api-key", "apikey",
                       "authorization", "private key", "access_token", "auth_token", "token=", "session=", "cookie")
# Key prefixes and local-path markers are built from parts, so no line of this file carries a key or path shape.
_KEY_PREFIXES = tuple(stem + tail for stem, tail in (
    ("sk", "-"), ("sk", "_"), ("pk", "_"), ("rk", "_"), ("gh", "p_"), ("gh", "o_"), ("gh", "s_"), ("gh", "u_"),
    ("github", "_pat_"), ("glpat", "-"), ("xox", "a-"), ("xox", "b-"), ("xox", "p-"), ("hf", "_"), ("ak", "ia"),
    ("as", "ia"), ("ai", "za")))
_PATH_MARKERS = tuple("/" + name + "/" for name in ("users", "home", "root", "private", "tmp")) + ("c:" + "\\",)
_SEPARATORS = frozenset(" \t\n\r,;()[]{}<>\"'`|=!?*")
_HEX_RUN = frozenset("0123456789abcdefABCDEF:.")
_LABEL = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_OPAQUE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+/=")
# LM-P1-1 (2): a percent-encoded scheme separator is refused as written, in any letter case; values are never decoded.
_PERCENT_SEPARATOR = "%3a" + "%2f" * 2
# LM-P2-1 (2): an encoded double slash, and a doubly encoded colon or slash, refused as written in any letter case.
_ENCODED_DOUBLE_SLASH = "%2f" * 2
_DOUBLE_ENCODED_COLON = "%25" + "3a"
_DOUBLE_ENCODED_SLASH = "%25" + "2f"
# LM-P2-1 (1): every token is also checked part by part, split on each of these characters.
_PART_SEPARATORS = ("/", "\\", "#", "&", "~", ":")
_OCTAL_DIGITS = frozenset("01234567")
_BASE64URL = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
_JWT_HEADER = "ey" + "J"
_DIGIT_CHARS = frozenset("0123456789")
_HEX_DIGITS = frozenset("0123456789abcdef")
# The inet_aton field widths, in bits, of the one-, two- and three-part IPv4 forms (a, a.b and a.b.c).
_INET_WIDTHS = {1: (32,), 2: (8, 24), 3: (8, 8, 16)}


class EvidenceError(ValueError):
    """A refused record; the message names the rule."""

    def __init__(self, reason):
        super().__init__("evidence: " + reason)
        self.reason = reason


def _tokens(text):
    token = []
    for ch in text + " ":
        if ch in _SEPARATORS:
            if token:
                yield "".join(token)
                token = []
        else:
            token.append(ch)


def _runs(text, alphabet):
    run = []
    for ch in text + " ":
        if ch in alphabet:
            run.append(ch)
        elif run:
            yield "".join(run)
            run = []


def _dotted_quad(run):
    for part in run.split(":"):
        groups = part.split(".")
        for start in range(len(groups) - 3):
            window = groups[start:start + 4]
            if all(group and len(group) <= 3 and group.isdigit() for group in window):
                return True
    return False


def _inet_number(part):
    """(value, is_hex) of a decimal or 0x-hex inet_aton part, or (None, False)."""
    low = part.lower()
    if low.startswith("0x") and 3 <= len(low) <= 10 and set(low[2:]) <= _HEX_DIGITS:
        return int(low[2:], 16), True
    if part and len(part) <= 10 and set(part) <= _DIGIT_CHARS:
        return int(part), False
    return None, False


def _short_ipv4(token):
    """LM-P1-1 (4): an integer, 0x-hex or short dotted IPv4 form (inet_aton's a, a.b and a.b.c shapes).

    Bound, so that only address-shaped values are refused: every part must fit its inet_aton field, and the first octet
    must be non-zero (0.0.0.0/8 is "this network", never a host). So a plain integer is refused only from 2^24 =
    16,777,216 up to 2^32 - 1, and row counts, byte counts and latencies in milliseconds below that stay legal; 0x10
    stays legal too. A two-part decimal a.b is also an ordinary decimal number, so it is refused only when a is 10 or
    more: that covers the first octet of every loopback, private, link-local and shared range (10, 100, 127, 169, 172,
    192, 198) while 0.5 or 1.25 stay legal. A hex part makes any form address-shaped.
    """
    parts = token.rstrip(".").split(".")
    if len(parts) == 4:
        return _marked_quad(parts)
    if len(parts) not in _INET_WIDTHS:
        return False
    values, hexed = [], False
    for part, width in zip(parts, _INET_WIDTHS[len(parts)]):
        value, is_hex = _inet_number(part)
        if value is None or value >= 1 << width:
            return False
        values.append(value)
        hexed = hexed or is_hex
    first_octet = values[0] >> 24 if len(values) == 1 else values[0]
    if len(values) == 2 and not hexed:
        return first_octet >= 10
    return first_octet >= 1


def _marked_quad(parts):
    """LM-P2-1 (4): a four-part dotted form with a 0x-hex or leading-zero (octal) part, each part one octet. A plain
    decimal dotted quad is caught by the address runs already."""
    marked = False
    for part in parts:
        low = part.lower()
        if low.startswith("0x") and 3 <= len(low) <= 4 and set(low[2:]) <= _HEX_DIGITS:
            value, marked = int(low[2:], 16), True
        elif len(part) > 1 and part.startswith("0") and set(part) <= _OCTAL_DIGITS:
            value, marked = int(part, 8), True
        elif part and set(part) <= _DIGIT_CHARS:
            value = int(part)
        else:
            return False
        if value > 255:
            return False
    return marked


def _jwt(token):
    """A JWT shape: base64url segments joined by '.', the first starting with a JSON-object header. LM-P1-1 (3) takes
    the signed form (three non-empty segments); LM-P2-1 (3) adds the unsigned form (an empty third segment) and a
    two-segment form."""
    segments = token.split(".")
    if not segments[0].startswith(_JWT_HEADER) or not all(set(segment) <= _BASE64URL for segment in segments):
        return False
    if len(segments) == 3 and segments[1] and segments[2]:
        return True
    if len(segments) == 3 and segments[1]:
        return True
    if len(segments) == 2 and segments[1]:
        return True
    return False


def _host(value):
    """A dotted host name: two or more labels of [a-z0-9-], the last alphabetic and at least two letters long."""
    labels = value.rstrip(".").split(".")
    return (len(labels) >= 2 and all(label and set(label) <= _LABEL for label in labels) and labels[-1].isalpha()
            and len(labels[-1]) >= 2)


def _parts(token):
    """LM-P2-1 (1): the token itself and each part of it, split on every character of _PART_SEPARATORS."""
    parts = [token]
    for separator in _PART_SEPARATORS:
        parts = [piece for part in parts for piece in part.split(separator)]
    return [token] + parts


def leak_class(text):
    """The first leak class found in `text`, or None:
    - "url": '://', a token starting with '//', or, as written in any letter case, a percent-encoded '://', an
      encoded double slash, or a doubly encoded colon or slash;
    - "localhost": the name localhost; "account": an '@' (an e-mail-style account, user@host);
    - "path": a local path under a home, root, private or temporary directory, or a drive letter;
    - "credential": authorization, password, secret and key markers, known key prefixes, a signed, unsigned or
      two-segment JWT shape, or a long opaque token;
    - "address": an IPv4 or IPv6 literal, an integer, 0x-hex or short dotted IPv4 form (bounded, see _short_ipv4), or
      a dotted quad with a hex or leading-zero part;
    - "port": a ':' followed by a digit;
    - "host": a dotted host name.
    The host, JWT and short-IPv4 rules apply to every part of a token (see _parts). Detection is best-effort; the
    README states its limits.
    """
    low = text.lower()
    if "://" in text:
        return "url"
    if _PERCENT_SEPARATOR in low:
        return "url"
    if _ENCODED_DOUBLE_SLASH in low:
        return "url"
    if _DOUBLE_ENCODED_COLON in low:
        return "url"
    if _DOUBLE_ENCODED_SLASH in low:
        return "url"
    # LM-P1-1 (1): a network-path reference (a token starting with //).
    if any(token.startswith("//") for token in _tokens(text)):
        return "url"
    if "localhost" in low:
        return "localhost"
    if "@" in text:
        return "account"
    if any(marker in low for marker in _PATH_MARKERS):
        return "path"
    if any(marker in low for marker in _CREDENTIAL_MARKERS):
        return "credential"
    for run in _runs(text, _HEX_RUN):
        if run.count(":") >= 2 or _dotted_quad(run):
            return "address"
    for token in _tokens(text):
        try:
            ipaddress.ip_address(token.strip("[]"))
            return "address"
        except ValueError:
            pass
    if any(_short_ipv4(part) for token in _tokens(text) for part in _parts(token)):
        return "address"
    for index, ch in enumerate(text[:-1]):
        if ch == ":" and text[index + 1].isdigit():
            return "port"
    for token in _tokens(text):
        lowered = token.lower()
        if any(_jwt(part) for part in _parts(token)):
            return "credential"
        if lowered.startswith(_KEY_PREFIXES):
            return "credential"
        if (len(token) >= 32 and all(ch in _OPAQUE for ch in token) and any(ch.isdigit() for ch in token)
                and any(ch.isalpha() for ch in token)):
            return "credential"
        # LM-P1-1 (1), LM-P2-1 (1): the host rule applies to each part of a token.
        if any(_host(part) for part in _parts(lowered)):
            return "host"
    return None


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _check_leaks(record):
    for text in _strings(record):
        if text in _VOCABULARY:
            continue
        found = leak_class(text)
        if found is not None:
            raise EvidenceError("leak (" + found + ")")


def validate_record(record):
    """Refuse anything but one closed record of one profile; return the record."""
    if type(record) is not dict or set(record) != RECORD_FIELDS or record["schemaVersion"] != SCHEMA:
        raise EvidenceError("closed record")
    _check_leaks(record)
    profile_id = record["profileId"]
    if type(profile_id) is not str or profile_id not in PROFILES:
        raise EvidenceError("profile id")
    if record["backendRole"] != PROFILES[profile_id]:
        raise EvidenceError("pooled (backend role of another profile)")
    rows = record["rows"]
    if type(rows) is not list or not all(type(row) is dict for row in rows):
        raise EvidenceError("closed rows")
    for row in rows:
        if not ROW_FIELDS <= set(row) <= ROW_FIELDS | ROW_OPTIONAL_FIELDS:
            raise EvidenceError("closed row")
        if row["profileId"] != profile_id:
            raise EvidenceError("pooled (a row of another profile)")
        if type(row["id"]) is not str or row["id"] not in ROW_IDS:
            raise EvidenceError("row id")
        if type(row["status"]) is not str or row["status"] not in STATUSES:
            raise EvidenceError("status")
        if "detail" in row:
            detail = row["detail"]
            if (type(detail) is not str or not detail or len(detail) > MAX_DETAIL_CHARS
                    or any(not " " <= ch <= "~" for ch in detail)):
                raise EvidenceError("detail")
    if [row["id"] for row in rows] != list(ROW_IDS):
        raise EvidenceError("rows (each row id once, in order)")
    return record


def build_record(profile_id, statuses, details=None):
    """Build and validate the record of one profile from {row id: status} and optional {row id: detail}."""
    details = {} if details is None else details
    if type(statuses) is not dict or set(statuses) != set(ROW_IDS):
        raise EvidenceError("rows (each row id once, in order)")
    if type(details) is not dict or not set(details) <= set(ROW_IDS):
        raise EvidenceError("detail")
    rows = []
    for row_id in ROW_IDS:
        row = {"id": row_id, "profileId": profile_id, "status": statuses[row_id]}
        if row_id in details:
            row["detail"] = details[row_id]
        rows.append(row)
    return validate_record({"schemaVersion": SCHEMA, "profileId": profile_id, "backendRole": PROFILES.get(profile_id),
                            "rows": rows})


def validate_records(records):
    """Refuse a set of records that pools profiles: each record valid, each profile id at most once."""
    if type(records) is not list:
        raise EvidenceError("record list")
    seen = set()
    for record in records:
        validate_record(record)
        if record["profileId"] in seen:
            raise EvidenceError("pooled (one record per profile id)")
        seen.add(record["profileId"])
    return records


def serialize(record):
    validate_record(record)
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _no_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise EvidenceError("duplicate key")
    return dict(pairs)


def parse(raw):
    """Parse canonical record bytes and validate them; non-canonical bytes are refused."""
    try:
        record = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError, AttributeError) as error:
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError("not JSON") from None
    if serialize(validate_record(record)) != raw:
        raise EvidenceError("not canonical")
    return record
