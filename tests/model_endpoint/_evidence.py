"""CONF-MEQ-001A: the per-profile evidence record of MODEL-EXIST-QUAL-001 (shape only; no row has a pass rule yet).

One record per profile id, never pooled (run plan rev 3, sections 2 and 6; owner decision Q-MEQ-PROFILES). Each record
names its profile and backend role and carries one row per probe row of run plan section 5, in that order. A row's status
is exactly PASS, FAIL, NOT_SERVED or NOT_RUN_ENV_UNAVAILABLE. A row may carry a short fixed `detail`; no record may
carry a host, an address, a port, a URL, an account name or a credential-shaped value anywhere. The rows' pass rules, the
PI-D1 mapping and the events binding wait for MEQ-CAMPAIGN-CONTRACT.

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


def leak_class(text):
    """The first leak class found in `text` ("url", "localhost", "account", "path", "credential", "address", "port" or
    "host"), or None."""
    low = text.lower()
    if "://" in text:
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
    for index, ch in enumerate(text[:-1]):
        if ch == ":" and text[index + 1].isdigit():
            return "port"
    for token in _tokens(text):
        lowered = token.lower()
        if lowered.startswith(_KEY_PREFIXES):
            return "credential"
        if (len(token) >= 32 and all(ch in _OPAQUE for ch in token) and any(ch.isdigit() for ch in token)
                and any(ch.isalpha() for ch in token)):
            return "credential"
        labels = lowered.rstrip(".").split(".")
        if (len(labels) >= 2 and all(label and set(label) <= _LABEL for label in labels) and labels[-1].isalpha()
                and len(labels[-1]) >= 2):
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
