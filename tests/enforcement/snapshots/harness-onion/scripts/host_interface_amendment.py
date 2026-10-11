#!/usr/bin/env python3
"""W01-AMEND: W02d's carried items as a reviewed amendment of the resolved W01 host-interface specification.

The resolved specification (architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md) stays byte-identical:
later layers freeze it, and this module pins its digest. The amendment record
(architecture/host-interface-amendment-w02d/amendment.json) lists exact, counted substring replacements, each citing its
owner decisions; every item W02d carried to W01 (architecture/seccomp-allowlists/status.json, carriedToW01) has a
disposition naming the items and obligations that answer it. effective_spec() applies the replacements to the pinned
base bytes and must give exactly the pinned effective bytes, which are published beside the record.

check(read) validates the record, the carried items, the base and the published effective specification through an
injected byte reader, so a history-chain layer can pass its reviewed_bytes.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

SCHEMA = "planeon.internal.host-interface-amendment/v1"
RECORD_PATH = "architecture/host-interface-amendment-w02d/amendment.json"
BASE_PATH = "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md"
BASE_SHA256 = "8a3a09bb5dbc08804dbea06dd0700a14648a9cdbc8efd62112dc64ba0b6ba1b4"
EFFECTIVE_PATH = "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md"
CARRIED_PATH = "architecture/seccomp-allowlists/status.json"
DESIGN_LABEL = "HOST-INTERFACE-DRAFT-002-W02D"
DECIDED = "OWNER_DECIDED"
KINDS = ("CARRIED", "RESTATED", "EDITORIAL")   # RESTATED: an adopted decision the rows contradict, not a carried item
RECORD_KEYS = {"schemaVersion", "designLabel", "base", "effective", "carriedFrom", "ownerDecisions", "items",
               "dispositions", "obligations", "notAmended"}
ITEM_KEYS = {"id", "kind", "section", "baseLines", "current", "proposed", "occurrences", "decisions", "source", "why"}
MAX_BYTES = 16_777_216


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate amendment member: " + key)
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite amendment number")

    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "bounded amendment bytes")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _texts(value: Any) -> bool:
    return type(value) is list and bool(value) and all(_text(entry) for entry in value) and len(set(value)) == len(value)


def _ids(value: Any) -> bool:
    """A possibly empty list of distinct non-empty strings."""
    return type(value) is list and all(_text(entry) for entry in value) and len(set(value)) == len(value)


OBLIGATION_REF = re.compile(r"\bO-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")
EDGES = ("# W01 host interfaces — gate resolutions, candidate v2\n",
         "- https://kubernetes.io/docs/reference/access-authn-authz/authorization/\n")


def _closed(value: Any, keys: set, message: str) -> None:
    require(type(value) is dict and set(value) == keys, message)


def check_record(record: Any, carried: list) -> None:
    """A closed record: pinned paths, decided owner decisions, exact items, and a disposition for every carried item."""
    _closed(record, RECORD_KEYS, "closed amendment record")
    require(record["schemaVersion"] == SCHEMA and record["designLabel"] == DESIGN_LABEL, "amendment schema and label")
    require(record["base"] == {"path": BASE_PATH, "sha256": BASE_SHA256}, "pinned W01 base")
    _closed(record["effective"], {"path", "sha256"}, "closed effective pin")
    require(record["effective"]["path"] == EFFECTIVE_PATH and type(record["effective"]["sha256"]) is str
            and len(record["effective"]["sha256"]) == 64, "effective path and digest")
    _closed(record["carriedFrom"], {"path", "field", "items"}, "closed carried source")
    require(record["carriedFrom"]["path"] == CARRIED_PATH and record["carriedFrom"]["field"] == "carriedToW01"
            and record["carriedFrom"]["items"] == carried, "every item W02d carried to W01, in order")
    decisions = record["ownerDecisions"]
    require(type(decisions) is list and bool(decisions), "owner decisions")
    for row in decisions:
        _closed(row, {"id", "date", "state", "decision"}, "closed owner decision")
        require(_text(row["id"]) and _text(row["date"]) and row["state"] == DECIDED and _text(row["decision"]),
                "every owner decision is decided: %r" % (row.get("id"),))
    ids = [row["id"] for row in decisions]
    require(len(ids) == len(set(ids)), "unique owner decisions")
    items = record["items"]
    require(type(items) is list and bool(items), "amendment items")
    item_ids = []
    for item in items:
        _closed(item, ITEM_KEYS, "closed amendment item")
        require(_text(item["id"]) and item["id"] not in item_ids and item["kind"] in KINDS and _text(item["section"])
                and _text(item["baseLines"]) and _text(item["why"]) and _text(item["source"]),
                "described amendment item %r" % (item["id"],))
        require(_text(item["current"]) and type(item["proposed"]) is str and item["current"] != item["proposed"]
                and type(item["occurrences"]) is int and item["occurrences"] >= 1, "effective amendment item " + item["id"])
        require(_ids(item["decisions"]) and set(item["decisions"]) <= set(ids)
                and (item["kind"] == "EDITORIAL") == (not item["decisions"]),
                "item %s cites decided owner decisions" % item["id"])
        if item["kind"] == "EDITORIAL":
            # Only the title line and the last line, each kept: an editorial item adds text, it never changes the record.
            require(item["current"] in EDGES and item["proposed"].startswith(item["current"].rstrip("\n")),
                    "editorial item %s only extends the title or the last line" % item["id"])
        if item["kind"] == "RESTATED":
            require(item["decisions"][:1] == ["W02d-QB"] and set(item["decisions"]) <= {"W02d-QB", "W01-AMEND-QW4"}
                    and "ENOSYS" in item["proposed"] and "ENOSYS" not in item["current"],
                    "restated item %s only restates W02d-QB's ENOSYS refusal" % item["id"])
        item_ids.append(item["id"])
    obligations = record["obligations"]
    require(type(obligations) is list, "obligations")
    obligation_ids = []
    for row in obligations:
        _closed(row, {"id", "owner", "text"}, "closed obligation")
        require(_text(row["id"]) and row["id"] not in obligation_ids and _text(row["owner"]) and _text(row["text"]),
                "described obligation")
        obligation_ids.append(row["id"])
    dispositions = record["dispositions"]
    require(type(dispositions) is list and [row.get("item") for row in dispositions if type(row) is dict] == carried,
            "one disposition per carried item, in order")
    answered, used = set(), set()
    for row in dispositions:
        _closed(row, {"item", "decisions", "items", "obligations", "summary"}, "closed disposition")
        require(_texts(row["items"]) and set(row["items"]) <= set(item_ids)
                and _ids(row["decisions"]) and set(row["decisions"]) <= set(ids)
                and _ids(row["obligations"]) and set(row["obligations"]) <= set(obligation_ids)
                and _text(row["summary"]), "disposition of %r names known items, decisions and obligations" % row["item"])
        cited = {decision for item in items if item["id"] in row["items"] for decision in item["decisions"]}
        require(set(row["decisions"]) <= cited, "disposition of %r cites only its items' decisions" % row["item"])
        answered |= set(row["items"])
        used |= set(row["obligations"])
    require({item["id"] for item in items if item["kind"] == "CARRIED"} <= answered,
            "every carried amendment answers a carried item")
    require(used == set(obligation_ids), "every obligation answers a carried item")
    named = {ref for item in items for ref in OBLIGATION_REF.findall(item["proposed"])}
    require(named <= set(obligation_ids), "every obligation an item names exists")
    require(_texts(record["notAmended"]), "stated non-amendments")


def effective_spec(record: dict, base: bytes) -> bytes:
    """Apply every item in order. Each current text occurs exactly its stated number of times when applied, and every
    proposed text still occurs exactly that often at the end, so no later item rewrites an earlier one."""
    require(type(base) is bytes and digest(base) == BASE_SHA256, "pinned W01 base bytes")
    text = base.decode("utf-8")
    for item in record["items"]:
        require(text.count(item["current"]) == item["occurrences"], "item %s current text count" % item["id"])
        before = text.count(item["proposed"])
        text = text.replace(item["current"], item["proposed"])
        require(text.count(item["proposed"]) == before + item["occurrences"], "item %s proposed text count" % item["id"])
    for item in record["items"]:
        require(text.count(item["proposed"]) >= item["occurrences"], "item %s survives every later item" % item["id"])
    raw = text.encode("utf-8")
    require(digest(raw) == record["effective"]["sha256"], "pinned effective W01 bytes")
    return raw


def check(read: Callable[[str], bytes]) -> dict:
    """The record is closed and answers every carried item, and the published effective specification is exact."""
    carried = parse(read(CARRIED_PATH))
    require(type(carried) is dict and type(carried.get("carriedToW01")) is list, "W02d carried items")
    record = parse(read(RECORD_PATH))
    check_record(record, carried["carriedToW01"])
    effective = effective_spec(record, read(BASE_PATH))
    require(read(EFFECTIVE_PATH) == effective, "published effective specification")
    return record
