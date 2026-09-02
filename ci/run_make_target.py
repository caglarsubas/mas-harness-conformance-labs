from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DESCRIPTORS = ROOT / "ci" / "targets"
GENERIC = {"campaign": "run", "evidence-verify": "evidence-verify", "acceptance-package": "acceptance-candidate"}
TARGET = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
PACKET = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
CAMPAIGN = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
SHELLS = {"sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh"}


def refuse(message: str) -> "NoReturn":
    print(f"make-dispatch refused: {message}", file=sys.stderr)
    raise SystemExit(2)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse(f"duplicate JSON member {key}")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or path.parent != DESCRIPTORS:
        refuse("descriptor path is linked or escaped")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        refuse(f"malformed descriptor {path.name}: {type(exc).__name__}")
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "packetId", "handlers"}:
        refuse(f"descriptor {path.name} has unknown or missing fields")
    if value["schemaVersion"] != "harness.planeon.ai/make-target-descriptor/v1alpha1":
        refuse(f"descriptor {path.name} has unsupported schema")
    packet_id = value["packetId"]
    if not isinstance(packet_id, str) or not PACKET.fullmatch(packet_id):
        refuse(f"descriptor {path.name} has invalid packet ID")
    expected_name = packet_id.lower() + ".json"
    if path.name != expected_name:
        refuse(f"descriptor filename does not match owner {packet_id}")
    if not isinstance(value["handlers"], list) or not value["handlers"]:
        refuse(f"descriptor {path.name} has no handlers")
    return value


def _handlers() -> list[tuple[str, dict[str, Any]]]:
    paths = sorted(DESCRIPTORS.glob("*.json"), key=lambda item: item.name.encode("utf-8"))
    if not paths:
        refuse("no descriptors found")
    records: list[tuple[str, dict[str, Any]]] = []
    seen_packets: set[str] = set()
    seen_exact: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
    previous = ""
    for path in paths:
        descriptor = _load(path)
        packet_id = descriptor["packetId"]
        if packet_id in seen_packets or packet_id < previous:
            refuse("descriptor packet ownership is duplicate or non-lexical")
        seen_packets.add(packet_id)
        previous = packet_id
        for handler in descriptor["handlers"]:
            if not isinstance(handler, dict) or set(handler) != {"target", "variables", "argv"}:
                refuse(f"handler in {path.name} has unknown or missing fields")
            target, variables, argv = handler["target"], handler["variables"], handler["argv"]
            if not isinstance(target, str) or not TARGET.fullmatch(target) or target in GENERIC:
                refuse(f"handler in {path.name} has invalid or reserved target")
            if not isinstance(variables, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in variables.items()):
                refuse(f"handler in {path.name} has invalid variables")
            if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item for item in argv):
                refuse(f"handler in {path.name} is not direct argv")
            executable = Path(argv[0]).name.lower()
            if executable in SHELLS or any(character in argv[0] for character in "|;&`$<>"):
                refuse(f"handler in {path.name} uses shell transport")
            exact = (packet_id, target, tuple(sorted(variables.items())))
            if exact in seen_exact:
                refuse(f"duplicate handler in {path.name}")
            seen_exact.add(exact)
            records.append((packet_id, handler))
    return records


def _generic(target: str) -> list[str]:
    campaign_id = os.environ.get("CAMPAIGN", "")
    if not CAMPAIGN.fullmatch(campaign_id):
        refuse("CAMPAIGN is missing or invalid")
    sys.path.insert(0, str(ROOT / "src"))
    from harness_conformance.registry import resolve_campaign

    try:
        campaign = resolve_campaign(ROOT, campaign_id)
    except ValueError as exc:
        refuse(str(exc))
    return [sys.executable, "-m", "harness_conformance", GENERIC[target], "--campaign", str(campaign.relative_to(ROOT)), "--repository", str(ROOT)]


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not TARGET.fullmatch(argv[0]):
        refuse("exactly one canonical target is required")
    target = argv[0]
    if target in GENERIC:
        commands = [_generic(target)]
    else:
        if os.environ.get("CAMPAIGN"):
            refuse("CAMPAIGN is undeclared for this target")
        commands = []
        for _, handler in _handlers():
            if handler["target"] == target and handler["variables"] == {}:
                commands.append([sys.executable if item == "@PYTHON@" else item for item in handler["argv"]])
        if not commands:
            refuse(f"unknown or inapplicable target {target}")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, env=environment, check=False)
        if completed.returncode:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
