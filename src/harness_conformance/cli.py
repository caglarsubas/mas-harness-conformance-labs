from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .acceptance import build_candidate, validate_candidate
from .campaign import run_campaign_files
from .canonical import canonical_bytes, load_json
from .errors import ConformanceError
from .evidence import build_evidence, sign_evidence, validate_evidence, verify_evidence
from .schema import validate


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harness-conformance", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    validate_command = commands.add_parser("validate", allow_abbrev=False)
    validate_command.add_argument("--kind", required=True, choices=("campaign", "environment-intake", "control-result", "porting-ledger", "technical-evidence", "tenant-acceptance-candidate"))
    validate_command.add_argument("path", type=Path)
    for name in ("run", "evidence-verify", "acceptance-candidate"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--campaign", required=True, type=Path)
        command.add_argument("--repository", default=Path.cwd(), type=Path)
    signing = commands.add_parser("technical-sign", allow_abbrev=False)
    signing.add_argument("--evidence", required=True, type=Path)
    signing.add_argument("--key", required=True, type=Path)
    verification = commands.add_parser("technical-verify", allow_abbrev=False)
    verification.add_argument("--evidence", required=True, type=Path)
    verification.add_argument("--trust", required=True, type=Path)
    verification.add_argument("--now", required=True)
    return parser


def _emit(value: Any) -> None:
    sys.stdout.buffer.write(canonical_bytes(value) + b"\n")


def _run_files(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    repository = args.repository.resolve()
    campaign_path = args.campaign.resolve()
    if repository not in campaign_path.parents:
        raise ConformanceError("CAMPAIGN_OUTSIDE_REPOSITORY", "campaign escaped the repository")
    report, _ = run_campaign_files(campaign_path, repository)
    return report, build_evidence(report)


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "validate":
            document = load_json(args.path)
            if args.kind == "technical-evidence":
                validate_evidence(document)
            elif args.kind == "tenant-acceptance-candidate":
                validate_candidate(document)
            else:
                validate(args.kind, document)
            _emit({"kind": args.kind, "status": "PASS"})
        elif args.command == "run":
            report, _ = _run_files(args)
            _emit(report)
        elif args.command == "evidence-verify":
            report, evidence = _run_files(args)
            validate_evidence(evidence, signed=False)
            _emit({"bundleDigest": evidence["bundleDigest"], "reportDigest": report["reportDigest"], "status": "PASS"})
        elif args.command == "acceptance-candidate":
            report, evidence = _run_files(args)
            candidate = build_candidate(report, evidence)
            validate_candidate(candidate)
            _emit(candidate)
        elif args.command == "technical-sign":
            key_path = args.key.resolve()
            if key_path.is_symlink() or os.stat(key_path).st_mode & 0o077:
                raise ConformanceError("PRIVATE_KEY_MODE", "signing-key file must not grant group or other access")
            _emit(sign_evidence(load_json(args.evidence), load_json(key_path, require_absolute=True)))
        elif args.command == "technical-verify":
            _emit(verify_evidence(load_json(args.evidence), load_json(args.trust), now=args.now))
        return 0
    except ConformanceError as exc:
        sys.stderr.write(json.dumps({"reasonCode": exc.reason, "status": "FAIL"}, separators=(",", ":")) + "\n")
        return 2
