"""CONF-MEQ-001A: the per-profile evidence record is closed, never pooled, and refuses every leak class (host, address,
port, URL, account, local path, credential). Leak vectors are built from parts, so no added line carries one.
"""
import ast
import copy
import unittest
from pathlib import Path

import _evidence

HERE = Path(__file__).resolve().parent
ROW_IDS = ("network-disabled-startup", "local-weights", "streaming", "embeddings", "cancellation", "context-at-limit",
           "context-over-limit", "structured-output", "no-network-pulls", "hosted-fallback", "tunnel", "errors-and-usage")


def statuses(default, **overrides):
    value = {row_id: default for row_id in ROW_IDS}
    value.update({key.replace("_", "-"): status for key, status in overrides.items()})
    return value


def records():
    return {
        "dev-macos-arm64": _evidence.build_record(
            "dev-macos-arm64", statuses("PASS", embeddings="NOT_SERVED", context_over_limit="FAIL"),
            {"embeddings": "The backend serves no embedding model.", "context-over-limit": "Truncated, not refused."}),
        "linux-amd64-cpu": _evidence.build_record("linux-amd64-cpu", statuses("NOT_RUN_ENV_UNAVAILABLE")),
        "linux-amd64-nvidia": _evidence.build_record(
            "linux-amd64-nvidia", statuses("NOT_RUN_ENV_UNAVAILABLE"), {"local-weights": "No GPU host is named."}),
    }


class EvidenceTests(unittest.TestCase):
    def refused(self, record, reason):
        with self.assertRaises(_evidence.EvidenceError) as caught:
            _evidence.validate_record(record)
        self.assertEqual(caught.exception.reason, reason)

    def test_the_profiles_rows_and_statuses_are_the_run_plans(self):
        self.assertEqual(_evidence.PROFILES, {"dev-macos-arm64": "planeon.ollama", "linux-amd64-cpu": "planeon.llamacpp",
                                              "linux-amd64-nvidia": "planeon.vllm"})
        self.assertEqual(_evidence.ROW_IDS, ROW_IDS)
        self.assertEqual(_evidence.STATUSES, ("PASS", "FAIL", "NOT_SERVED", "NOT_RUN_ENV_UNAVAILABLE"))

    def test_a_valid_record_per_profile_round_trips(self):
        for profile_id, record in records().items():
            with self.subTest(profile=profile_id):
                raw = _evidence.serialize(record)
                self.assertTrue(raw.endswith(b"}\n"))
                self.assertEqual(_evidence.parse(raw), record)
                self.assertEqual(_evidence.serialize(_evidence.parse(raw)), raw)
                self.assertEqual((record["profileId"], record["backendRole"]), (profile_id, _evidence.PROFILES[profile_id]))
                self.assertEqual([row["id"] for row in record["rows"]], list(ROW_IDS))
                self.assertTrue(all(row["profileId"] == profile_id for row in record["rows"]))
        self.assertEqual(_evidence.validate_records(list(records().values())), list(records().values()))

    def test_non_canonical_or_duplicate_key_bytes_are_refused(self):
        raw = _evidence.serialize(records()["linux-amd64-cpu"])
        for name, variant, reason in (("indented", raw.replace(b",", b", "), "not canonical"),
                                      ("no newline", raw[:-1], "not canonical"),
                                      ("duplicate key", raw.replace(b'{"backendRole"', b'{"rows":[],"backendRole"', 1),
                                       "duplicate key"),
                                      ("not json", b"{", "not JSON"), ("not ascii", "{\u00e9}".encode("utf-8"), "not JSON")):
            with self.subTest(case=name), self.assertRaises(_evidence.EvidenceError) as caught:
                _evidence.parse(variant)
            self.assertEqual(caught.exception.reason, reason)

    def test_the_record_shape_is_closed(self):
        base = records()["dev-macos-arm64"]
        cases = []
        for mutate, reason in ((lambda r: r.pop("rows"), "closed record"), (lambda r: r.update(extra=1), "closed record"),
                               (lambda r: r.update(schemaVersion="r12.meq-profile-evidence/v2"), "closed record"),
                               (lambda r: r.update(rows={}), "closed rows"), (lambda r: r["rows"].append("x"), "closed rows"),
                               (lambda r: r["rows"][0].pop("status"), "closed row"),
                               (lambda r: r["rows"][0].update(latencyMs=3), "closed row"),
                               (lambda r: r["rows"][0].update(detail=""), "detail"),
                               (lambda r: r["rows"][0].update(detail=7), "detail"),
                               (lambda r: r["rows"][0].update(detail="x" * 201), "detail"),
                               (lambda r: r["rows"][0].update(detail="two\nlines"), "detail")):
            record = copy.deepcopy(base)
            mutate(record)
            cases.append((record, reason))
        for index, (record, reason) in enumerate(cases):
            with self.subTest(case=index, reason=reason):
                self.refused(record, reason)
        self.refused([base], "closed record")

    def test_statuses_are_exactly_the_four(self):
        for status in _evidence.STATUSES:
            with self.subTest(status=status):
                _evidence.build_record("linux-amd64-cpu", statuses(status))
        for status in ("pass", "SKIPPED", "NOT_SERVED ", "", None, 1):
            with self.subTest(status=status):
                record = copy.deepcopy(records()["linux-amd64-cpu"])
                record["rows"][3]["status"] = status
                self.refused(record, "status")

    def test_row_ids_are_closed_once_each_and_in_order(self):
        base = records()["linux-amd64-cpu"]
        unknown = copy.deepcopy(base)
        unknown["rows"][0]["id"] = "latency"
        self.refused(unknown, "row id")
        for name, rows in (("missing", base["rows"][:-1]), ("duplicate", base["rows"] + base["rows"][-1:]),
                           ("swapped", [base["rows"][1], base["rows"][0]] + base["rows"][2:]), ("empty", [])):
            with self.subTest(case=name):
                record = copy.deepcopy(base)
                record["rows"] = copy.deepcopy(rows)
                self.refused(record, "rows (each row id once, in order)")
        incomplete = statuses("PASS")
        incomplete.pop("tunnel")
        with self.assertRaises(_evidence.EvidenceError):
            _evidence.build_record("dev-macos-arm64", incomplete)

    def test_a_pooled_record_is_refused(self):
        dev, cpu = records()["dev-macos-arm64"], records()["linux-amd64-cpu"]
        foreign_row = copy.deepcopy(dev)
        foreign_row["rows"][4] = copy.deepcopy(cpu["rows"][4])
        self.refused(foreign_row, "pooled (a row of another profile)")
        foreign_role = copy.deepcopy(dev)
        foreign_role["backendRole"] = cpu["backendRole"]
        self.refused(foreign_role, "pooled (backend role of another profile)")
        for profile_id in ("dev-macos-arm64,linux-amd64-cpu", "all", "", None):
            with self.subTest(profile=profile_id):
                record = copy.deepcopy(dev)
                record["profileId"] = profile_id
                self.refused(record, "profile id")
        with self.assertRaises(_evidence.EvidenceError) as caught:
            _evidence.validate_records([dev, cpu, copy.deepcopy(dev)])
        self.assertEqual(caught.exception.reason, "pooled (one record per profile id)")
        with self.assertRaises(_evidence.EvidenceError):
            _evidence.validate_records({"dev-macos-arm64": dev})

    def test_every_leak_class_is_refused(self):
        dot, colon, slash = ".", ":", "/"
        vectors = {
            "url": ["see http" + colon + slash * 2 + "engine" + dot + "example" + slash + "v1", "ws" + colon + slash * 2 + "x"],
            "localhost": ["served on local" + "host", "LOCAL" + "HOST answered"],
            "account": ["run by ops" + "@" + "lab", "user" + "@" + "engine"],
            "path": [slash.join(["", "home", "op", "log"]), slash.join(["", "Users", "op"]), "C" + colon + "\\" + "x"],
            "credential": ["Bear" + "er abc", "pass" + "word is x", "api" + "_key", "-----BEG" + "IN KEY", "Author" + "ization"],
            "address": [dot.join(["10", "1", "2", "3"]), dot.join(["127", "0", "0", "1"]), colon * 2 + "1",
                        "fe80" + colon * 2 + "1", "[fd00" + colon * 2 + "1]", "2001" + colon + "db8" + colon * 2 + "7"],
            "port": ["listener on " + colon + "11434", "port" + colon + "8080"],
            "host": ["engine" + dot + "example", "gpu-host" + dot + "internal", "api" + dot + "vendor" + dot + "com"],
        }
        key_like = ["sk" + "-" + "ab" * 10, "ghp" + "_" + "x1" * 10, "AK" + "IA" + "Q" * 16, "hf" + "_" + "z" * 12,
                    "a1b2" * 10]
        vectors["credential"] += key_like
        for kind, texts in vectors.items():
            for text in texts:
                with self.subTest(kind=kind, text_length=len(text)):
                    self.assertEqual(_evidence.leak_class(text), kind)
                    record = copy.deepcopy(records()["linux-amd64-cpu"])
                    record["rows"][5]["detail"] = text
                    self.refused(record, "leak (" + kind + ")")
                    with self.assertRaises(_evidence.EvidenceError):
                        _evidence.build_record("linux-amd64-cpu", statuses("FAIL"), {"tunnel": text})
        keyed = copy.deepcopy(records()["linux-amd64-cpu"])
        keyed["rows"][0][dot.join(["10", "0", "0", "9"])] = "x"
        with self.assertRaises(_evidence.EvidenceError):
            _evidence.validate_record(keyed)

    def test_benign_details_are_accepted(self):
        for text in ("The backend serves no embedding model.", "No GPU host is named.", "Truncated, not refused.",
                     "Context limit minus 256 tokens was accepted.", "Ollama 0.5 answered; e.g. one restart.",
                     "First byte within the latency plus 5 s."):
            with self.subTest(text=text):
                self.assertIsNone(_evidence.leak_class(text))
                _evidence.build_record("dev-macos-arm64", statuses("PASS"), {"cancellation": text})

    def test_the_module_imports_only_ipaddress_and_json(self):
        tree = ast.parse((HERE / "_evidence.py").read_text(encoding="utf-8"))
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imported, {"ipaddress", "json"})


if __name__ == "__main__":
    unittest.main()
