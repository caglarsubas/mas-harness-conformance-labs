from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness_conformance.canonical import canonical_bytes, load_json_bytes, require_canonical_document, secure_read
from harness_conformance.errors import ConformanceError
from harness_conformance.models import EVIDENCE_AXES, HANDLERS, RESULT_STATES
from harness_conformance.schema import validate_campaign, validate_environment

ROOT = Path(__file__).resolve().parents[2]


class CanonicalSchemaTests(unittest.TestCase):
    def test_closed_vocabularies(self) -> None:
        self.assertEqual(RESULT_STATES, ("PASS", "FAIL", "WARN", "NOT_APPLICABLE", "NOT_RUN_ENV_UNAVAILABLE"))
        self.assertEqual(len(EVIDENCE_AXES), 12)
        self.assertEqual(len(HANDLERS), 5)

    def test_duplicate_and_noncanonical_numbers_are_rejected(self) -> None:
        for data, reason in ((b'{"a":1,"a":2}', "DUPLICATE_JSON_MEMBER"), (b'{"a":1.5}', "NON_CANONICAL_NUMBER"), (b'{"a":NaN}', "NON_CANONICAL_NUMBER")):
            with self.subTest(reason=reason), self.assertRaises(ConformanceError) as raised:
                load_json_bytes(data)
            self.assertEqual(raised.exception.reason, reason)

    def test_canonical_bytes_are_stable(self) -> None:
        value = {"z": [True, None, 3], "a": "é"}
        self.assertEqual(canonical_bytes(value), b'{"a":"\xc3\xa9","z":[true,null,3]}')
        self.assertEqual(require_canonical_document(canonical_bytes(value)), value)

    def test_campaign_and_environment_are_closed(self) -> None:
        campaign = json.loads((ROOT / "campaigns/meta/campaign.json").read_text())
        environment = json.loads((ROOT / "fixtures/environments/meta-complete.json").read_text())
        validate_campaign(campaign)
        validate_environment(environment)
        campaign["remoteUrl"] = "forbidden"
        with self.assertRaises(ConformanceError) as raised:
            validate_campaign(campaign)
        self.assertEqual(raised.exception.reason, "UNKNOWN_FIELD")
        environment["apiKey"] = "forbidden"
        with self.assertRaises(ConformanceError) as raised:
            validate_environment(environment)
        self.assertIn(raised.exception.reason, {"UNKNOWN_FIELD", "SECRET_SHAPED_FIELD"})

    def test_secure_read_refuses_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(ConformanceError):
                secure_read(link)

    def test_every_published_schema_is_closed_and_valid_json(self) -> None:
        schemas = sorted((ROOT / "schemas").glob("**/*.json"))
        self.assertGreaterEqual(len(schemas), 10)
        for path in schemas:
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertIs(value["additionalProperties"], False, path)


if __name__ == "__main__":
    unittest.main()
