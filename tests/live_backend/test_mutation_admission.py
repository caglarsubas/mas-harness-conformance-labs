"""Offline data/state regressions; neither fixtures nor journals grant effects."""
from copy import deepcopy
import base64
import json
import unittest

from _fixtures import ROOT
from test_replay_store import MemoryJournal
from harness_conformance import live_mutation_admission as admission
from harness_conformance.canonical import byte_digest, canonical_bytes, canonical_digest
from harness_conformance.errors import ConformanceError

VECTORS = json.loads((ROOT / "fixtures/live-backend/proxy-vectors.json").read_bytes())
NOW = "2026-09-08T00:00:02Z"


def altered(value, path, replacement):
    result = deepcopy(value)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return result


def transcript_sample(index=0):
    value = deepcopy(VECTORS["broker"]["positive"][index])
    return value, admission.BrokerTranscript(value["binding"], value["request"])


def sender(frame):
    return "SERVER" if frame["kind"] in ("RESOURCE_RESULT", "CLEANUP_RECORDED", "ABORT") else "BROKER"


class ProxyAdmissionTests(unittest.TestCase):
    def test_approved_profile_and_all_30_adversarial_vectors(self):
        positive = VECTORS["proxy"]["positive"]
        self.assertEqual(admission.validate_profile(positive), positive)
        self.assertEqual(len(VECTORS["proxy"]["negative"]), 30)
        for row in VECTORS["proxy"]["negative"]:
            with self.subTest(vector=row["label"]), self.assertRaises((ConformanceError, ValueError)):
                admission.validate_profile(altered(positive, row["path"], row["value"]))

    def test_observer_positive_and_all_27_negative_vectors(self):
        sample = VECTORS["observation"]["positive"]
        args = {key: sample[key] for key in ("binding", "request", "observation", "now", "previous")}
        args["profile"] = VECTORS["proxy"]["positive"]
        self.assertEqual(admission.validate_messages(**args), sample["observation"])
        self.assertEqual(len(VECTORS["observation"]["negative"]), 27)
        for row in VECTORS["observation"]["negative"]:
            modified = deepcopy(args)
            if row["path"]:
                modified[row["document"]] = altered(modified[row["document"]], row["path"], row["value"])
            else:
                modified[row["document"]] = row["value"]
            with self.subTest(vector=row["label"]), self.assertRaises((ConformanceError, ValueError)):
                admission.validate_messages(**modified)

    def test_exact_builtin_canonical_bounds_and_duplicates(self):
        class Dictionary(dict):
            pass
        for value in (Dictionary(a=1), {"a": 1.0}, {"a": float("nan")}, {1: "key"},
                      {"a": 9007199254740992}, b'{"a":1,"a":2}', b'{ "a":1}', b'{}\n'):
            with self.subTest(value=str(value)), self.assertRaises((ConformanceError, ValueError)):
                admission.document(value)
        value = "end"
        for _ in range(18):
            value = [value]
        with self.assertRaises(ConformanceError):
            admission.document(value)

    def test_no_alias_to_caller_profile(self):
        source = deepcopy(VECTORS["proxy"]["positive"])
        result = admission.validate_profile(source)
        source["binding"]["tenantId"] = "changed"
        self.assertEqual(result, VECTORS["proxy"]["positive"])

    def test_zero_and_resource_profiles_have_exact_integer_reservation_units(self):
        for sample in VECTORS["qualification"]["positive"]:
            profile = admission.validate_profile(sample["profile"])
            units = admission.resource_units(profile)
            self.assertEqual(set(units), set(admission.UNITS))
            self.assertTrue(all(type(value) is int for value in units.values()))
            self.assertEqual(units["configMaps"], len(profile["resources"]))
            self.assertEqual(sum(units[k] for k in units if k != "configMaps"), 0)

    def test_postmutation_object_requires_exact_uid_version_and_signed_manifest(self):
        manifest = VECTORS["proxy"]["positive"]["resources"][0]["manifest"]
        actual = deepcopy(manifest)
        actual["metadata"].update(uid="created-uid", resourceVersion="17")
        self.assertEqual(admission.validate_observed_manifest(actual, manifest), ("created-uid", "17"))
        for path, value in ((["metadata", "uid"], "replacement"), (["metadata", "resourceVersion"], ""),
                            (["metadata", "namespace"], "foreign"), (["immutable"], False)):
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                admission.validate_observed_manifest(altered(actual, path, value), manifest, "created-uid")

    def test_remaining_unknown_uid_cannot_be_claimed_clean_or_deleted(self):
        resource = VECTORS["proxy"]["positive"]["resources"][0]
        metadata = resource["manifest"]["metadata"]
        remaining = {"apiVersion": "v1", "kind": "ConfigMap", "namespace": metadata["namespace"],
                     "name": metadata["name"], "uid": None, "manifestDigest": resource["manifestDigest"],
                     "reasonCode": "IO_AMBIGUOUS"}
        receipt = admission.cleanup_receipt(admission.ZERO, admission.CASES[0], NOW, [remaining])
        self.assertEqual(receipt["state"], "CLEANUP_PENDING")
        for change in ({"reasonCode": "DELETE_DENIED"}, {"uid": ""}, {"kind": "Namespace"}, {"extra": True}):
            with self.subTest(change=change), self.assertRaises(ConformanceError):
                admission.cleanup_receipt(admission.ZERO, admission.CASES[0], NOW, [{**remaining, **change}])
        with self.assertRaises(ConformanceError):
            admission.cleanup_receipt(admission.ZERO, admission.CASES[0], NOW, [remaining, remaining])

    def test_both_complete_broker_transcripts_are_non_authorizing_data(self):
        for index in range(2):
            sample, subject = transcript_sample(index)
            for frame in sample["frames"]:
                self.assertEqual(subject.accept(canonical_bytes(frame), sender(frame)), frame)
            self.assertEqual(json.loads(subject.receipt())["evidenceClass"], "DATA_CHECK_ONLY")
            with self.assertRaises(ConformanceError):
                subject.accept(sample["frames"][-1], "BROKER")

    def test_every_broker_binding_field_substitution_poisoned(self):
        for key in admission.BROKER_COMMON:
            sample, subject = transcript_sample()
            frame = deepcopy(sample["frames"][0])
            frame[key] = "sha256:" + "f" * 64 if key.endswith("Digest") else "wrong"
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                subject.accept(frame, "BROKER")
            self.assertTrue(subject.poisoned)
            with self.assertRaises(ConformanceError):
                subject.accept(sample["frames"][0], "BROKER")

    def test_returned_frames_do_not_alias_retained_actions_cleanup_or_terminal(self):
        sample, subject = transcript_sample(1)
        for frame in sample["frames"]:
            returned = subject.accept(frame, sender(frame))
            original = deepcopy(returned["payload"])
            returned["payload"].clear()
            if frame["kind"] == "RESOURCE_ACTION":
                self.assertEqual(subject.pending, original)
            elif frame["kind"] == "CLEANUP_RECORDED":
                self.assertEqual(subject.cleanup, original)
            elif frame["kind"] == "TERMINAL":
                self.assertEqual(subject.terminal, original)

    def test_each_frame_wrong_direction_and_replay_refused(self):
        original = VECTORS["broker"]["positive"][1]
        for index, frame in enumerate(original["frames"]):
            for fault in ("direction", "replay"):
                sample, subject = transcript_sample(1)
                for prior in sample["frames"][:index]:
                    subject.accept(prior, sender(prior))
                if fault == "replay":
                    subject.accept(frame, sender(frame))
                with self.subTest(index=index, fault=fault), self.assertRaises(ConformanceError):
                    subject.accept(frame, ("SERVER" if sender(frame) == "BROKER" else "BROKER")
                                   if fault == "direction" else sender(frame))

    def test_terminal_requires_actual_chunk_digest_size_cleanup_and_reaped(self):
        for key, value in (("receiptSize", 1), ("receiptDigest", admission.ZERO),
                           ("cleanupDigest", admission.ZERO), ("workerReaped", False)):
            sample, subject = transcript_sample()
            for frame in sample["frames"][:-1]:
                subject.accept(frame, sender(frame))
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                subject.accept(altered(sample["frames"][-1], ["payload", key], value), "BROKER")

    def test_receipt_not_exposed_before_terminal(self):
        sample, subject = transcript_sample()
        for frame in sample["frames"][:-1]:
            subject.accept(frame, sender(frame))
            with self.assertRaises(ConformanceError):
                subject.receipt()

    def test_noncanonical_or_oversize_base64_and_chunk_order(self):
        sample, _ = transcript_sample()
        for payload in ({"index": 1, "dataBase64": "YQ=="}, {"index": 0, "dataBase64": "YR=="},
                        {"index": 0, "dataBase64": "YQ==\n"}, {"index": 0, "dataBase64": ""},
                        {"index": 0, "dataBase64": base64.b64encode(b"x" * 24577).decode()}):
            subject = admission.BrokerTranscript(sample["binding"], sample["request"])
            subject.accept(sample["frames"][0], "BROKER")
            with self.subTest(payload_size=len(payload["dataBase64"])), self.assertRaises(ConformanceError):
                subject.accept({**sample["frames"][1], "payload": payload}, "BROKER")

    def test_binding_requires_disjoint_complete_case_resource_ownership(self):
        sample = VECTORS["broker"]["positive"][1]
        for fault in (None, "duplicate", "missing", "unlisted", "wrong-profile"):
            binding = deepcopy(sample["binding"])
            if fault == "duplicate":
                binding["caseResourceDigests"][admission.CASES[1]] = binding["caseResourceDigests"][admission.CASES[0]]
            elif fault == "missing":
                binding["caseResourceDigests"][admission.CASES[0]] = []
            elif fault == "unlisted":
                binding["caseResourceDigests"][admission.CASES[1]] = [admission.ZERO]
            elif fault:
                binding["profileDigest"] = admission.ZERO
            raw = canonical_bytes(binding)
            tree = [{"path": admission.BROKER_BINDING_PATH, "mode": "0444", "size": len(raw), "sha256": byte_digest(raw)}]
            args = (sample["profile"], sample["observationBinding"], {"tree": tree}, {admission.BROKER_BINDING_PATH: raw})
            if fault is None:
                self.assertEqual(admission.retained_broker_binding(*args), binding)
            else:
                with self.subTest(fault=fault), self.assertRaises(ConformanceError):
                    admission.retained_broker_binding(*args)


class ProxyReservationTests(unittest.TestCase):
    def setUp(self):
        self.io = MemoryJournal()
        self.subject = admission._AdmissionLog(self.io)
        self.binding = {key: "sha256:" + "a" * 64 if key.endswith("Digest") else "unit-" + key.lower()
                        for key in admission.BINDING_FIELDS}

    def test_whole_run_reservation_is_durable_before_return(self):
        self.subject.record(self.binding, "RESERVED", None, NOW)
        self.assertEqual(self.io.events, ["lock", "read", "append", "fsync", "read", "unlock"])
        self.assertEqual(admission.parse_reservations(self.io.raw)[2], 1)

    def test_each_ambiguous_write_sync_or_readback_poisoned_without_retry(self):
        for fault in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.io.fail = fault
            with self.subTest(fault=fault), self.assertRaises((ConformanceError, OSError)):
                self.subject.record(self.binding, "RESERVED", None, NOW)
            self.assertTrue(self.subject.poisoned)
            events = list(self.io.events)
            with self.assertRaises(ConformanceError):
                self.subject.record(self.binding, "RESERVED", None, NOW)
            self.assertEqual(self.io.events, events)

    def test_other_run_capacity_held_until_all_ten_distinct_clean_operations(self):
        self.subject.record(self.binding, "RESERVED", None, NOW)
        other = {**self.binding, "runNonce": "other-run"}
        previous = admission.ZERO
        for case in admission.CASES:
            with self.assertRaises(ConformanceError):
                self.subject.record(other, "RESERVED", None, NOW)
            self.subject.record(self.binding, "RUNNING", case, NOW)
            receipt = admission.cleanup_receipt(canonical_digest(self.binding), case, NOW, [], previous)
            self.subject.record(self.binding, "RECORDED", case, NOW, receipt)
            previous = canonical_digest(receipt)
        self.subject.record(other, "RESERVED", None, NOW)
        with self.assertRaises(ConformanceError):
            self.subject.record(self.binding, "RESERVED", None, NOW)

    def test_concurrent_journal_owner_never_writes(self):
        with self.io.transaction(), self.assertRaises(ConformanceError):
            self.subject.record(self.binding, "RESERVED", None, NOW)
        self.assertEqual(self.io.raw, b"")

    def test_history_corruption_torn_tail_and_foreign_binding_do_not_repair(self):
        self.subject.record(self.binding, "RESERVED", None, NOW)
        original = self.io.raw
        for raw in (original[:-1], original + b"torn", original + original, original.replace(b"RESERVED", b"CLEAN")):
            with self.subTest(raw=raw[-20:]), self.assertRaises(ConformanceError):
                admission.parse_reservations(raw)
        with self.assertRaises(ConformanceError):
            self.subject.record({**self.binding, "environmentId": "other"}, "RUNNING", admission.CASES[0], NOW)
        self.assertEqual(self.io.raw, original)
