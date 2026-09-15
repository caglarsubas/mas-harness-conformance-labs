"""Offline data/state regressions; neither fixtures nor journals grant effects."""
from copy import deepcopy
from datetime import datetime, timezone
import base64
import json
import re
import unittest
from time import perf_counter as _wall_clock
from unittest.mock import patch

from _fixtures import ROOT
from test_replay_store import MemoryJournal
from harness_conformance import live_mutation_admission as admission
from harness_conformance.canonical import byte_digest, canonical_bytes, canonical_digest
from harness_conformance.errors import ConformanceError

VECTORS = json.loads((ROOT / "fixtures/live-backend/proxy-vectors.json").read_bytes())


def setUpModule():
    # Diagnostic only: do not intercept TestCase.run, discovery or any guard.
    global _module_started
    _module_started = _wall_clock()


def tearDownModule():
    print(f"CONF-LIVE-003 module-timing module={__name__} "
          f"elapsedSeconds={_wall_clock() - _module_started:.6f} evidenceClass=DIAGNOSTIC_ONLY", flush=True)
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


class ResourceJournalTests(unittest.TestCase):
    """Real journal algorithms, explicitly in-memory storage; no API effects."""
    def setUp(self):
        sample = deepcopy(VECTORS["broker"]["positive"][1])
        self.profile, self.broker_binding = sample["profile"], sample["binding"]
        self.operation = admission.CASES[0]
        self.binding = {k: admission.ZERO if k.endswith("Digest") else self.profile["binding"][k]
                        for k in admission.BINDING_FIELDS}
        self.binding["profileDigest"] = canonical_digest(self.profile)
        self.action = {"actionId": 1, "verb": "CREATE",
                       "manifestDigest": self.profile["resources"][0]["manifestDigest"]}
        self.observed = deepcopy(self.profile["resources"][0]["manifest"])
        self.observed["metadata"].update(uid="unit-created-uid", resourceVersion="17")
        self.io = MemoryJournal()
        self.log = admission._AdmissionLog(self.io)
        self.log.record(self.binding, "RESERVED", None, NOW)
        self.log.record(self.binding, "RUNNING", self.operation, NOW)
        self.initial = self.io.raw
        self.io.events.clear()

    def record(self, state="CREATE_INTENT", **changes):
        args = dict(binding=self.binding, state=state, operation=self.operation, now=NOW,
                    profile=self.profile, broker_binding=self.broker_binding, action=self.action,
                    expected_history=self.io.raw, observed=self.observed if state == "CREATED" else None)
        args.update(changes)
        return self.log.record_resource(**args)

    def state(self):
        return admission.parse_reservations(self.io.raw)[0][(self.binding["tenantId"], self.binding["runNonce"])]

    def resource(self):
        return next(iter(self.state()["resources"].values()))

    def raw_row(self, state, resource, **changes):
        rows = self.io.raw.splitlines()
        row = dict(sequence=len(rows) + 1, previousDigest=canonical_digest(json.loads(rows[-1])),
                   binding=self.binding, state=state, operation=self.operation, observedAt=NOW,
                   cleanup=None, resource=resource)
        row.update(changes)
        return self.io.raw + canonical_bytes(row) + b"\n"

    def payload(self):
        return {k: v for k, v in self.resource().items() if k not in ("operation", "state")}

    def pending(self, reason="IO_AMBIGUOUS"):
        fields = ("apiVersion", "kind", "namespace", "name", "uid", "manifestDigest")
        remaining = [{**{k: self.resource()[k] for k in fields}, "reasonCode": reason}]
        return admission.cleanup_receipt(canonical_digest(self.binding), self.operation, NOW, remaining)

    def test_intent_fsync_readback_before_return_and_null_identity(self):
        digest = self.record()
        self.assertEqual(self.io.events, ["lock", "read", "append", "fsync", "read", "unlock"])
        self.assertEqual(digest, canonical_digest(json.loads(self.io.raw.splitlines()[-1])))
        self.assertEqual(self.resource()["state"], "CREATE_INTENT")
        self.assertIsNone(self.resource()["uid"])
        self.assertIsNone(self.resource()["resourceVersion"])
        self.assertTrue(self.state()["held"])

    def test_observed_uid_version_persist_only_after_validated_intent(self):
        self.record()
        self.io.events.clear()
        self.record("CREATED")
        self.assertEqual(self.io.events, ["lock", "read", "append", "fsync", "read", "unlock"])
        self.assertEqual((self.resource()["uid"], self.resource()["resourceVersion"]), ("unit-created-uid", "17"))
        self.assertEqual(self.resource()["state"], "CREATED")
        self.assertTrue(self.state()["held"])
        self.assertEqual(self.state()["current"], self.operation)

    def test_returned_state_is_detached_and_restart_does_not_adopt(self):
        self.record()
        detached = self.state()
        next(iter(detached["resources"].values()))["uid"] = "invented"
        self.assertIsNone(self.resource()["uid"])
        self.log = admission._AdmissionLog(self.io)
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.record()
        self.assertEqual(self.io.raw, before)
        self.assertTrue(self.state()["held"])

    def test_intent_write_sync_readback_faults_poison_and_never_retry(self):
        for fault in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.io.fail = fault
            with self.subTest(fault=fault), self.assertRaises((OSError, ConformanceError)):
                self.record()
            self.assertTrue(self.log.poisoned)
            events = list(self.io.events)
            with self.assertRaises(ConformanceError):
                self.record()
            with self.assertRaises(ConformanceError):
                self.log.record(self.binding, "RUNNING", admission.CASES[1], NOW)
            self.assertEqual(self.io.events, events)

    def test_created_write_faults_preserve_intent_without_retry(self):
        for fault in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.record()
            intent = self.io.raw
            self.io.fail = fault
            with self.subTest(fault=fault), self.assertRaises((OSError, ConformanceError)):
                self.record("CREATED")
            self.assertTrue(self.log.poisoned)
            self.assertTrue(self.io.raw.startswith(intent))
            events = list(self.io.events)
            with self.assertRaises(ConformanceError):
                self.record("CREATED")
            self.assertEqual(events, self.io.events)

    def test_transaction_exit_failure_is_ambiguous_even_after_readback(self):
        from contextlib import contextmanager
        original = self.io.transaction
        @contextmanager
        def ambiguous_exit():
            with original() as io:
                yield io
            raise OSError("unit unlock ambiguity")
        self.io.transaction = ambiguous_exit
        with self.assertRaises(OSError):
            self.record()
        self.assertTrue(self.log.poisoned)
        self.assertEqual(self.resource()["state"], "CREATE_INTENT")

    def test_requires_existing_exact_running_reservation(self):
        for raw in (b"", self.initial.splitlines(keepends=True)[0]):
            self.io.raw = raw
            with self.subTest(raw=raw[:16]), self.assertRaises(ConformanceError):
                self.record()
            self.assertEqual(self.io.raw, raw)

    def test_wrong_active_case_and_foreign_case_ownership_rejected(self):
        with self.assertRaises(ConformanceError):
            self.record(operation=admission.CASES[1])
        self.broker_binding["caseResourceDigests"][admission.CASES[1]] = self.broker_binding["caseResourceDigests"][self.operation]
        self.broker_binding["caseResourceDigests"][self.operation] = []
        with self.assertRaises(ConformanceError):
            self.record(operation=admission.CASES[1])
        self.assertEqual(self.io.raw, self.initial)

    def test_all_reservation_binding_substitutions_refused(self):
        for key in self.binding:
            value = "sha256:" + "f" * 64 if key.endswith("Digest") else "foreign"
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                self.record(binding={**self.binding, key: value})
        self.assertEqual(self.io.raw, self.initial)

    def test_invalid_or_substituted_profile_cannot_write(self):
        for profile in ({}, {**self.profile, "profileId": "unknown"},
                        altered(self.profile, ["resources", 0, "manifest", "data", "fixture.json"], "changed")):
            with self.subTest(profile=profile.get("profileId")), self.assertRaises(ConformanceError):
                self.record(profile=profile)
        self.assertEqual(self.io.raw, self.initial)

    def test_broker_binding_requires_exact_disjoint_complete_resource_sets(self):
        for fault in ("missing", "duplicate", "profile"):
            binding = deepcopy(self.broker_binding)
            if fault == "missing":
                binding["caseResourceDigests"][self.operation] = []
            elif fault == "duplicate":
                binding["caseResourceDigests"][admission.CASES[1]] = [self.action["manifestDigest"]]
            else:
                binding["profileDigest"] = admission.ZERO
            with self.subTest(fault=fault), self.assertRaises(ConformanceError):
                self.record(broker_binding=binding)
        self.assertEqual(self.io.raw, self.initial)

    def test_unknown_manifest_digest_refused_without_storage_write(self):
        with self.assertRaises(ConformanceError):
            self.record(action={**self.action, "manifestDigest": admission.ZERO})
        self.assertNotIn("append", self.io.events)

    def test_action_is_closed_create_only_and_bounded_exact_integer(self):
        actions = [{**self.action, "verb": value} for value in ("GET", "DELETE", "PATCH", None)]
        actions += [{**self.action, "actionId": value} for value in (True, 0, 257, "1", 1.0)]
        actions += [{**self.action, "url": "https://unit.invalid"}]
        for action in actions:
            with self.subTest(action=action), self.assertRaises(ConformanceError):
                self.record(action=action)
        self.assertEqual(self.io.raw, self.initial)

    def test_observed_object_is_required_only_for_created(self):
        for state, observed in (("CREATE_INTENT", self.observed), ("CREATED", None), ("UNKNOWN", None)):
            with self.subTest(state=state), self.assertRaises(ConformanceError):
                self.record(state, observed=observed)
        self.assertEqual(self.io.events, [])

    def test_stale_history_and_nonbytes_history_never_append(self):
        self.record()
        before = self.io.raw
        self.io.events.clear()
        for history in (self.initial, b"", bytearray(before), before.decode(), b"x" * 4194305):
            with self.subTest(kind=type(history).__name__), self.assertRaises(ConformanceError):
                self.record("CREATED", expected_history=history)
        self.assertNotIn("append", self.io.events)
        self.assertEqual(self.io.raw, before)

    def test_concurrent_owner_cannot_append_intent(self):
        with self.io.transaction(), self.assertRaises(ConformanceError):
            self.record()
        self.assertEqual(self.io.raw, self.initial)

    def test_second_create_cannot_reuse_name_even_with_new_action_id(self):
        self.record()
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.record(action={**self.action, "actionId": 2})
        self.assertEqual(self.io.raw, before)

    def test_created_without_intent_cannot_adopt_existing_object(self):
        with self.assertRaises(ConformanceError):
            self.record("CREATED")
        self.assertEqual(self.io.raw, self.initial)

    def test_created_identity_cannot_be_overwritten_or_recorded_twice(self):
        self.record()
        self.record("CREATED")
        before = self.io.raw
        for uid in ("unit-created-uid", "replacement-uid"):
            observed = altered(self.observed, ["metadata", "uid"], uid)
            with self.subTest(uid=uid), self.assertRaises(ConformanceError):
                self.record("CREATED", observed=observed)
        self.assertEqual(self.io.raw, before)

    def test_post_defaulting_substitution_and_missing_identity_preserve_null_intent(self):
        self.record()
        before = self.io.raw
        for path, value in ((["kind"], "Pod"), (["metadata", "name"], "foreign"),
                            (["metadata", "namespace"], "foreign"),
                            (["metadata", "labels", "planeon.ai/tenant-id"], "foreign"),
                            (["metadata", "uid"], ""), (["metadata", "resourceVersion"], ""),
                            (["data", "fixture.json"], "changed")):
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                self.record("CREATED", observed=altered(self.observed, path, value))
        self.assertEqual(self.io.raw, before)
        self.assertIsNone(self.resource()["uid"])

    def test_created_must_match_original_action_id(self):
        self.record()
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.record("CREATED", action={**self.action, "actionId": 2})
        self.assertEqual(self.io.raw, before)

    def test_parser_refuses_intent_with_guessed_uid_or_resource_version(self):
        self.record()
        payload = self.payload()
        self.io.raw = self.initial
        for key, value in (("uid", "guessed"), ("resourceVersion", "1")):
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                admission.parse_reservations(self.raw_row("CREATE_INTENT", {**payload, key: value}))

    def test_parser_validates_created_uid_and_version_not_just_writer(self):
        self.record()
        payload = {**self.payload(), "uid": "unit-created-uid", "resourceVersion": "17"}
        for key, value in (("uid", None), ("uid", "x/y"), ("uid", "x" * 129),
                           ("resourceVersion", None), ("resourceVersion", 17), ("resourceVersion", "x" * 129)):
            with self.subTest(key=key, value=value), self.assertRaises(ConformanceError):
                admission.parse_reservations(self.raw_row("CREATED", {**payload, key: value}))

    def test_parser_rejects_unknown_fields_noncanonical_torn_and_nondict_rows(self):
        self.record()
        payload = self.payload()
        self.io.raw = self.initial
        variants = [self.raw_row("CREATE_INTENT", {**payload, "delete": True}),
                    self.raw_row("CREATE_INTENT", payload, arbitrary=True),
                    self.raw_row("UNKNOWN", payload), self.raw_row("RUNNING", payload),
                    self.raw_row("CREATE_INTENT", payload)[:-1],
                    self.initial + b"[]\n", self.initial + b"null\n",
                    self.raw_row("CREATE_INTENT", payload).replace(b'"actionId":1', b'"actionId": 1')]
        for raw in variants:
            with self.subTest(tail=raw[-20:]), self.assertRaises(ConformanceError):
                admission.parse_reservations(raw)

    def test_parser_rejects_cross_binding_time_chain_scope_and_nonnull_cleanup(self):
        self.record()
        payload = self.payload()
        self.io.raw = self.initial
        for changes in ({"binding": {**self.binding, "runNonce": "foreign"}}, {"observedAt": "2026-09-07T00:00:00Z"},
                        {"sequence": 1}, {"previousDigest": admission.ZERO}, {"cleanup": {}},
                        {"operation": admission.CASES[1]}):
            with self.subTest(changes=changes), self.assertRaises(ConformanceError):
                admission.parse_reservations(self.raw_row("CREATE_INTENT", payload, **changes))

    def test_parser_bounds_total_resources_and_prevents_action_or_manifest_reuse(self):
        self.record()
        self.record("CREATED")
        payload = self.payload()
        for action in range(2, 33):
            row = {**payload, "actionId": action, "name": "unit-" + str(action),
                   "manifestDigest": "sha256:" + format(action, "064x"), "uid": None, "resourceVersion": None}
            self.io.raw = self.raw_row("CREATE_INTENT", row)
            self.io.raw = self.raw_row("CREATED", {**row, "uid": "uid-" + str(action), "resourceVersion": "1"})
        self.assertEqual(len(self.state()["resources"]), 32)
        with self.assertRaises(ConformanceError):
            admission.parse_reservations(self.raw_row("CREATE_INTENT", {**payload, "actionId": 33,
                "name": "unit-33", "manifestDigest": "sha256:" + format(33, "064x"),
                "uid": None, "resourceVersion": None}))
        self.io.raw = self.initial
        self.record()
        self.record("CREATED")
        payload = {**payload, "uid": None, "resourceVersion": None}
        for row in ({**payload, "name": "different", "manifestDigest": admission.ZERO},
                    {**payload, "actionId": 2, "name": "different"}):
            with self.subTest(row=row), self.assertRaises(ConformanceError):
                admission.parse_reservations(self.raw_row("CREATE_INTENT", row))

    def test_parser_refuses_uid_reuse_between_distinct_created_resources(self):
        self.record()
        self.record("CREATED")
        second = {**self.payload(), "name": "second", "actionId": 2,
                  "manifestDigest": admission.ZERO, "uid": None, "resourceVersion": None}
        self.io.raw = self.raw_row("CREATE_INTENT", second)
        with self.assertRaises(ConformanceError):
            admission.parse_reservations(self.raw_row("CREATED", {**second, "uid": "unit-created-uid", "resourceVersion": "18"}))

    def test_clean_receipt_cannot_erase_unresolved_intent_or_created_uid(self):
        self.record()
        for state in ("CREATE_INTENT", "CREATED"):
            if state == "CREATED":
                self.record(state)
            before = self.io.raw
            receipt = admission.cleanup_receipt(canonical_digest(self.binding), self.operation, NOW, [])
            with self.subTest(state=state), self.assertRaises(ConformanceError):
                self.log.record(self.binding, "RECORDED", self.operation, NOW, receipt)
            self.assertEqual(self.io.raw, before)
            self.assertTrue(self.state()["held"])

    def test_lost_response_pending_receipt_retains_exact_name_and_null_uid(self):
        self.record()
        receipt = self.pending()
        self.log.record(self.binding, "RECORDED", self.operation, NOW, receipt)
        self.assertEqual(self.state()["cleanupDigest"], canonical_digest(receipt))
        self.assertTrue(self.state()["held"])
        self.assertIsNone(self.resource()["uid"])
        self.assertEqual(receipt["state"], "CLEANUP_PENDING")

    def test_known_uid_pending_receipt_retains_version_and_capacity(self):
        self.record()
        self.record("CREATED")
        receipt = self.pending("DELETE_DENIED")
        self.log.record(self.binding, "RECORDED", self.operation, NOW, receipt)
        self.assertEqual(self.resource()["resourceVersion"], "17")
        self.assertTrue(self.state()["held"])
        self.assertEqual(self.state()["current"], self.operation)

    def test_cleanup_cannot_omit_substitute_or_invent_owned_resources(self):
        self.record()
        self.record("CREATED")
        remaining = self.pending("DELETE_DENIED")["remainingResources"]
        for changed in ([], [{**remaining[0], "uid": "foreign"}], [{**remaining[0], "name": "foreign"}],
                        [{**remaining[0], "manifestDigest": admission.ZERO}],
                        remaining + [{**remaining[0], "name": "extra"}]):
            receipt = admission.cleanup_receipt(canonical_digest(self.binding), self.operation, NOW, changed)
            with self.subTest(changed=changed), self.assertRaises(ConformanceError):
                self.log.record(self.binding, "RECORDED", self.operation, NOW, receipt)
        self.assertTrue(self.state()["held"])

    def test_no_resource_rows_after_cleanup_record_even_if_pending(self):
        self.record()
        self.log.record(self.binding, "RECORDED", self.operation, NOW, self.pending())
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.record("CREATED")
        with self.assertRaises(ConformanceError):
            self.record(action={**self.action, "actionId": 2})
        self.assertEqual(self.io.raw, before)

    def test_unresolved_resources_block_other_case_and_other_run(self):
        self.record()
        for binding, state, operation in ((self.binding, "RUNNING", admission.CASES[1]),
                                         ({**self.binding, "runNonce": "other"}, "RESERVED", None)):
            with self.subTest(state=state), self.assertRaises(ConformanceError):
                self.log.record(binding, state, operation, NOW)
        self.assertTrue(self.state()["held"])

    def test_input_mutation_after_commit_cannot_rewrite_durable_identity(self):
        self.record()
        self.record("CREATED")
        before = self.io.raw
        self.observed["metadata"]["uid"] = "replacement"
        self.action["actionId"] = 17
        self.profile["resources"][0]["manifest"]["metadata"]["name"] = "foreign"
        self.assertEqual(self.io.raw, before)
        self.assertEqual(self.resource()["uid"], "unit-created-uid")
        self.assertEqual(self.resource()["actionId"], 1)

    def test_zero_resource_profile_cannot_create_an_intent(self):
        sample = VECTORS["broker"]["positive"][0]
        binding = {**self.binding, "profileDigest": canonical_digest(sample["profile"])}
        with self.assertRaises(ConformanceError):
            self.record(binding=binding, profile=sample["profile"], broker_binding=sample["binding"])
        self.assertEqual(self.io.events, [])

    def test_unresolved_intent_blocks_another_create_not_just_name_reuse(self):
        self.record()
        second = {**self.payload(), "name": "second", "actionId": 2, "manifestDigest": admission.ZERO}
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_CREATE_REPLAY"):
            admission.parse_reservations(self.raw_row("CREATE_INTENT", second))
        self.assertIsNone(self.resource()["uid"])

    def test_replayed_resource_scope_is_closed_and_bounded(self):
        self.record()
        payload = self.payload()
        self.io.raw = self.initial
        for key, value in (("actionId", True), ("actionId", 0), ("actionId", 257),
                           ("apiVersion", "apps/v1"), ("kind", "PersistentVolumeClaim"),
                           ("namespace", "../foreign"), ("name", "x" * 64), ("manifestDigest", "latest")):
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                admission.parse_reservations(self.raw_row("CREATE_INTENT", {**payload, key: value}))


class FailureJournalTests(unittest.TestCase):
    """Fail-only data accounting; these records authenticate no execution."""
    setUp = ResourceJournalTests.setUp
    record = ResourceJournalTests.record
    state = ResourceJournalTests.state
    resource = ResourceJournalTests.resource

    def fail_record(self, reason="OBSERVATION_UNAVAILABLE"):
        return self.log.record_failure(self.binding, self.operation, NOW, reason,
                                       expected_history=self.log._verified_history)

    def last(self):
        return json.loads(self.io.raw.splitlines()[-1])

    def test_failed_zero_resource_case_is_held_without_fake_cleanup(self):
        self.fail_record()
        self.assertEqual(self.last()["state"], "FAILURE_RECORDED")
        self.assertIsNone(self.last()["cleanup"])
        self.assertTrue(self.log.poisoned)
        self.assertTrue(self.state()["held"])
        self.assertEqual(self.state()["current"], self.operation)
        self.assertNotIn("terminalCases", self.state())
        self.assertEqual(self.io.events, ["lock", "read", "append", "fsync", "read", "unlock"])

    def test_lost_create_response_retains_exact_name_null_uid_and_ambiguity(self):
        self.record()
        original = deepcopy(self.resource())
        self.fail_record("DEADLINE")
        receipt = self.last()["cleanup"]
        self.assertEqual(receipt["state"], "CLEANUP_PENDING")
        row = receipt["remainingResources"][0]
        self.assertIsNone(row["uid"])
        self.assertEqual(row["reasonCode"], "IO_AMBIGUOUS")
        self.assertEqual(row["name"], original["name"])
        self.assertEqual(self.resource(), original)
        self.assertTrue(self.state()["held"])

    def test_known_uid_preserved_for_each_closed_failure_reason(self):
        for reason in ("DELETE_DENIED", "UID_CHANGED", "DEADLINE", "IO_AMBIGUOUS", "OBSERVATION_UNAVAILABLE"):
            self.setUp()
            self.record()
            self.record("CREATED")
            original = deepcopy(self.resource())
            with self.subTest(reason=reason):
                self.fail_record(reason)
                row = self.last()["cleanup"]["remainingResources"][0]
                self.assertEqual(row["uid"], original["uid"])
                self.assertEqual(row["reasonCode"], reason)
                self.assertEqual(self.resource(), original)

    def test_execution_poison_can_only_append_failure_not_restore_work(self):
        self.record()
        before = self.io.raw
        self.log.poisoned = True
        self.fail_record()
        self.assertTrue(self.io.raw.startswith(before))
        self.assertTrue(self.log.poisoned)
        self.assertFalse(self.log._storage_ambiguous)
        with self.assertRaises(ConformanceError):
            self.log.record(self.binding, "RUNNING", admission.CASES[1], NOW)

    def test_every_prior_write_ambiguity_forbids_a_failure_append(self):
        for kind in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.io.fail = kind
            with self.subTest(kind=kind), self.assertRaises((ConformanceError, OSError)):
                self.record()
            self.assertTrue(self.log._storage_ambiguous)
            before = self.io.raw
            self.io.fail = None
            self.io.events.clear()
            with self.assertRaisesRegex(ConformanceError, "ADMISSION_FAILURE_UNAVAILABLE"):
                self.fail_record()
            self.assertEqual(self.io.raw, before)
            self.assertEqual(self.io.events, [])

    def test_failure_append_ambiguity_is_sticky_and_never_retried(self):
        for kind in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.record()
            self.io.fail = kind
            with self.subTest(kind=kind), self.assertRaises((ConformanceError, OSError)):
                self.fail_record()
            self.assertTrue(self.log.poisoned and self.log._storage_ambiguous)
            before = self.io.raw
            self.io.fail = None
            with self.assertRaises(ConformanceError):
                self.fail_record()
            self.assertEqual(self.io.raw, before)

    def test_reopened_data_log_cannot_adopt_history_for_failure_writes(self):
        self.record()
        reopened = admission._AdmissionLog(self.io)
        self.io.events.clear()
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_FAILURE_UNAVAILABLE"):
            reopened.record_failure(self.binding, self.operation, NOW, "IO_AMBIGUOUS", expected_history=self.io.raw)
        self.assertEqual(self.io.events, [])

    def test_valid_foreign_append_is_not_adopted_as_verified_history(self):
        other = admission._AdmissionLog(self.io)
        other.record_resource(self.binding, "CREATE_INTENT", self.operation, NOW,
            self.profile, self.broker_binding, self.action, expected_history=self.io.raw)
        before = self.io.raw
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_FAILURE_HISTORY_CHANGED"):
            self.fail_record()
        self.assertEqual(self.io.raw, before)
        self.assertTrue(self.log.poisoned)

    def test_failure_input_cannot_insert_error_text_url_or_extra_fields(self):
        for reason in (None, True, {}, "https://unit.invalid/secret", "arbitrary-error"):
            self.setUp()
            before = self.io.raw
            with self.subTest(reason=type(reason).__name__), self.assertRaises(ConformanceError):
                self.fail_record(reason)
            self.assertEqual(self.io.raw, before)

    def test_failure_scope_cannot_be_reassigned(self):
        for key in admission.BINDING_FIELDS:
            self.setUp()
            changed = {**self.binding, key: admission.ZERO if key.endswith("Digest") else "foreign"}
            if changed == self.binding:
                changed[key] = "sha256:" + "f" * 64
            before = self.io.raw
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                self.log.record_failure(changed, self.operation, NOW, "IO_AMBIGUOUS", expected_history=before)
            self.assertEqual(self.io.raw, before)

    def test_failure_replay_and_every_resume_transition_are_refused(self):
        self.record()
        self.fail_record()
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.fail_record()
        previous = canonical_digest(self.last())
        for state in ("RUNNING", "CREATED", "ABSENT", "CLEANUP_SEALED", "TERMINAL_RECORDED", "RECORDED", "FAILURE_RECORDED"):
            row = {**self.last(), "sequence": len(before.splitlines()) + 1, "previousDigest": previous, "state": state}
            with self.subTest(state=state), self.assertRaises(ConformanceError):
                admission.parse_reservations(before + canonical_bytes(row) + b'\n')
        self.assertEqual(self.io.raw, before)

    def test_failure_cleanup_cannot_omit_pending_resource_or_change_uid(self):
        self.record()
        self.record("CREATED")
        before = self.io.raw
        self.fail_record()
        for edit in ("empty", "uid", "reason"):
            row = self.last()
            if edit == "empty":
                row["cleanup"] = None
            else:
                row["cleanup"]["remainingResources"][0]["uid" if edit == "uid" else "reasonCode"] = (
                    "foreign-uid" if edit == "uid" else "DEADLINE")
            with self.subTest(edit=edit), self.assertRaisesRegex(ConformanceError, "ADMISSION_FAILURE_CLEANUP_CHANGED"):
                admission.parse_reservations(before + canonical_bytes(row) + b'\n')

    def test_lost_terminal_keeps_seal_and_adds_no_fabricated_terminal(self):
        CompletionJournalTests.setUp(self)
        CompletionJournalTests.seal(self)
        sealed = self.io.raw
        self.log.record_failure(self.binding, self.case, NOW, "IO_AMBIGUOUS", expected_history=sealed)
        current = CompletionJournalTests.state(self)
        self.assertTrue(self.io.raw.startswith(sealed))
        self.assertIn("pendingCompletion", current)
        self.assertNotIn("terminalCases", current)
        self.assertTrue(current["held"])
        with self.assertRaises(ConformanceError):
            CompletionJournalTests.finish(self)

    def prepare(self, *args, **kwargs):
        return CompletionJournalTests.prepare(self, *args, **kwargs)

    def test_terminal_completed_case_cannot_be_relabelled_as_active_failure(self):
        CompletionJournalTests.setUp(self)
        CompletionJournalTests.seal(self)
        CompletionJournalTests.finish(self)
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.log.record_failure(self.binding, self.case, NOW, "DEADLINE", expected_history=before)
        self.assertEqual(self.io.raw, before)


class CompletionJournalTests(unittest.TestCase):
    """Real journal replay/fsync algorithm; terminal frames here are data only."""
    def setUp(self):
        self.io = MemoryJournal()
        self.log = admission._AdmissionLog(self.io)
        self.binding = {key: "sha256:" + "a" * 64 if key.endswith("Digest") else "unit-" + key.lower()
                        for key in admission.BINDING_FIELDS}
        self.log.record(self.binding, "RESERVED", None, NOW)
        self.case = admission.CASES[0]
        self.log.record(self.binding, "RUNNING", self.case, NOW)
        self.prepare()

    def state(self):
        return admission.parse_reservations(self.io.raw)[0][(self.binding["tenantId"], self.binding["runNonce"])]

    def prepare(self, status="PASS", remaining=None):
        dispatch = deepcopy(VECTORS["broker"]["positive"][0]["request"])
        dispatch.update(reservationDigest=canonical_digest(self.binding), runNonce=self.binding["runNonce"], caseId=self.case)
        self.proof = {"dispatch": dispatch, "executionId": "c" * 64, "receiptDigest": canonical_digest({"unit": status}),
            "receiptSize": 32, "receiptStatus": status, "failedAction": False,
            "cleanupSequence": 3, "cleanupPreviousDigest": "sha256:" + "d" * 64}
        self.cleanup = admission.cleanup_receipt(canonical_digest(self.binding), self.case, NOW,
            [] if remaining is None else remaining, self.state()["cleanupDigest"])
        self.cleanup_frame = {"schemaVersion": "planeon.internal.broker-frame/v1",
            **{k: dispatch[k] for k in admission.BROKER_COMMON}, "executionId": self.proof["executionId"],
            "sequence": 3, "previousDigest": self.proof["cleanupPreviousDigest"], "kind": "CLEANUP_RECORDED",
            "payload": {"cleanupDigest": canonical_digest(self.cleanup), "state": self.cleanup["state"],
                        "remainingResources": self.cleanup["remainingResources"]}}
        self.terminal = {**self.cleanup_frame, "sequence": 4, "previousDigest": canonical_digest(self.cleanup_frame),
            "kind": "TERMINAL", "payload": {"status": {"PASS": "COMPLETED", "FAIL": "FAILED",
                "NOT_RUN_ENV_UNAVAILABLE": "UNAVAILABLE"}[status], "receiptSize": self.proof["receiptSize"],
                "receiptDigest": self.proof["receiptDigest"], "cleanupDigest": canonical_digest(self.cleanup), "workerReaped": True}}
        self.before = self.io.raw
        self.io.events.clear()

    def seal(self):
        return self.log.record_completion(self.binding, "CLEANUP_SEALED", self.case, NOW,
            expected_history=self.io.raw, cleanup=self.cleanup, completion=self.proof)

    def finish(self):
        return self.log.record_completion(self.binding, "TERMINAL_RECORDED", self.case, NOW,
            expected_history=self.io.raw, terminal=self.terminal)

    def test_seal_is_durable_and_holds_case_without_inventing_terminal(self):
        digest = self.seal()
        self.assertEqual(self.io.events, ["lock", "read", "append", "fsync", "read", "unlock"])
        self.assertEqual(digest, canonical_digest(json.loads(self.io.raw.splitlines()[-1])))
        self.assertEqual(self.state()["pendingCompletion"]["frameDigest"], canonical_digest(self.cleanup_frame))
        self.assertTrue(self.state()["held"])
        self.assertEqual(self.state()["current"], self.case)
        self.assertNotIn("terminalCases", self.state())

    def test_only_matching_terminal_record_can_close_current_case(self):
        self.seal()
        self.io.events.clear()
        self.finish()
        self.assertEqual(self.io.events, ["lock", "read", "append", "fsync", "read", "unlock"])
        self.assertIsNone(self.state()["current"])
        self.assertEqual(self.state()["terminalCases"], [self.case])
        self.assertTrue(self.state()["held"])
        self.assertNotIn("pendingCompletion", self.state())

    def test_tenth_cleanup_without_terminal_still_blocks_other_run(self):
        other = {**self.binding, "runNonce": "other-run"}
        for index, case in enumerate(admission.CASES):
            self.case = case
            if index:
                self.log.record(self.binding, "RUNNING", case, NOW)
            self.prepare()
            self.seal()
            with self.assertRaises(ConformanceError):
                self.log.record(other, "RESERVED", None, NOW)
            self.assertTrue(self.state()["held"])
            self.finish()
        self.assertFalse(self.state()["held"])
        self.log.record(other, "RESERVED", None, NOW)
        with self.assertRaises(ConformanceError):
            self.log.record(self.binding, "RESERVED", None, NOW)

    def test_lost_terminal_survives_restart_with_consumed_case(self):
        self.seal()
        restarted = admission._AdmissionLog(self.io)
        for state, operation in (("RUNNING", self.case), ("RUNNING", admission.CASES[1])):
            with self.subTest(operation=operation), self.assertRaises(ConformanceError):
                restarted.record(self.binding, state, operation, NOW)
        self.assertTrue(self.state()["held"])
        self.assertEqual(self.state()["current"], self.case)

    def test_terminal_cannot_precede_seal_or_repeat(self):
        with self.assertRaises(ConformanceError):
            self.finish()
        self.seal()
        self.finish()
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.finish()
        self.assertEqual(self.io.raw, before)

    def test_seal_cannot_repeat_or_be_downgraded_to_legacy_recorded(self):
        self.seal()
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.seal()
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_COMPLETION_MODE_CHANGED"):
            self.log.record(self.binding, "RECORDED", self.case, NOW, self.cleanup)
        self.assertEqual(self.io.raw, before)

    def test_legacy_completed_case_cannot_be_mixed_into_native_release(self):
        self.log.record(self.binding, "RECORDED", self.case, NOW, self.cleanup)
        self.case = admission.CASES[1]
        self.log.record(self.binding, "RUNNING", self.case, NOW)
        self.prepare()
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_COMPLETION_MODE_CHANGED"):
            self.seal()

    def test_native_completed_case_cannot_fall_back_to_legacy_release(self):
        self.seal()
        self.finish()
        self.case = admission.CASES[1]
        self.log.record(self.binding, "RUNNING", self.case, NOW)
        self.prepare()
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_COMPLETION_MODE_CHANGED"):
            self.log.record(self.binding, "RECORDED", self.case, NOW, self.cleanup)

    def test_wrong_terminal_digest_scope_status_or_reaping_never_releases(self):
        self.seal()
        before, original = self.io.raw, deepcopy(self.terminal)
        for path, value in ((["payload", "cleanupDigest"], admission.ZERO), (["payload", "receiptDigest"], admission.ZERO),
                (["payload", "receiptSize"], 33), (["payload", "status"], "FAILED"), (["payload", "workerReaped"], False),
                (["runNonce"], "foreign"), (["sequence"], 5), (["previousDigest"], admission.ZERO),
                (["executionId"], "e" * 64), (["generation"], "e" * 64), (["challenge"], "e" * 64)):
            self.terminal = altered(original, path, value)
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                self.finish()
            self.assertEqual(self.io.raw, before)
            self.assertFalse(self.log.poisoned)
            self.assertTrue(self.state()["held"])

    def test_invalid_or_unbounded_proof_never_appends(self):
        original = deepcopy(self.proof)
        for path, value in ((["receiptSize"], 0), (["receiptSize"], 4194305), (["receiptSize"], True),
                (["cleanupSequence"], 2), (["cleanupSequence"], 2048), (["receiptStatus"], "WARN"),
                (["failedAction"], 1), (["dispatch", "reservationDigest"], admission.ZERO),
                (["dispatch", "caseId"], admission.CASES[1]), (["extra"], "field")):
            self.proof = altered(original, path, value)
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                self.seal()
            self.assertEqual(self.io.raw, self.before)

    def test_failed_action_cannot_seal_pass(self):
        self.proof["failedAction"] = True
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_COMPLETION_FALSE_PASS"):
            self.seal()
        self.assertEqual(self.io.raw, self.before)

    def test_failed_and_unavailable_terminals_never_close_case_or_release(self):
        for status in ("FAIL", "NOT_RUN_ENV_UNAVAILABLE"):
            self.setUp()
            self.prepare(status)
            self.seal()
            self.finish()
            self.assertTrue(self.state()["held"])
            self.assertEqual(self.state()["current"], self.case)
            with self.assertRaises(ConformanceError):
                self.log.record(self.binding, "RUNNING", admission.CASES[1], NOW)

    def test_each_seal_write_or_readback_failure_is_sticky(self):
        for fault in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.io.fail = fault
            with self.subTest(fault=fault), self.assertRaises((ConformanceError, OSError)):
                self.seal()
            self.assertTrue(self.log.poisoned)
            after = self.io.raw
            with self.assertRaises(ConformanceError):
                self.seal()
            self.assertEqual(self.io.raw, after)

    def test_each_terminal_write_failure_preserves_history_without_retry(self):
        for fault in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.seal()
            sealed = self.io.raw
            self.io.fail = fault
            with self.subTest(fault=fault), self.assertRaises((ConformanceError, OSError)):
                self.finish()
            self.assertTrue(self.log.poisoned)
            self.assertTrue(self.io.raw.startswith(sealed))
            after = self.io.raw
            with self.assertRaises(ConformanceError):
                self.finish()
            self.assertEqual(self.io.raw, after)

    def test_stale_expected_history_never_appends_or_repairs(self):
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_COMPLETION_HISTORY_CHANGED"):
            self.log.record_completion(self.binding, "CLEANUP_SEALED", self.case, NOW,
                expected_history=b"", cleanup=self.cleanup, completion=self.proof)
        self.assertFalse(self.log.poisoned)
        self.assertEqual(self.io.raw, self.before)

    def test_zero_resource_seal_cannot_invent_remaining_resource(self):
        manifest = deepcopy(VECTORS["broker"]["positive"][1]["profile"]["resources"][0]["manifest"])
        row = {"apiVersion": "v1", "kind": manifest["kind"], "namespace": manifest["metadata"]["namespace"],
            "name": manifest["metadata"]["name"], "uid": "foreign", "manifestDigest": canonical_digest(manifest),
            "reasonCode": "OBSERVATION_UNAVAILABLE"}
        self.prepare("FAIL", [row])
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_RESOURCE_NOT_CLEAN"):
            self.seal()


class DeleteDataTests(unittest.TestCase):
    """Pure scoped request/response checks; no I/O, grants or cleanup result."""
    def setUp(self):
        self.manifest = deepcopy(VECTORS["broker"]["positive"][1]["profile"]["resources"][0]["manifest"])
        self.actual = deepcopy(self.manifest)
        self.uid = "unit-created-uid"
        self.actual["metadata"].update(uid=self.uid, resourceVersion="124")
        plural = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}[self.manifest["kind"]]
        self.success = {"apiVersion": "v1", "kind": "Status", "metadata": {}, "status": "Success", "code": 200,
            "details": {"name": self.manifest["metadata"]["name"], "kind": plural, "uid": self.uid}}

    def test_request_contains_only_uid_and_observed_version_preconditions(self):
        original = deepcopy(self.actual)
        raw = admission.delete_request_body(self.actual, self.manifest, self.uid)
        self.assertEqual(json.loads(raw), {"apiVersion": "v1", "kind": "DeleteOptions",
            "preconditions": {"uid": self.uid, "resourceVersion": "124"}})
        self.assertEqual(self.actual, original)

    def test_request_cannot_adopt_unknown_or_changed_uid(self):
        for uid in (None, "", "foreign", 1, True):
            with self.subTest(uid=uid), self.assertRaises(ConformanceError):
                admission.delete_request_body(self.actual, self.manifest, uid)

    def test_changed_label_or_manifest_never_produces_delete_options(self):
        for path, value in ((["metadata", "labels", "foreign"], "changed"),
                            (["metadata", "name"], "foreign"), (["data"], {"foreign": "changed"})):
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                admission.delete_request_body(altered(self.actual, path, value), self.manifest, self.uid)

    def test_version_is_required_and_never_defaults_to_uid_only(self):
        for version in (None, "", 123, True, "with space"):
            with self.subTest(version=version), self.assertRaises(ConformanceError):
                admission.delete_request_body(altered(self.actual, ["metadata", "resourceVersion"], version),
                                              self.manifest, self.uid)

    def test_unsafe_request_options_cannot_be_injected_through_observation(self):
        for field, value in (("gracePeriodSeconds", 0), ("propagationPolicy", "Foreground"),
                             ("ignoreStoreReadErrorWithClusterBreakingPotential", True)):
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                admission.delete_request_body({**self.actual, field: value}, self.manifest, self.uid)

    def test_exact_status_acknowledgement_returns_no_cleanup_authority(self):
        self.assertIsNone(admission.validate_delete_response(self.success, self.manifest, self.uid))
        self.assertIsNone(admission.validate_delete_response(
            altered(self.success, ["details", "group"], ""), self.manifest, self.uid))

    def test_status_must_match_original_uid_name_and_kind(self):
        for field, value in (("uid", "foreign"), ("name", "foreign"), ("kind", "namespaces"), ("group", "apps")):
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                admission.validate_delete_response(altered(self.success, ["details", field], value),
                                                   self.manifest, self.uid)

    def test_failure_wrong_code_or_wrong_shape_is_not_deleted(self):
        for field, value in (("status", "Failure"), ("code", 404), ("code", True),
                             ("metadata", {"name": "foreign"}), ("details", []), ("apiVersion", "v2")):
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                admission.validate_delete_response(altered(self.success, [field], value), self.manifest, self.uid)

    def test_status_unknown_fields_are_refused(self):
        for path in (["unknown"], ["details", "unknown"]):
            with self.subTest(path=path), self.assertRaises(ConformanceError):
                admission.validate_delete_response(altered(self.success, path, "value"), self.manifest, self.uid)

    def test_resource_response_is_not_an_absence_observation(self):
        self.assertIsNone(admission.validate_delete_response(self.actual, self.manifest, self.uid))
        with self.assertRaises(ConformanceError):
            admission.validate_absent_status(self.actual, self.manifest, self.uid)

    def test_graceful_delete_response_remains_only_an_acknowledgement(self):
        actual = deepcopy(self.actual)
        actual["metadata"].update(deletionTimestamp=NOW, deletionGracePeriodSeconds=30)
        before = deepcopy(actual)
        self.assertIsNone(admission.validate_delete_response(actual, self.manifest, self.uid))
        self.assertEqual(actual, before)

    def test_malformed_deletion_metadata_does_not_pass(self):
        for field, value in (("deletionTimestamp", "invalid"), ("deletionGracePeriodSeconds", -1),
                             ("deletionGracePeriodSeconds", True)):
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                admission.validate_delete_response(altered(self.actual, ["metadata", field], value),
                                                   self.manifest, self.uid)

    def test_changed_object_or_finalizer_list_cannot_be_silently_stripped(self):
        for field, value in (("uid", "foreign"), ("finalizers", ["foreign.example/hold"]),
                             ("labels", {"foreign": "true"})):
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                admission.validate_delete_response(altered(self.actual, ["metadata", field], value),
                                                   self.manifest, self.uid)

    def test_non_object_and_oversized_response_are_rejected(self):
        for value in ([], None, "text", b" " * 16385):
            with self.subTest(kind=type(value)), self.assertRaises(ConformanceError):
                admission.validate_delete_response(value, self.manifest, self.uid)


class AbsenceJournalTests(unittest.TestCase):
    """Actual data/journal algorithms; no authenticated API or native evidence."""
    record = ResourceJournalTests.record
    state = ResourceJournalTests.state
    resource = ResourceJournalTests.resource
    raw_row = ResourceJournalTests.raw_row
    payload = ResourceJournalTests.payload
    pending = ResourceJournalTests.pending

    def setUp(self):
        ResourceJournalTests.setUp(self)
        self.manifest = deepcopy(self.profile["resources"][0]["manifest"])
        name = self.manifest["metadata"]["name"]
        plural = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}[self.manifest["kind"]]
        self.not_found = {"apiVersion": "v1", "kind": "Status", "metadata": {}, "status": "Failure",
            "reason": "NotFound", "code": 404, "message": plural + ' "' + name + '" not found',
            "details": {"kind": plural, "name": name}}
        self.get = {**self.action, "actionId": 2, "verb": "GET"}

    def created(self):
        self.record()
        self.record("CREATED")
        self.before = self.io.raw
        self.io.events.clear()

    def absent(self, **changes):
        args = dict(binding=self.binding, operation=self.operation, now=NOW, profile=self.profile,
            broker_binding=self.broker_binding, action=self.get, expected_history=self.io.raw, observed=self.not_found)
        args.update(changes)
        return self.log.record_absence(**args)

    def test_exact_not_found_data_is_accepted_only_with_known_uid(self):
        self.assertIsNone(admission.validate_absent_status(self.not_found, self.manifest, "unit-created-uid"))
        explicit_core = altered(self.not_found, ["details", "group"], "")
        self.assertIsNone(admission.validate_absent_status(explicit_core, self.manifest, "unit-created-uid"))
        for uid in (None, True, "", "../foreign", "x" * 129):
            with self.subTest(uid=uid), self.assertRaises(ConformanceError):
                admission.validate_absent_status(self.not_found, self.manifest, uid)

    def test_status_missing_extra_and_wrong_type_fields_are_rejected(self):
        for field in self.not_found:
            missing = {k: v for k, v in self.not_found.items() if k != field}
            with self.subTest(field=field), self.assertRaises(ConformanceError):
                admission.validate_absent_status(missing, self.manifest, "unit-created-uid")
        for value in (None, [], True, {**self.not_found, "accepted": True}):
            with self.subTest(value_type=type(value)), self.assertRaises(ConformanceError):
                admission.validate_absent_status(value, self.manifest, "unit-created-uid")

    def test_generic_error_namespace_error_and_foreign_resource_are_not_absence(self):
        for path, value in ((["status"], "Success"), (["code"], True), (["code"], 200),
                            (["code"], "404"), (["reason"], "Forbidden"), (["apiVersion"], "v2"),
                            (["kind"], "ConfigMap"), (["metadata"], {"resourceVersion": "17"}),
                            (["details", "name"], "foreign"), (["details", "kind"], "namespaces"),
                            (["details", "group"], "apps"), (["details", "uid"], "foreign"),
                            (["message"], "the server could not find the requested resource")):
            with self.subTest(path=path, value=value), self.assertRaises(ConformanceError):
                admission.validate_absent_status(altered(self.not_found, path, value), self.manifest, "unit-created-uid")

    def test_noncanonical_duplicate_and_oversize_status_bytes_are_rejected(self):
        raw = canonical_bytes(self.not_found)
        for value in (raw + b" ", raw[:-1] + b',"code":404}', b" " * 16385):
            with self.subTest(size=len(value)), self.assertRaises(ConformanceError):
                admission.validate_absent_status(value, self.manifest, "unit-created-uid")

    def test_absence_is_durable_before_return_and_keeps_original_identity(self):
        self.created()
        original = deepcopy(self.resource())
        digest = self.absent()
        self.assertEqual(self.io.events, ["lock", "read", "append", "fsync", "read", "unlock"])
        row = json.loads(self.io.raw.splitlines()[-1])
        self.assertEqual(digest, canonical_digest(row))
        self.assertEqual(row["resource"], {k: original[k] for k in self.payload() if k not in ("absenceActionId", "absenceDigest")})
        self.assertEqual(row["absence"], {"actionId": 2, "responseDigest": canonical_digest(self.not_found), "status": self.not_found})
        self.assertEqual(self.resource()["state"], "ABSENT")
        self.assertEqual((self.resource()["uid"], self.resource()["resourceVersion"], self.resource()["actionId"]),
                         ("unit-created-uid", "17", 1))
        self.assertEqual(self.state()["current"], self.operation)
        self.assertTrue(self.state()["held"])

    def test_absence_row_allows_clean_receipt_but_does_not_reopen_case_or_nonce(self):
        self.created()
        self.absent()
        receipt = admission.cleanup_receipt(canonical_digest(self.binding), self.operation, NOW, [])
        self.log.record(self.binding, "RECORDED", self.operation, NOW, receipt)
        self.assertIsNone(self.state()["current"])
        self.assertTrue(self.state()["held"])
        self.assertEqual(self.resource()["uid"], "unit-created-uid")
        for binding, state, operation in ((self.binding, "RUNNING", self.operation),
                                         ({**self.binding, "runNonce": "new-run"}, "RESERVED", None)):
            with self.subTest(state=state), self.assertRaises(ConformanceError):
                self.log.record(binding, state, operation, NOW)

    def test_no_owned_create_and_ambiguous_create_cannot_be_recorded_absent(self):
        for intent in (False, True):
            if intent:
                self.record()
            before = self.io.raw
            with self.subTest(intent=intent), self.assertRaises(ConformanceError):
                self.absent()
            self.assertEqual(self.io.raw, before)
            self.assertTrue(self.state()["held"])

    def test_duplicate_absence_and_created_name_reuse_are_rejected(self):
        self.created()
        self.absent()
        before = self.io.raw
        for action in (self.get, {**self.get, "actionId": 3}):
            with self.subTest(action=action), self.assertRaises(ConformanceError):
                self.absent(action=action)
        with self.assertRaises(ConformanceError):
            self.record(action={**self.action, "actionId": 3})
        self.assertEqual(self.io.raw, before)

    def test_absence_rejects_action_scope_and_non_get_verbs_before_write(self):
        self.created()
        for key, value in (("verb", "CREATE"), ("verb", "DELETE"), ("actionId", 1),
                           ("actionId", True), ("actionId", 257), ("manifestDigest", admission.ZERO)):
            with self.subTest(key=key, value=value), self.assertRaises(ConformanceError):
                self.absent(action={**self.get, key: value})
        self.assertEqual(self.io.raw, self.before)
        self.assertNotIn("append", self.io.events)

    def test_wrong_case_binding_profile_or_history_cannot_claim_absence(self):
        self.created()
        for change in ({"operation": admission.CASES[1]}, {"binding": {**self.binding, "runNonce": "foreign"}},
                       {"profile": altered(self.profile, ["resources", 0, "manifest", "metadata", "name"], "foreign")},
                       {"expected_history": self.initial}):
            with self.subTest(change=next(iter(change))), self.assertRaises(ConformanceError):
                self.absent(**change)
        self.assertEqual(self.io.raw, self.before)

    def test_each_ambiguous_absence_write_is_poisoned_and_cannot_retry(self):
        for failure in ("before", "partial", "after", "sync", "readback"):
            self.setUp()
            self.created()
            self.io.fail = failure
            with self.subTest(failure=failure), self.assertRaises((ConformanceError, OSError)):
                self.absent()
            self.assertTrue(self.log.poisoned)
            retained, events = self.io.raw, list(self.io.events)
            with self.assertRaises(ConformanceError):
                self.absent()
            self.assertEqual(self.io.raw, retained)
            self.assertEqual(self.io.events, events)

    def test_restart_replays_absence_history_without_changing_identity(self):
        self.created()
        self.absent()
        before = self.io.raw
        self.log = admission._AdmissionLog(self.io)
        self.assertEqual(self.resource()["state"], "ABSENT")
        self.assertEqual(self.resource()["uid"], "unit-created-uid")
        with self.assertRaises(ConformanceError):
            self.absent()
        self.assertEqual(self.io.raw, before)

    def test_forged_absence_row_cannot_replace_uid_version_or_digest(self):
        self.created()
        resource, proof = admission._absence_record(self.binding, self.operation, self.profile,
            self.broker_binding, self.get, self.io.raw, self.not_found)
        for key, value in (("uid", "foreign"), ("resourceVersion", "18"), ("actionId", 2),
                           ("name", "foreign"), ("manifestDigest", admission.ZERO)):
            with self.subTest(key=key), self.assertRaises(ConformanceError):
                admission.parse_reservations(self.raw_row("ABSENT", {**resource, key: value}, absence=proof))

    def test_absence_proof_fields_and_hash_are_closed(self):
        self.created()
        resource, proof = admission._absence_record(self.binding, self.operation, self.profile,
            self.broker_binding, self.get, self.io.raw, self.not_found)
        for value in ({**proof, "responseDigest": admission.ZERO}, {**proof, "actionId": True},
                      {**proof, "actionId": 1}, {**proof, "accepted": True},
                      {k: v for k, v in proof.items() if k != "status"}):
            with self.subTest(value=value), self.assertRaises(ConformanceError):
                admission.parse_reservations(self.raw_row("ABSENT", resource, absence=value))

    def test_pending_cleanup_cannot_be_reopened_by_later_absence(self):
        self.created()
        self.log.record(self.binding, "RECORDED", self.operation, NOW, self.pending("DELETE_DENIED"))
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.absent()
        self.assertEqual(self.io.raw, before)
        self.assertTrue(self.state()["held"])

    def test_resolved_resource_cannot_be_reintroduced_as_pending_cleanup(self):
        self.created()
        pending = self.pending("DELETE_DENIED")
        self.absent()
        before = self.io.raw
        with self.assertRaises(ConformanceError):
            self.log.record(self.binding, "RECORDED", self.operation, NOW, pending)
        self.assertEqual(self.io.raw, before)

    def test_absence_does_not_clear_a_second_unresolved_resource(self):
        self.created()
        first = self.payload()
        second = {**first, "name": "second", "actionId": 3, "manifestDigest": admission.ZERO,
                  "uid": None, "resourceVersion": None}
        self.io.raw = self.raw_row("CREATE_INTENT", second)
        self.get["actionId"] = 4
        self.absent()
        with self.assertRaises(ConformanceError):
            receipt = admission.cleanup_receipt(canonical_digest(self.binding), self.operation, NOW, [])
            self.log.record(self.binding, "RECORDED", self.operation, NOW, receipt)
        remaining = [{k: second[k] for k in ("apiVersion", "kind", "namespace", "name", "uid", "manifestDigest")}]
        remaining[0]["reasonCode"] = "IO_AMBIGUOUS"
        receipt = admission.cleanup_receipt(canonical_digest(self.binding), self.operation, NOW, remaining)
        self.log.record(self.binding, "RECORDED", self.operation, NOW, receipt)
        self.assertTrue(self.state()["held"])
        self.assertEqual({r["state"] for r in self.state()["resources"].values()}, {"ABSENT", "CREATE_INTENT"})

    def test_native_seal_and_failed_terminal_preserve_ambiguous_create_name(self):
        self.record()
        self.case = self.operation
        remaining = self.pending()["remainingResources"]
        CompletionJournalTests.prepare(self, "FAIL", remaining)
        CompletionJournalTests.seal(self)
        CompletionJournalTests.finish(self)
        self.assertTrue(self.state()["held"])
        self.assertEqual(self.state()["current"], self.operation)
        self.assertIsNone(self.resource()["uid"])
        self.assertEqual(self.resource()["state"], "CREATE_INTENT")
        self.assertEqual(json.loads(self.io.raw.splitlines()[-2])["cleanup"]["remainingResources"], remaining)

    def test_native_seal_cannot_omit_ambiguous_create_even_for_failed_receipt(self):
        self.record()
        self.case = self.operation
        CompletionJournalTests.prepare(self, "FAIL")
        before = self.io.raw
        with self.assertRaisesRegex(ConformanceError, "ADMISSION_RESOURCE_NOT_CLEAN"):
            CompletionJournalTests.seal(self)
        self.assertEqual(self.io.raw, before)

    def test_native_terminal_preserves_confirmed_original_uid_without_reuse(self):
        self.created()
        self.absent()
        self.case = self.operation
        original = self.resource()
        CompletionJournalTests.prepare(self)
        CompletionJournalTests.seal(self)
        self.assertEqual(self.state()["current"], self.operation)
        CompletionJournalTests.finish(self)
        self.assertIsNone(self.state()["current"])
        self.assertEqual(self.resource(), original)
        self.assertTrue(self.state()["held"])
        with self.assertRaises(ConformanceError):
            self.record()


class StrictTimestampParserTests(unittest.TestCase):
    """Compare the private fast path with the exact former parser, not a clock.

    These pure-data tests grant no qualification. Invalid input still follows
    the old rejection path; no expiration, signature or I/O check is cached.
    """
    @staticmethod
    def legacy(value):
        admission.require(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value),
                          "PROXY_TIME_INVALID")
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    @staticmethod
    def outcome(function, value):
        try:
            result = function(value)
        except (ValueError, ConformanceError) as error:
            return (type(error), error.args, getattr(error, "code", None),
                    type(error.__cause__), type(error.__context__))
        return (type(result), result, result.tzinfo, result.fold, result.microsecond)

    def assert_equivalent(self, value):
        self.assertEqual(self.outcome(admission._time, value), self.outcome(self.legacy, value))

    def test_calendar_boundaries_keep_values_and_original_errors(self):
        for year in (1, 4, 100, 400, 999, 1000, 1582, 1600, 1700, 1800,
                     1900, 1999, 2000, 2024, 2026, 2100, 2400, 9999):
            for month in range(1, 13):
                for day in (1, 28, 29, 30, 31, 32):
                    value = f"{year:04d}-{month:02d}-{day:02d}T23:59:59Z"
                    with self.subTest(value=value):
                        self.assert_equivalent(value)

    def test_clock_boundaries_and_leap_seconds_keep_original_errors(self):
        for hour in (0, 1, 23, 24, 99):
            for minute in (0, 1, 59, 60, 99):
                for second in (0, 1, 59, 60, 61, 99):
                    value = f"2026-09-15T{hour:02d}:{minute:02d}:{second:02d}Z"
                    with self.subTest(value=value):
                        self.assert_equivalent(value)

    def test_invalid_calendar_keeps_error_args_without_fast_parser_context(self):
        for value in ("0000-01-01T00:00:00Z", "2026-00-01T00:00:00Z",
                      "2026-13-01T00:00:00Z", "2026-01-00T00:00:00Z",
                      "2026-02-30T00:00:00Z", "1900-02-29T00:00:00Z",
                      "2026-09-15T99:99:99Z"):
            with self.subTest(value=value):
                self.assert_equivalent(value)
                with self.assertRaises(ValueError) as caught:
                    admission._time(value)
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)

    def test_exact_ascii_grammar_rejects_broader_iso_spellings_before_parsing(self):
        class NoParser:
            @staticmethod
            def fromisoformat(value):
                raise AssertionError("invalid grammar reached ISO parser")
            @staticmethod
            def strptime(value, format):
                raise AssertionError("invalid grammar reached legacy parser")
        class String(str):
            pass
        values = (None, True, 1, {}, [], b"2026-09-15T00:00:00Z",
            String("2026-09-15T00:00:00Z"), "", "20260915T000000Z",
            "2026-W38-2T00:00:00Z", "2026-258T00:00:00Z", "2026-9-15T00:00:00Z",
            "2026-09-15t00:00:00Z", "2026-09-15T00:00:00z", "2026-09-15 00:00:00Z",
            "2026-09-15T00:00:00+00:00", "2026-09-15T00:00:00.000Z",
            "2026-09-15T00:00:00,1Z", "2026-09-15T00:00:00Z\n",
            "2026-09-15T00:00:00Z\x00", "２０２６-09-15T00:00:00Z",
            "2026-09-15T٠٠:00:00Z", " 2026-09-15T00:00:00Z",
            "2026-02-99T00:00:00Zsuffix", "10000-01-01T00:00:00Z")
        with patch.object(admission, "datetime", NoParser):
            for value in values:
                with self.subTest(value=value):
                    self.assert_equivalent(value)
                    with self.assertRaisesRegex(ConformanceError, "PROXY_TIME_INVALID"):
                        admission._time(value)

    def test_valid_path_uses_iso_parser_and_returns_exact_utc_datetime(self):
        seen = []
        class Parser:
            @staticmethod
            def fromisoformat(value):
                seen.append(value)
                return datetime.fromisoformat(value)
            @staticmethod
            def strptime(value, format):
                raise AssertionError("valid fixed grammar reached locale parser")
        with patch.object(admission, "datetime", Parser):
            result = admission._time("0001-01-01T00:00:00Z")
        self.assertEqual(seen, ["0001-01-01T00:00:00"])
        self.assertIs(type(result), datetime)
        self.assertIs(result.tzinfo, timezone.utc)
        self.assertEqual(result, self.legacy("0001-01-01T00:00:00Z"))

    def test_each_call_reparses_without_reusing_an_expiry_or_result(self):
        values = ("2026-09-15T00:00:00Z", "2026-09-15T00:00:01Z",
                  "2026-09-14T23:59:59Z", "2026-09-15T00:00:00Z")
        results = [admission._time(value) for value in values]
        self.assertEqual(results, [self.legacy(value) for value in values])
        self.assertIsNot(results[0], results[-1])

    def test_bounded_parser_timing_is_diagnostic_not_an_acceptance_threshold(self):
        # ABBA order; fixed small workload, full discovery, no speed assertion.
        # This is not a native-phase benchmark or a whole-suite speedup claim.
        value = "2026-09-15T00:00:02Z"
        expected = self.legacy(value)
        for label, function in (("legacy", self.legacy), ("candidate", admission._time),
                                ("candidate", admission._time), ("legacy", self.legacy)):
            start = _wall_clock()
            for _ in range(512):
                result = function(value)
            elapsed = _wall_clock() - start
            self.assertEqual(result, expected)
            print(f"CONF-FIX-007 timestamp-parser variant={label} calls=512 "
                  f"elapsedSeconds={elapsed:.6f} evidenceClass=DIAGNOSTIC_ONLY", flush=True)
