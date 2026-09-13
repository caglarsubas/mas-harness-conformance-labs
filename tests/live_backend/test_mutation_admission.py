"""Offline data/state regressions; neither fixtures nor journals grant effects."""
from copy import deepcopy
import base64
import json
import unittest
from time import perf_counter as _wall_clock

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
