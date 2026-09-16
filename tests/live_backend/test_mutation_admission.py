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


# CONF-PERF-006: independent fixed semantic oracles and source-only custody.
import ast as _doc_ast
import hashlib as _doc_hashlib

_DOCUMENT_REPAIR_PROOF_SHA256 = "0122ee71f769fe14edd90912ab143ce373db7bced202cea7162c87df94f7d82d"
_DOC_RUNTIME = "src/harness_conformance/live_mutation_admission.py"
_DOC_TESTS = "tests/live_backend/test_mutation_admission.py"
_DOC_GUIDE = "docs/live-backend/proxy.md"
_DOC_BEGIN = b"<!-- CONF-PERF-006 SOURCE_DELTA_ONLY BEGIN -->\n"
_DOC_END = b"\n<!-- CONF-PERF-006 SOURCE_DELTA_ONLY END -->\n"


def _doc_sha(raw):
    return _doc_hashlib.sha256(raw).hexdigest()


def _doc_function(raw):
    nodes = [node for node in _doc_ast.parse(raw).body
             if isinstance(node, _doc_ast.FunctionDef) and node.name == "document"]
    if len(nodes) != 1 or nodes[0].decorator_list:
        raise ValueError("exact document function required")
    node = nodes[0]
    lines = raw.splitlines(keepends=True)
    return (b"".join(lines[:node.lineno - 1]),
            b"".join(lines[node.lineno - 1:node.end_lineno]),
            b"".join(lines[node.end_lineno:]))


def _doc_ids(sources):
    result = {}
    for path, raw in sorted(sources.items()):
        if not (path.startswith("tests/") and path.rsplit("/", 1)[-1].startswith("test_")
                and path.endswith(".py")):
            continue
        tree = _doc_ast.parse(raw)
        if any(isinstance(n, (_doc_ast.FunctionDef, _doc_ast.AsyncFunctionDef))
               and n.name == "load_tests" for n in tree.body):
            raise ValueError("no discovery override")
        ids = [cls.name + "." + method.name for cls in tree.body
               if isinstance(cls, _doc_ast.ClassDef) for method in cls.body
               if isinstance(method, _doc_ast.FunctionDef) and method.name.startswith("test_")]
        if not ids or len(set(ids)) != len(ids):
            raise ValueError("empty or duplicate test identities")
        result[path] = sorted(ids)
    return result


def _doc_verify_sources(rows, sources):
    # This validates data, never imports or executes stored source text.
    guide = sources.get(_DOC_GUIDE, b"")
    if guide.count(_DOC_BEGIN) != 1 or guide.count(_DOC_END) != 1:
        raise ValueError("one exact source proof required")
    prefix, tail = guide.split(_DOC_BEGIN)
    proof_raw, suffix = tail.split(_DOC_END)
    if suffix or _doc_sha(proof_raw) != _DOCUMENT_REPAIR_PROOF_SHA256:
        raise ValueError("independently pinned proof required")
    proof = json.loads(proof_raw)
    baseline = proof["baselineFiles"]
    if len(rows) != 135 or len(sources) != 135:
        raise ValueError("135 current files required")
    seen = set()
    for row in rows:
        path = row["path"]
        if path in seen or path not in baseline or path not in sources:
            raise ValueError("unknown, duplicate or missing source")
        seen.add(path)
        raw = sources[path]
        if (type(raw) is not bytes or row["kind"] != "file" or row["nlink"] != 1
                or row["linkedAncestry"] is not False or row["mode"] != baseline[path]["mode"]
                or row["size"] != len(raw) or row["sha256"] != _doc_sha(raw)):
            raise ValueError("current row/source custody mismatch")
        if path not in (_DOC_RUNTIME, _DOC_TESTS, _DOC_GUIDE):
            blob = _doc_hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            if (len(raw), _doc_sha(raw), blob) != (
                    baseline[path]["size"], baseline[path]["sha256"], baseline[path]["blob"]):
                raise ValueError("non-owned source changed")
    if seen != set(baseline) or set(sources) != seen:
        raise ValueError("closed source inventory required")
    before, function, after = _doc_function(sources[_DOC_RUNTIME])
    region = proof["runtime"]
    original = region["beforeSource"].encode()
    if (_doc_sha(before) != region["prefixSha256"] or _doc_sha(after) != region["suffixSha256"]
            or _doc_sha(function) != region["candidateSha256"]
            or _doc_sha(original) != region["beforeSha256"]
            or _doc_sha(before + original + after) != baseline[_DOC_RUNTIME]["sha256"]):
        raise ValueError("exact owner region and before-image required")
    for path in (_DOC_TESTS, _DOC_GUIDE):
        old = baseline[path]
        if _doc_sha(sources[path][:old["size"]]) != old["sha256"]:
            raise ValueError("historical prefix changed")
    if prefix[baseline[_DOC_GUIDE]["size"]:] != proof["guideIntroduction"].encode():
        raise ValueError("exact appended guidance required")
    extension = sources[_DOC_TESTS][baseline[_DOC_TESTS]["size"]:]
    anchor = ('_DOCUMENT_REPAIR_PROOF_SHA256 = "' + _DOCUMENT_REPAIR_PROOF_SHA256 + '"').encode()
    normalized = b'_DOCUMENT_REPAIR_PROOF_SHA256 = "' + b"0" * 64 + b'"'
    if extension.count(anchor) != 1 or _doc_sha(extension.replace(anchor, normalized)) != proof["testExtensionSha256"]:
        raise ValueError("test definitions changed")
    observed = _doc_ids(sources)
    expected = deepcopy(proof["baselineTestIds"])
    expected[_DOC_TESTS] = sorted(expected[_DOC_TESTS] + proof["addedTestIds"])
    if observed != expected or sum(map(len, observed.values())) != 1309:
        raise ValueError("exact old plus new test identities required")
    return proof


def _doc_current_sources():
    # Reuse only the accepted current-file reader, not its acceptance result.
    from _inventory import SUCCESSOR
    return SUCCESSOR.tracked_inventory(ROOT)


def _doc_reseal(rows, sources, path, raw):
    # Independent negative assembler: do not call any production/proof builder.
    changed_rows, changed_sources = deepcopy(rows), dict(sources)
    changed_sources[path] = raw
    row = next(r for r in changed_rows if r["path"] == path)
    row["size"] = len(raw)
    row["sha256"] = _doc_hashlib.sha256(raw).hexdigest()
    return changed_rows, changed_sources


class DocumentRepairTests(unittest.TestCase):
    def _error(self, value, maximum, reason, message="fixed proxy refused; no execution authority"):
        with self.assertRaises(ConformanceError) as caught:
            admission.document(value, maximum)
        self.assertIs(type(caught.exception), ConformanceError)
        self.assertEqual((caught.exception.reason, caught.exception.message), (reason, message))
        self.assertEqual(str(caught.exception), reason + ": " + message)

    def test_compact_primitives(self):
        rows = [(b"null", None), (b"true", True), (b"false", False), (b"0", 0),
                (b"9007199254740991", 9007199254740991),
                (b"-9007199254740991", -9007199254740991),
                (b'"caf\xc3\xa9"', "caf\u00e9")]
        for raw, expected in rows:
            with self.subTest(raw=raw):
                result = admission.document(raw)
                self.assertIs(type(result), type(expected))
                self.assertEqual(result, expected)

    def test_compact_containers(self):
        for raw, expected in [(b"[]", []), (b"{}", {}),
                              (b'[0,true,null,{"a":[]}]', [0, True, None, {"a": []}]),
                              (b'{"a":[1],"b":{"c":false}}', {"a": [1], "b": {"c": False}})]:
            with self.subTest(raw=raw):
                self.assertEqual(admission.document(raw), expected)

    def test_final_newline(self):
        for raw in (b"{}\n", b"null\n", b"[0]\n"):
            with self.subTest(raw=raw):
                self._error(raw, len(raw), "PROXY_NONCANONICAL_BYTES")

    def test_noncanonical_wire(self):
        for raw in (b'{ "a":1}', b"{}\r\n", b'{"b":0,"a":1}', b'"\\u0061"', b'"\\/"', b"-0"):
            with self.subTest(raw=raw):
                self._error(raw, 262144, "NON_CANONICAL_JSON", "document bytes are not canonical JSON")
        for raw in (b"{}x", b"{}{}", b"{}\n\n{}"):
            with self.subTest(raw=raw):
                self._error(raw, 262144, "INVALID_JSON", "document is not valid strict JSON")

    def test_duplicate_members(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":{"a":1,"a":2}}'):
            with self.subTest(raw=raw):
                self._error(raw, 262144, "DUPLICATE_JSON_MEMBER", "duplicate member 'a'")

    def test_invalid_utf8(self):
        for raw in (b"\xff", b'"\xc3"', b'"\xed\xa0\x80"'):
            with self.subTest(raw=raw):
                self._error(raw, len(raw), "INVALID_UTF8", "document is not UTF-8")

    def test_malformed_json(self):
        for raw in (b"{", b"[", b"tru", b"01", b'{"a":}', b'"unterminated'):
            with self.subTest(raw=raw):
                self._error(raw, len(raw), "INVALID_JSON", "document is not valid strict JSON")

    def test_noncanonical_numbers(self):
        for raw in (b"1.0", b"1e0", b"NaN", b"Infinity", b"-Infinity", b"[1.5]"):
            with self.subTest(raw=raw):
                self._error(raw, 262144, "NON_CANONICAL_NUMBER", "floating-point values are not permitted")

    def test_integer_bounds(self):
        for number in (-9007199254740991, 9007199254740991):
            self.assertEqual(admission.document(str(number).encode()), number)
        for raw in (b"9007199254740992", b"-9007199254740992"):
            self._error(raw, len(raw), "INTEGER_OUT_OF_RANGE", "integer exceeds the canonical safe range")

    def test_unicode_nfc_and_surrogates(self):
        self.assertEqual(admission.document(b'{"caf\xc3\xa9":"\xe7\x95\x8c"}'), {"caf\u00e9": "\u754c"})
        for raw in (b'"e\xcc\x81"', b'{"e\xcc\x81":0}'):
            self._error(raw, 262144, "NON_NORMALIZED_STRING", "strings must use Unicode NFC")
        for raw, value in ((b'"\\ud800"', "\ud800"), (b'{"\\udfff":0}', "\udfff")):
            with self.assertRaises(UnicodeEncodeError) as caught:
                admission.document(raw)
            self.assertIs(type(caught.exception), UnicodeEncodeError)
            self.assertEqual((caught.exception.encoding, caught.exception.object,
                              caught.exception.start, caught.exception.end, caught.exception.reason),
                             ("utf-8", value, 0, 1, "surrogates not allowed"))

    def test_wire_size_precedence(self):
        for raw, maximum in ((b"", 1), (b"", 0), (b"0", 0), (b"0", -1),
                             (b"{broken", 2), (b"\xff\xff", 1), (b"null", 3)):
            with self.subTest(raw=raw, maximum=maximum):
                self._error(raw, maximum, "PROXY_DATA_SIZE")
        self.assertIsNone(admission.document(b"null", 4))

    def test_depth_boundaries(self):
        expected = None
        for _ in range(16):
            expected = [expected]
        self.assertEqual(admission.document(b"[" * 16 + b"null" + b"]" * 16), expected)
        for depth in (17, 32):
            self._error(b"[" * depth + b"null" + b"]" * depth, 262144, "PROXY_DATA_TYPE")
        self._error(b"[" * 33 + b"null" + b"]" * 33, 262144,
                    "DOCUMENT_TOO_DEEP", "document nesting exceeds the bound")

    def test_collection_boundaries(self):
        self.assertEqual(admission.document(b"[" + b"0," * 4095 + b"0]"), [0] * 4096)
        self._error(b"[" + b"0," * 4096 + b"0]", 262144,
                    "COLLECTION_TOO_LARGE", "array exceeds the item bound")
        for count in (4096, 4097):
            # Independent sorted wire construction, not a candidate serializer.
            raw = ("{" + ",".join('"k%04d":0' % n for n in range(count)) + "}").encode()
            if count == 4096:
                self.assertEqual(admission.document(raw), {"k%04d" % n: 0 for n in range(count)})
            else:
                self._error(raw, 262144, "COLLECTION_TOO_LARGE", "object exceeds the member bound")

    def test_object_budget_and_encoded_size(self):
        self.assertEqual(admission.document([0, 0], 5), [0, 0])
        self._error([0, 0], 4, "PROXY_DATA_SIZE")  # aggregate node budget
        self._error({"a": 0}, 5, "PROXY_DATA_SIZE")  # encoded size 7, node budget 5
        self.assertEqual(admission.document({"a": 0}, 7), {"a": 0})
        self._error([object()], 1, "PROXY_DATA_SIZE")  # budget precedes child type
        self._error([object()], 2, "PROXY_DATA_TYPE")
        self._error({1: 0}, 0, "PROXY_DATA_SIZE")
        self._error({1: 0}, 2, "PROXY_DATA_KEY")
        self._error([0, 9007199254740992], 4, "PROXY_DATA_SIZE")
        self._error([0, 9007199254740992], 5, "PROXY_INTEGER_RANGE")

    def test_global_document_bound(self):
        raw = b" " * (4 * 1024 * 1024 + 1)
        self._error(raw, len(raw), "DOCUMENT_TOO_LARGE", "document exceeds the local size bound")
        self._error(raw, 262144, "PROXY_DATA_SIZE")

    def test_exact_error_contract(self):
        rows = [(b"{}\n", 3, "PROXY_NONCANONICAL_BYTES", "fixed proxy refused; no execution authority"),
                (b"{}\r\n", 4, "NON_CANONICAL_JSON", "document bytes are not canonical JSON"),
                (b'{"a":1,"a":2}', 262144, "DUPLICATE_JSON_MEMBER", "duplicate member 'a'"),
                (b"\xff", 1, "INVALID_UTF8", "document is not UTF-8"),
                (b"{", 1, "INVALID_JSON", "document is not valid strict JSON"),
                (b"", 0, "PROXY_DATA_SIZE", "fixed proxy refused; no execution authority"),
                (b"1.0", 3, "NON_CANONICAL_NUMBER", "floating-point values are not permitted")]
        for raw, maximum, reason, message in rows:
            with self.subTest(raw=raw):
                self._error(raw, maximum, reason, message)
        with self.assertRaises(TypeError) as caught:
            admission.document(b"0", None)
        self.assertIs(type(caught.exception), TypeError)
        self.assertEqual(str(caught.exception), "'<=' not supported between instances of 'int' and 'NoneType'")
        with self.assertRaises(UnicodeEncodeError) as caught:
            admission.document(b'"\\ud800"')
        self.assertIs(type(caught.exception), UnicodeEncodeError)
        self.assertEqual(caught.exception.reason, "surrogates not allowed")

    def test_bytes_subclass(self):
        class Bytes(bytes):
            pass
        for value in (Bytes(b"0"), Bytes(b"{broken")):
            self._error(value, 262144, "PROXY_DATA_TYPE")

    def test_mutable_buffers(self):
        for value in (bytearray(b"0"), memoryview(b"0")):
            self._error(value, 262144, "PROXY_DATA_TYPE")

    def test_container_subclasses(self):
        for parent, value in ((dict, {}), (list, []), (str, "a"), (int, 1)):
            subclass = type("NotExact", (parent,), {})
            self._error(subclass(value), 262144, "PROXY_DATA_TYPE")

    def test_bool_maximum(self):
        self.assertEqual(admission.document(b"0", True), 0)
        self._error(b"0", False, "PROXY_DATA_SIZE")

    def test_float_maximum(self):
        self.assertEqual(admission.document(b"0", 1.0), 0)
        for maximum in ("1", None):
            with self.assertRaises(TypeError) as caught:
                admission.document(b"0", maximum)
            self.assertIs(type(caught.exception), TypeError)

    def test_integer_subclass_maximum(self):
        calls = []
        class Maximum(int):
            def __ge__(self, other):
                calls.append(("ge", other))
                return int(self) >= other
            def __sub__(self, other):
                calls.append(("sub", other))
                return int(self) - other
        self.assertEqual(admission.document(b"0", Maximum(1)), 0)
        self.assertEqual(calls, [("ge", 1), ("sub", 1), ("ge", 1)])

    def test_effectful_maximum(self):
        calls = []
        class Maximum:
            def __init__(self, allow):
                self.allow = allow
            def __ge__(self, other):
                calls.append(("ge", other))
                return self.allow
            def __sub__(self, other):
                calls.append(("sub", other))
                return 1 - other
        self.assertEqual(admission.document(b"0", Maximum(True)), 0)
        self.assertEqual(calls, [("ge", 1), ("sub", 1), ("ge", 1)])
        calls.clear()
        self._error(b"{", Maximum(False), "PROXY_DATA_SIZE")
        self.assertEqual(calls, [("ge", 1)])

    def test_ordinary_object_fallback(self):
        value = {"a": [0, {"b": True}]}
        result = admission.document(value)
        self.assertEqual(result, {"a": [0, {"b": True}]})
        self.assertIsNot(result, value)
        self.assertIsNot(result["a"], value["a"])
        self._error(9007199254740992, 262144, "PROXY_INTEGER_RANGE")
        self._error(1.0, 262144, "PROXY_DATA_TYPE")

    def test_detached_input(self):
        value = {"a": [{"b": [1]}]}
        result = admission.document(value)
        value["a"][0]["b"].append(2)
        value["a"].append({})
        self.assertEqual(result, {"a": [{"b": [1]}]})

    def test_detached_result(self):
        value = {"a": [{"b": [1]}]}
        result = admission.document(value)
        result["a"][0]["b"].clear()
        self.assertEqual(value, {"a": [{"b": [1]}]})
        self.assertEqual(admission.document(value), {"a": [{"b": [1]}]})

    def test_repeated_bytes(self):
        raw = b'{"a":[{"b":[1]}]}'
        first, second = admission.document(raw), admission.document(raw)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["a"], second["a"])
        self.assertIsNot(first["a"][0], second["a"][0])
        self.assertIsNot(first["a"][0]["b"], second["a"][0]["b"])
        first["a"][0]["b"].clear()
        self.assertEqual(second, {"a": [{"b": [1]}]})
        self.assertEqual(admission.document(raw), second)

    def test_changed_bytes(self):
        self.assertEqual(admission.document(b'{"a":[1]}'), {"a": [1]})
        self.assertEqual(admission.document(b'{"a":[2]}'), {"a": [2]})
        self._error(b'{"a":[}', 262144, "INVALID_JSON", "document is not valid strict JSON")
        self._error(b'{"a":[1]}\n', 262144, "PROXY_NONCANONICAL_BYTES")
        self.assertEqual(admission.document(b'{"a":[1]}'), {"a": [1]})

    def test_exact_owner_regions(self):
        rows, sources = _doc_current_sources()
        proof = _doc_verify_sources(rows, sources)
        self.assertEqual(proof["evidenceClass"], "SOURCE_DELTA_ONLY")
        self.assertEqual(proof["baselineCommit"], "092fcf475c6f3ebd455e3c354cddb7664ea1f900")
        self.assertEqual(proof["runtime"]["candidateSha256"],
                         "fe3b468872cb14db63f1b2bc1b5c4579703d1e8909c037f8e657ed2d2c26d97c")
        before, function, after = _doc_function(sources[_DOC_RUNTIME])
        self.assertIn(proof["runtime"]["beforeSource"].encode().split(b"\n", 1)[1], function)
        self.assertTrue(before and after)

    def test_unchanged_inventory(self):
        rows, sources = _doc_current_sources()
        _doc_verify_sources(rows, sources)
        variants = [(rows[:-1], sources), (rows + [dict(rows[0])], sources),
                    (rows, {**sources, "unexpected.py": b""}),
                    (rows, {p: v for p, v in sources.items() if p != rows[0]["path"]})]
        for key, value in (("kind", "symlink"), ("nlink", 2), ("linkedAncestry", True),
                           ("mode", "120000"), ("sha256", "0" * 64), ("size", -1)):
            changed = deepcopy(rows)
            changed[0][key] = value
            variants.append((changed, sources))
        for changed_rows, changed_sources in variants:
            with self.subTest(rows=len(changed_rows), files=len(changed_sources)), self.assertRaises(ValueError):
                _doc_verify_sources(changed_rows, changed_sources)
        from pathlib import Path
        import os
        import tempfile
        from _inventory import SUCCESSOR
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            regular = root / "original"
            regular.write_bytes(b"current")
            (root / "alias").symlink_to(regular)
            with self.assertRaises(ValueError):
                SUCCESSOR.regular_bytes(root, "alias")
            os.link(regular, root / "hardlink")
            with self.assertRaises(ValueError):
                SUCCESSOR.regular_bytes(root, "original")

    def test_resealed_substitutions(self):
        rows, sources = _doc_current_sources()
        proof = _doc_verify_sources(rows, sources)
        prefix, function, suffix = _doc_function(sources[_DOC_RUNTIME])
        variants = [(_DOC_RUNTIME, b"# outside owner\n" + sources[_DOC_RUNTIME]),
                    (_DOC_RUNTIME, prefix + function.replace(b"maximum=262144", b"maximum=262145") + suffix),
                    (_DOC_RUNTIME, prefix + function + suffix + b"\n"),
                    (_DOC_TESTS, sources[_DOC_TESTS].replace(b"self.assertEqual", b"self.assertNotEqual", 1)),
                    (_DOC_TESTS, sources[_DOC_TESTS] + b"\n# resealed test change\n"),
                    ("src/harness_conformance/canonical.py", sources["src/harness_conformance/canonical.py"] + b"\n"),
                    (_DOC_GUIDE, sources[_DOC_GUIDE] + sources[_DOC_GUIDE].split(_DOC_BEGIN)[1])]
        for field in ("baselineCommit", "beforeSource"):
            changed_proof = deepcopy(proof)
            if field == "beforeSource":
                changed_proof["runtime"][field] += "# false before-image\n"
                changed_proof["runtime"]["beforeSha256"] = _doc_sha(changed_proof["runtime"][field].encode())
            else:
                changed_proof[field] = "0" * 40
            guide_prefix = sources[_DOC_GUIDE].split(_DOC_BEGIN)[0]
            changed_raw = json.dumps(changed_proof, sort_keys=True, separators=(",", ":")).encode()
            variants.append((_DOC_GUIDE, guide_prefix + _DOC_BEGIN + changed_raw + _DOC_END))
        for path, raw in variants:
            changed_rows, changed_sources = _doc_reseal(rows, sources, path, raw)
            with self.subTest(path=path, sha256=_doc_sha(raw)), self.assertRaises(ValueError):
                _doc_verify_sources(changed_rows, changed_sources)
        changed = dict(sources)
        changed[_DOC_RUNTIME] += b"# stale current bytes\n"
        with self.assertRaises(ValueError):
            _doc_verify_sources(rows, changed)

    def test_consumer_history_preserved(self):
        rows, sources = _doc_current_sources()
        proof = _doc_verify_sources(rows, sources)
        self.assertEqual(len(proof["baselineFiles"]), 135)
        self.assertEqual(sum(map(len, proof["baselineTestIds"].values())), 1277)
        self.assertEqual(set(proof["allowedPaths"]), {_DOC_RUNTIME, _DOC_TESTS, _DOC_GUIDE})
        stage3 = json.loads(sources["fixtures/platform/linux-baseline/successor-inventory.json"])["record"]["stages"][2]["paths"]
        self.assertLessEqual(set(proof["allowedPaths"]), set(stage3))
        from _inventory import SUCCESSOR
        observed = {}
        roots = ("tests/meta", "tests/parity", "tests/alpha1", "tests/fixes/runner_boundary",
                 "tests/platform/linux_baseline", "tests/live_backend")
        for root in roots:
            observed.update({root + "/" + p: ids for p, ids in SUCCESSOR.discover_inventory(ROOT / root).items()})
        self.assertEqual(observed, _doc_ids(sources))
        self.assertEqual(sum(map(len, observed.values())), 1309)
        self.assertEqual(sum(len(ids) for p, ids in observed.items() if p.startswith("tests/live_backend/")), 1139)
