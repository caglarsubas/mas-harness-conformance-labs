"""TG-05 verdicts (W04-4a, CONF-ENF-004): the evaluator judged on synthetic timelines and answer logs.

Each case gets the implementation it must pass and the implementations it is meant to catch: a gate whose timer is paused by
a stalled CPython role, stops in suspend, follows the wall clock or restarts with the reader; a gate that refuses for the
wrong reason, rebinds the tested execution or lets a restarted broker reconnect into the dead generation; a reader that
keeps serving after its peer died, rebinds to the restarted peer, resurrects its old execution after a restart, or cannot
serve a fresh one. The answers follow the I05 v3 model: one channel and one bound execution at a time per generation; a
fresh execution is bound after the tested one ends, or in a new generation once the old one is held or closed. A check
never passes on answers for another execution, outside its window, for an execution that was not bound and live at the
fault, or from a run whose fault did not take effect (design reviews D1 to D5).
"""
from __future__ import annotations

import json
import unittest

from tg05_clocks import _verdicts as v

S = 1_000_000_000
BOOT = "4f1c0d2e-8a6b-4c39-9e57-0b8d3a2f6c14"
TREE = "f" * 64
DEADLINE = 1_000 * S
POLICY = "sha256:" + "1" * 64


def clocks(boottime, monotonic=None):
    return {"realtime": 1_791_000_000 * S + boottime, "monotonic": boottime if monotonic is None else monotonic,
            "boottime": boottime}


def line(kind, **fields):
    return json.dumps(dict({"schemaVersion": v.TIMELINE, "kind": kind}, **fields))


def binding(**extra):
    return dict({"route": "W06-TEST-ROUTE", "policyDigest": POLICY, "expiresAt": "2026-10-14T00:00:00Z", "execution": "E1"},
                **extra)


def timeline(case, records, bound=None, fault_result="PASS", tree=TREE, boot=BOOT, deadline=True):
    head = [line("start", case=case, arch="x86_64", bootId=boot, probeTree=tree, binding=bound or binding(), clocks=clocks(0))]
    if deadline:
        head.append(line("deadline", expiresAt="2026-10-14T00:00:00Z", boottime=DEADLINE, clocks=clocks(0)))
    return head + list(records) + [line("end", faultResult=fault_result, reason=None if fault_result == "PASS" else "EPERM")]


def answer(sent, party, value, execution="E1", reason=None, generation="G1", answered=None, boot=BOOT, operation=None):
    if reason is None and value in ("REFUSED", "CLOSED"):
        reason = "EXECUTION_EXPIRED"
    operation = operation or ("HTTP_REQUEST" if party == "GATE" else "REQUEST")
    return json.dumps({"schemaVersion": v.ANSWERS, "bootId": boot, "sentBoottime": sent,
                       "answeredBoottime": sent + 1000 if answered is None else answered, "party": party,
                       "operation": operation, "execution": execution, "generation": generation,
                       "request": "%s:%s:%s@%d" % (party, operation, execution, sent), "answer": value, "reason": reason})


def bind(sent, execution, generation, value="ALLOWED", reason=None):
    return answer(sent, "GATE", value, execution=execution, generation=generation, operation="BIND_EXECUTION", reason=reason)


def live(at):
    """The broker's channel opens G1, the tested execution is bound in it, allowed by the gate and served by the reader
    shortly before a fault (the driver logs the opening and the bind: reviews R2-1, R3-1)."""
    return [channel((at - 6) * S, "G1"), bind((at - 5) * S, "E1", "G1"), answer(at * S, "GATE", "ALLOWED"),
            answer(at * S, "SERVER", "SERVED")]


def channel(sent, generation, value="ALLOWED", reason=None):
    """A channel opening: it names the generation it opens, and the placeholder execution "-"."""
    return answer(sent, "GATE", value, execution="-", generation=generation, operation="CHANNEL_OPEN", reason=reason)


def close(sent, generation):
    return answer(sent, "GATE", "ALLOWED", execution="-", generation=generation, operation="CLOSE_GENERATION")


def case_result(case, runs):
    return v.judge_case(case, runs, TREE)


def results(verdict):
    return [(check["id"], check["result"]) for check in verdict["checks"]], verdict["result"]


STALL = [line("fault", fault="SIGSTOP", pids=[11, 12], applied=True, clocks=clocks(900 * S)),
         line("observation", name="exitedDuringStall", value=[12], clocks=clocks(1_060 * S)),
         line("fault", fault="SIGCONT", applied=True, clocks=clocks(1_060 * S))]


class StalledPython(unittest.TestCase):
    case = "MATRIX:expiry with stalled Python"

    def judge(self, answers, records=STALL, before=None):
        return case_result(self.case, [(timeline(self.case, records), (live(890) if before is None else before) + answers)])

    def test_the_resumed_role_finds_the_authority_already_ended(self):
        self.assertEqual(results(self.judge([answer(1_065 * S, "GATE", "REFUSED")])), ([("E08-STALLED", "PASS")], "PASS"))

    def test_a_timer_paused_by_the_stall_fails(self):
        self.assertEqual(self.judge([answer(1_065 * S, "GATE", "ALLOWED")])["result"], "FAIL")

    def test_a_refusal_for_a_later_checks_reason_fails(self):
        # Review D2-1: the I05 v3 model refuses an expired execution before any stamp check.
        self.assertEqual(self.judge([answer(1_065 * S, "GATE", "REFUSED", reason="STAMP_NONE")])["result"], "FAIL")

    def test_after_a_new_execution_is_bound_any_refusal_of_the_old_one_stands_but_never_an_allowance(self):
        # Review D3-1: I05 v3 binds a new execution after expiry (T36); the old one is then refused as not bound.
        replaced = [answer(1_065 * S, "GATE", "REFUSED"), bind(1_070 * S, "E2", "G1"),
                    answer(1_080 * S, "GATE", "REFUSED", reason="STAMP_MISMATCH")]
        self.assertEqual(self.judge(replaced)["result"], "PASS")
        self.assertEqual(self.judge(replaced[:2] + [answer(1_080 * S, "GATE", "ALLOWED")])["result"], "FAIL")
        self.assertEqual(self.judge(replaced[1:])["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_new_execution_bound_between_the_fault_and_the_window_is_a_replacement(self):
        # Review D4-2: the replacement counts from the fault, so the old execution's later STAMP_MISMATCH does not fail.
        early = [bind(950 * S, "E2", "G1"), answer(1_065 * S, "GATE", "REFUSED", reason="STAMP_MISMATCH")]
        self.assertEqual(self.judge(early)["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_generation_turned_over_at_expiry_is_judged_on_the_model_refusals(self):
        # Reviews D5-2, D5-3: the broker closes G1 and opens G2; the channel is neither judged by execution nor a
        # replacement, and an ARM of the old execution in G2 is refused EXECUTION_NOT_BOUND by the model.
        turnover = [close(1_001 * S, "G1"), channel(1_002 * S, "G2"),
                    answer(1_065 * S, "GATE", "REFUSED", reason="EXECUTION_NOT_BOUND", generation="G2", operation="ARM_ACTION")]
        self.assertEqual(self.judge(turnover)["result"], "PASS")

    def test_a_channel_reopened_into_the_tested_generation_fails(self):
        # Review D5-2: one channel per generation (T38).
        self.assertEqual(self.judge([answer(1_065 * S, "GATE", "REFUSED"), channel(1_070 * S, "G1")])["result"], "FAIL")

    def test_a_refused_rebind_of_the_expired_execution_stands_but_proves_nothing_alone(self):
        # Review D4-2: the model refuses a second BIND NOT_ACTIVE, ACTION_OUTSTANDING or EXECUTION_REPLAY first.
        rebinds = [bind(1_064 * S, "E1", "G1", "REFUSED", "EXECUTION_REPLAY"), bind(1_066 * S, "E1", "G1", "REFUSED", "ACTION_OUTSTANDING")]
        self.assertEqual(self.judge(rebinds)["result"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(self.judge(rebinds + [answer(1_065 * S, "GATE", "REFUSED")])["result"], "PASS")
        self.assertEqual(self.judge([bind(1_064 * S, "E1", "G1", "REFUSED", "STAMP_NONE"),
                                     answer(1_065 * S, "GATE", "REFUSED")])["result"], "FAIL")

    def test_answers_for_another_execution_are_not_judged(self):
        self.assertEqual(self.judge([answer(1_065 * S, "GATE", "REFUSED", execution="E9")])["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_answers_outside_the_paused_timers_window_are_not_judged_but_an_allowance_after_the_deadline_fails(self):
        # Review D3-4: only an exchange wholly inside the window, a margin inside each end, can carry a PASS.
        late = [answer(1_060 * S + S // 2, "GATE", "REFUSED", reason="STAMP_NONE"), answer(1_200 * S, "GATE", "REFUSED"),
                answer(1_158 * S + S // 2, "GATE", "REFUSED", answered=1_160 * S)]
        self.assertEqual(self.judge(late)["result"], "NOT_RUN_ENV_UNAVAILABLE")
        # Review R1-3: no conforming gate allows the tested execution after its deadline, inside the window or not.
        for sent in (1_030 * S, 1_200 * S, 5_000 * S):
            with self.subTest(sent=sent):
                self.assertEqual(self.judge([answer(1_065 * S, "GATE", "REFUSED"), answer(sent, "GATE", "ALLOWED")])["result"], "FAIL")

    def test_an_execution_not_bound_and_live_at_the_stall_is_not_the_case(self):
        # Reviews D3-2, D4-5: never allowed by the gate, refused or replaced before the stall, or allowed too long before it.
        for index, before in enumerate(([answer(890 * S, "SERVER", "SERVED")],
                                        live(880) + [answer(895 * S, "GATE", "REFUSED", reason="NOT_ACTIVE")],
                                        live(880) + [bind(895 * S, "E0", "G1")], live(800))):
            with self.subTest(index=index):
                self.assertEqual(self.judge([answer(1_065 * S, "GATE", "REFUSED")], before=before)["result"],
                                 "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_stall_after_the_deadline_is_not_the_case(self):
        late = [line("fault", fault="SIGSTOP", pids=[11], applied=True, clocks=clocks(1_001 * S)),
                line("fault", fault="SIGCONT", applied=True, clocks=clocks(1_060 * S))]
        self.assertEqual(self.judge([answer(1_065 * S, "GATE", "REFUSED")], late)["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_fault_that_did_not_take_effect_is_never_pass(self):
        verdict = case_result(self.case, [(timeline(self.case, STALL, fault_result="NOT_RUN_ENV_UNAVAILABLE"),
                                           live(890) + [answer(1_065 * S, "GATE", "REFUSED")])])
        self.assertEqual((verdict["checks"], verdict["result"]), ([], "NOT_RUN_ENV_UNAVAILABLE"))


SUSPEND = [line("fault", fault="SUSPEND", applied=True, suspendedNs=599 * S, clocksBefore=clocks(500 * S),
                clocks=clocks(1_100 * S, monotonic=501 * S))]


class Suspend(unittest.TestCase):
    case = "MATRIX:suspend"

    def judge(self, answers, records=SUSPEND):
        return case_result(self.case, [(timeline(self.case, records), live(490)[:3] + answers)])

    def test_suspended_time_counts(self):
        self.assertEqual(results(self.judge([answer(1_102 * S, "GATE", "REFUSED")])), ([("E08-SUSPEND", "PASS")], "PASS"))

    def test_a_timer_that_stops_in_suspend_fails(self):
        self.assertEqual(self.judge([answer(1_102 * S, "GATE", "ALLOWED")])["result"], "FAIL")

    def test_answers_after_a_stopped_timer_would_also_have_expired_are_not_judged(self):
        # Review D2-3/D3-4: past resume + (deadline - suspend) - awake even a MONOTONIC timer refuses.
        straddling = answer(1_597 * S, "GATE", "REFUSED", answered=1_600 * S)
        self.assertEqual(self.judge([answer(1_900 * S, "GATE", "REFUSED"), straddling])["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_deadline_inside_the_awake_entry_or_exit_is_not_the_case(self):
        awake_long = [line("fault", fault="SUSPEND", applied=True, suspendedNs=100 * S, clocksBefore=clocks(500 * S),
                           clocks=clocks(1_100 * S, monotonic=1_000 * S))]
        self.assertEqual(self.judge([answer(1_102 * S, "GATE", "REFUSED")], awake_long)["result"], "NOT_RUN_ENV_UNAVAILABLE")


ROLLBACK = [line("fault", fault="CLOCK_SET", applied=True, rolledBackNs=4_300 * S, clocks=clocks(600 * S)),
            line("observation", name="rolledBackAtRestore", value=4_300 * S, clocks=clocks(1_060 * S)),
            line("restore", what="CLOCK_SET", done=True, clocks=clocks(1_061 * S))]


class WallClockRollback(unittest.TestCase):
    case = "MATRIX:wall-clock rollback"

    def judge(self, answers, records=ROLLBACK):
        return case_result(self.case, [(timeline(self.case, records), live(590)[:3] + answers)])

    def test_a_wall_clock_step_does_not_extend_the_deadline(self):
        self.assertEqual(results(self.judge([answer(1_010 * S, "GATE", "REFUSED")])), ([("E08-ROLLBACK", "PASS")], "PASS"))

    def test_a_gate_that_trusts_the_wall_clock_fails(self):
        self.assertEqual(self.judge([answer(1_010 * S, "GATE", "ALLOWED")])["result"], "FAIL")

    def test_the_window_ends_at_the_last_reading_while_the_clock_was_behind(self):
        # Review D3-4: an answer after that reading may already see the restored clock.
        self.assertEqual(self.judge([answer(1_059 * S + S // 2, "GATE", "REFUSED")])["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_clock_that_did_not_stay_back_is_not_the_case(self):
        moved = ROLLBACK[:1] + [line("observation", name="rolledBackAtRestore", value=0, clocks=clocks(1_060 * S))] + ROLLBACK[2:]
        self.assertEqual(self.judge([answer(1_010 * S, "GATE", "REFUSED")], moved)["result"], "NOT_RUN_ENV_UNAVAILABLE")


def peer_run(peer, answers, restart=True, killed=500, role=None):
    records = [line("fault", fault="SIGKILL", role=role or peer, pid=21, startTicks=500, applied=True, clocks=clocks(killed * S))]
    if restart:
        records.append(line("observation", name="restarted", value={"role": peer, "pid": 31, "startTicks": 900},
                            clocks=clocks((killed + 20) * S)))
    return timeline("MATRIX:peer death/restart", records, binding(peer=peer)), answers


def broker_answers(after_restart=None, extra=()):
    """Broker killed at 500 s, restarted at 520 s. Before the restart the held generation refuses the tested execution and
    the reader fails it; after the restart the same, the restarted broker's channel into the dead G1 is refused, it opens
    G2, a fresh execution E2 is bound and served there, and a rebind of E1 in G2 is refused as a replay."""
    after = [answer(525 * S, "GATE", "REFUSED", reason="NOT_ACTIVE"), answer(525 * S, "SERVER", "FAILED")] \
        if after_restart is None else after_restart
    return (live(490) + [answer(505 * S, "GATE", "REFUSED", reason="NOT_ACTIVE"), answer(505 * S, "SERVER", "FAILED")] + after
            + [channel(530 * S, "G1", "REFUSED", "GENERATION_CHANNEL_USED"), channel(532 * S, "G2"), bind(535 * S, "E2", "G2"),
               answer(540 * S, "SERVER", "SERVED", execution="E2", generation="G2"),
               bind(545 * S, "E1", "G2", "REFUSED", "EXECUTION_REPLAY")] + list(extra))


def observer_answers(after_restart=None, fresh=None):
    """Observer killed at 600 s, restarted at 620 s; the gate is untouched. The reader fails the tested execution before and
    after the restart; the driver then closes G1, opens G3 and binds a fresh execution E3, which is served."""
    after = [answer(625 * S, "SERVER", "FAILED")] if after_restart is None else after_restart
    fresh = [close(627 * S, "G1"), channel(628 * S, "G3"), bind(630 * S, "E3", "G3"),
             answer(640 * S, "SERVER", "SERVED", execution="E3", generation="G3")] if fresh is None else fresh
    return live(590) + [answer(605 * S, "SERVER", "FAILED")] + after + fresh


class PeerDeathRestart(unittest.TestCase):
    case = "MATRIX:peer death/restart"

    def judge(self, broker=None, observer=None, **options):
        return case_result(self.case, [peer_run("BROKER", broker_answers() if broker is None else broker, **options),
                                       peer_run("OBSERVER", observer_answers() if observer is None else observer, killed=600)])

    def test_a_dead_peer_denies_and_the_reader_fails_sticky_and_serves_a_fresh_execution(self):
        self.assertEqual(results(self.judge()), ([("E07-GATE", "PASS"), ("E07-READER-BROKER", "PASS"),
                                                  ("E09-INSPECTION-BROKER", "PASS"), ("E07-READER-OBSERVER", "PASS"),
                                                  ("E09-INSPECTION-OBSERVER", "PASS")], "PASS"))

    def test_nothing_judged_after_the_restart_shows_nothing_about_reconnects(self):
        # Review D5-1: before the restart there is no peer, so any gate or reader fails the tested execution.
        verdict = self.judge(broker=broker_answers(after_restart=[]), observer=observer_answers(after_restart=[]))
        self.assertEqual([check["result"] for check in verdict["checks"] if check["id"].startswith("E07")],
                         ["NOT_RUN_ENV_UNAVAILABLE"] * 3)

    def test_a_gate_that_lets_the_restarted_broker_reconnect_into_the_dead_generation_fails(self):
        # Review D5-2: one channel per generation (T38).
        reconnect = broker_answers(extra=[channel(550 * S, "G1")])
        self.assertEqual(self.judge(broker=reconnect)["checks"][0]["result"], "FAIL")

    def test_rows_without_a_real_generation_are_refused_so_a_reconnect_is_never_passed_unjudged(self):
        # Reviews D6-1 (runs A, A2) and R1-1: the restarted broker reconnects into the dead G1. Before the fix these PASSed:
        # run A labels the tested execution's rows with no generation, run A2 names G1 only on its bind, and the R1-1
        # variants use an empty, blank or placeholder generation. Each is now malformed and recorded NOT_RUN.
        for label in ("null", '""', '" "', '"-"'):
            with self.subTest(label=label):
                rows = [row.replace('"execution": "E1", "generation": "G1"', '"execution": "E1", "generation": %s' % label)
                        for row in broker_answers(extra=[channel(550 * S, "G1")])]
                if label == "null":
                    rows.insert(0, bind(440 * S, "E1", "G1"))                         # run A2 keeps G1 on the bind
                recorded = v.verdict(self.case, [peer_run("BROKER", rows), peer_run("OBSERVER", observer_answers(), killed=600)], TREE)
                self.assertEqual(recorded["result"], "NOT_RUN_ENV_UNAVAILABLE")
                self.assertIn("generation", recorded["reason"])
        reconnect = broker_answers(extra=[channel(550 * S, "G1")])
        self.assertEqual(self.judge(broker=reconnect)["checks"][0]["result"], "FAIL")

    def test_the_dead_generation_comes_from_the_bind_whatever_word_the_rows_carry(self):
        # Review R2-1: with placeholder words on the tested execution's rows a reconnect into G1 must not PASS, and a
        # conforming gate must not FAIL; rows that disagree with the bind, or a missing bind, leave E07-GATE NOT_RUN.
        for word in ("None", "null", "unknown", "NA", "0"):
            with self.subTest(word=word):
                rows = [row.replace('"operation": "HTTP_REQUEST", "execution": "E1", "generation": "G1"',
                                    '"operation": "HTTP_REQUEST", "execution": "E1", "generation": "%s"' % word)
                        for row in broker_answers(extra=[channel(550 * S, "G1")])]
                self.assertNotEqual(self.judge(broker=rows)["checks"][0]["result"], "PASS")
                conforming = [row.replace('"operation": "HTTP_REQUEST", "execution": "E1", "generation": "G1"',
                                          '"operation": "HTTP_REQUEST", "execution": "E1", "generation": "%s"' % word)
                              for row in broker_answers()]
                self.assertEqual(self.judge(broker=conforming)["checks"][0]["result"], "NOT_RUN_ENV_UNAVAILABLE")
        no_bind = [row for row in broker_answers() if '"operation": "BIND_EXECUTION", "execution": "E1", "generation": "G1"' not in row]
        self.assertEqual(self.judge(broker=no_bind)["checks"][0]["result"], "NOT_RUN_ENV_UNAVAILABLE")
        # Review R3-1: a second allowed opening of G1 FAILs even without the bind.
        self.assertEqual(self.judge(broker=no_bind + [channel(550 * S, "G1")])["checks"][0]["result"], "FAIL")

    def test_the_dead_generation_must_be_established_by_one_bind_in_a_logged_opening(self):
        # Review R3-1 (run A3): the bind and the rows carry the same placeholder word; two allowed binds; every execution
        # row labelled None by the driver. None of these PASSes a reconnect or FAILs a conforming gate.
        def relabel(rows, word):
            return [row.replace('"execution": "E1", "generation": "G1"', '"execution": "E1", "generation": "%s"' % word) for row in rows]
        for word in ("None", "unknown", "0"):
            with self.subTest(word=word):
                self.assertEqual(self.judge(broker=relabel(broker_answers(extra=[channel(550 * S, word)]), word))["checks"][0]["result"],
                                 "FAIL")                                              # a second opening of that "generation"
                self.assertEqual(self.judge(broker=relabel(broker_answers(), word))["checks"][0]["result"], "NOT_RUN_ENV_UNAVAILABLE")
        two_binds = broker_answers()[:2] + [bind(487 * S, "E1", "G1")] + broker_answers()[2:]
        self.assertEqual(self.judge(broker=two_binds)["checks"][0]["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_second_allowed_opening_of_a_generation_fails_whatever_the_labels(self):
        # Review R3-1: one channel per generation (T38).
        self.assertEqual(self.judge(broker=broker_answers(extra=[channel(560 * S, "G2")]))["checks"][0]["result"], "FAIL")

    def test_a_channel_attempt_only_after_the_deadline_is_not_the_case(self):
        # Reviews R2-3, R3-4: the schedule puts the restarted broker's attempt before the tested execution's requests.
        late = [row for row in broker_answers() if '"operation": "CHANNEL_OPEN", "execution": "-", "generation": "G1", "request": "GATE:CHANNEL_OPEN:-@530' not in row
                and '"generation": "G2", "request": "GATE:CHANNEL_OPEN:-@532' not in row] + [channel(1_200 * S, "G9")]
        self.assertEqual(self.judge(broker=late)["checks"][0]["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_violation_that_needs_no_generation_fails_even_without_a_bind(self):
        # Review R3-2: an allowance after the kill, or a refusal for an unrelated reason, FAILs before the generation matters.
        no_bind = [row for row in broker_answers() if '"operation": "BIND_EXECUTION", "execution": "E1"' not in row]
        self.assertEqual(self.judge(broker=no_bind + [answer(560 * S, "GATE", "ALLOWED", generation="G2")])["checks"][0]["result"], "FAIL")
        unrelated = [row.replace('"reason": "NOT_ACTIVE"', '"reason": "STAMP_NONE"') for row in no_bind]
        self.assertEqual(self.judge(broker=unrelated)["checks"][0]["result"], "FAIL")

    def test_anything_allowed_in_the_dead_generation_after_the_kill_fails(self):
        # Review R1-2: the held generation allows nothing after the broker's death, whatever the operation or execution.
        for extra in ([bind(550 * S, "E5", "G1")],
                      [answer(550 * S, "GATE", "ALLOWED", execution="-", operation="GENERATION_STATUS")],
                      [answer(550 * S, "GATE", "ALLOWED", execution="E5", operation="ARM_ACTION")]):
            with self.subTest(extra=json.loads(extra[0])["operation"]):
                self.assertEqual(self.judge(broker=broker_answers(extra=extra))["checks"][0]["result"], "FAIL")

    def test_without_a_logged_channel_attempt_of_the_restarted_broker_the_gate_part_is_not_run(self):
        # Review R1-2: a reconnect shows only in that attempt; review R2-2: a visible use of the dead generation still FAILs.
        rows = [row for row in broker_answers() if '"operation": "CHANNEL_OPEN"' not in row]
        self.assertEqual(self.judge(broker=rows)["checks"][0]["result"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(self.judge(broker=rows + [bind(550 * S, "E5", "G1")])["checks"][0]["result"], "FAIL")

    def test_violations_after_the_window_still_fail(self):
        # Review R1-3: an allowance after the broker's death, a reconnect after the deadline, the reader serving the
        # tested execution after its deadline; no conforming implementation answers so.
        self.assertEqual(self.judge(broker=broker_answers(extra=[answer(1_200 * S, "GATE", "ALLOWED", generation="G2")]))["checks"][0]["result"], "FAIL")
        self.assertEqual(self.judge(broker=broker_answers(extra=[channel(1_200 * S, "G1")]))["checks"][0]["result"], "FAIL")
        self.assertEqual(self.judge(observer=observer_answers(fresh=observer_answers()[5:] + [answer(1_200 * S, "SERVER", "SERVED")]))["checks"][3]["result"], "FAIL")

    def test_a_gate_that_rebinds_the_execution_fails(self):
        self.assertEqual(self.judge(broker=broker_answers(extra=[bind(550 * S, "E1", "G2")]))["checks"][0]["result"], "FAIL")

    def test_an_arm_of_the_old_execution_in_the_new_generation_is_refused_not_bound(self):
        # Review D5-3: the model refuses it EXECUTION_NOT_BOUND.
        arm = [answer(525 * S, "GATE", "REFUSED", reason="EXECUTION_NOT_BOUND", generation="G2", operation="ARM_ACTION"),
               answer(525 * S, "SERVER", "FAILED")]
        self.assertEqual(self.judge(broker=broker_answers(after_restart=arm))["result"], "PASS")

    def test_a_gate_refusal_for_an_unrelated_reason_fails(self):
        unrelated = [answer(525 * S, "GATE", "REFUSED", reason="STAMP_NONE"), answer(525 * S, "SERVER", "FAILED")]
        self.assertEqual(self.judge(broker=broker_answers(after_restart=unrelated))["checks"][0]["result"], "FAIL")

    def test_a_reader_that_rebinds_to_the_restarted_peer_fails(self):
        rebinds = [answer(525 * S, "GATE", "REFUSED", reason="NOT_ACTIVE"), answer(525 * S, "SERVER", "SERVED")]
        self.assertEqual(self.judge(broker=broker_answers(after_restart=rebinds))["result"], "FAIL")
        self.assertEqual(self.judge(observer=observer_answers(after_restart=[answer(625 * S, "SERVER", "SERVED")]))["result"], "FAIL")

    def test_reader_answers_after_the_deadline_or_the_replacement_are_not_judged(self):
        # Reviews D3-3, D4-4: after the tested execution's deadline, or once the gate bound another one, even a reader the
        # check is meant to catch fails the old execution; nothing is shown there.
        late = observer_answers(after_restart=[answer(1_100 * S, "SERVER", "FAILED")])
        self.assertEqual(self.judge(observer=late)["checks"][3]["result"], "NOT_RUN_ENV_UNAVAILABLE")
        after_bind = observer_answers(after_restart=[], fresh=[close(627 * S, "G1"), channel(628 * S, "G3"), bind(630 * S, "E3", "G3"),
                                                             answer(635 * S, "SERVER", "FAILED"),
                                                             answer(640 * S, "SERVER", "SERVED", execution="E3", generation="G3")])
        self.assertEqual(self.judge(observer=after_bind)["checks"][3]["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_reader_that_cannot_inspect_the_restarted_peer_fails(self):
        broken = observer_answers(fresh=[close(627 * S, "G1"), channel(628 * S, "G3"), bind(630 * S, "E3", "G3"),
                                         answer(640 * S, "SERVER", "FAILED", execution="E3", generation="G3")])
        self.assertEqual(self.judge(observer=broken)["checks"][-1]["result"], "FAIL")

    def test_an_execution_the_gate_did_not_bind_after_the_restart_is_not_fresh(self):
        # Reviews D2-2, D4-3, D5-2: an execution seen before the restart, one whose bind was refused, or one only named in
        # a channel opening shows nothing.
        for fresh in ([answer(300 * S, "SERVER", "SERVED", execution="E0"), answer(640 * S, "SERVER", "SERVED", execution="E0")],
                      [bind(630 * S, "E3", "G3", "REFUSED", "WORKER_NOT_OBSERVED"),
                       answer(640 * S, "SERVER", "FAILED", execution="E3", generation="G3")],
                      [channel(628 * S, "G3"), answer(640 * S, "SERVER", "FAILED", execution="E3", generation="G3")]):
            with self.subTest(fresh=len(fresh)):
                self.assertEqual(self.judge(observer=observer_answers(fresh=fresh))["checks"][-1]["result"],
                                 "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_fresh_executions_answers_end_when_another_is_bound(self):
        # Review D5-7: after the next bind even a working reader may fail the earlier fresh execution.
        two = [close(627 * S, "G1"), channel(628 * S, "G3"), bind(630 * S, "E3", "G3"), bind(635 * S, "E4", "G3"),
               answer(640 * S, "SERVER", "FAILED", execution="E3", generation="G3"),
               answer(645 * S, "SERVER", "SERVED", execution="E4", generation="G3")]
        self.assertEqual(self.judge(observer=observer_answers(fresh=two))["checks"][-1]["result"], "PASS")

    def test_the_gate_is_judged_only_for_the_broker(self):
        verdict = v.judge_run(*peer_run("OBSERVER", observer_answers(), killed=600), TREE)
        self.assertEqual([check["id"] for check in verdict["checks"]], ["E07-READER-OBSERVER", "E09-INSPECTION-OBSERVER"])

    def test_one_peers_run_alone_is_not_the_case(self):
        self.assertEqual(case_result(self.case, [peer_run("BROKER", broker_answers())])["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_without_a_restart_nothing_is_judged(self):
        verdict = self.judge(restart=False)
        self.assertEqual([check["result"] for check in verdict["checks"][:3]], ["NOT_RUN_ENV_UNAVAILABLE"] * 3)
        # Review D6-8: each check keeps its own rule.
        self.assertEqual([check["rule"] for check in verdict["checks"][:3]], [v.PEER_GATE, v.PEER_READER, v.PEER_INSPECTION])

    def test_an_execution_not_bound_or_served_at_the_kill_is_not_the_case(self):
        verdict = self.judge(broker=broker_answers()[4:])
        self.assertEqual([check["result"] for check in verdict["checks"][:2]], ["NOT_RUN_ENV_UNAVAILABLE"] * 2)

    def test_the_killed_role_must_be_the_bindings_peer(self):
        with self.assertRaises(v.Malformed):
            case_result(self.case, [peer_run("BROKER", broker_answers(), role="OBSERVER")])


ORIGINAL = [line("fault", fault="SIGKILL", role="SERVER", pid=11, startTicks=100, applied=True, clocks=clocks(500 * S)),
            line("observation", name="restarted", value={"role": "SERVER", "pid": 41, "startTicks": 700}, clocks=clocks(510 * S))]
# The tested execution stays bound until its deadline; the fresh one is bound only after it (one bound execution at a time).
GOOD_ORIGINAL = live(490) + [answer(520 * S, "SERVER", "FAILED"), answer(1_005 * S, "GATE", "REFUSED"),
                             bind(1_020 * S, "E2", "G1"), answer(1_030 * S, "SERVER", "SERVED", execution="E2")]


class OriginalDeadlines(unittest.TestCase):
    case = "MATRIX:original deadlines"

    def judge(self, answers=GOOD_ORIGINAL):
        return case_result(self.case, [(timeline(self.case, ORIGINAL), answers)])

    def test_a_restart_renews_nothing_and_resurrects_nothing(self):
        self.assertEqual(results(self.judge()), ([("E08-ORIGINAL", "PASS"), ("E11-STALE", "PASS"), ("E09-CONSTRUCTION", "PASS")],
                                                 "PASS"))

    def test_a_deadline_renewed_by_the_restart_fails(self):
        renewed = live(490) + [GOOD_ORIGINAL[4], answer(1_005 * S, "GATE", "ALLOWED")] + GOOD_ORIGINAL[6:]
        self.assertEqual(self.judge(renewed)["checks"][0]["result"], "FAIL")

    def test_a_reader_that_resumes_its_old_execution_fails(self):
        resumed = live(490) + [answer(520 * S, "SERVER", "SERVED")] + GOOD_ORIGINAL[5:]
        self.assertEqual(self.judge(resumed)["checks"][1]["result"], "FAIL")

    def test_stale_answers_after_the_deadline_are_not_judged(self):
        # Review D3-3: the carried property is tested only before the tested execution's own deadline.
        late = live(490) + [answer(1_100 * S, "SERVER", "FAILED")] + GOOD_ORIGINAL[5:]
        self.assertEqual(self.judge(late)["checks"][1]["result"], "NOT_RUN_ENV_UNAVAILABLE")

    def test_a_reader_that_cannot_construct_after_the_restart_fails(self):
        broken = GOOD_ORIGINAL[:7] + [answer(1_030 * S, "SERVER", "FAILED", execution="E2")]
        self.assertEqual(self.judge(broken)["checks"][2]["result"], "FAIL")

    def test_the_killed_role_must_be_the_server(self):
        wrong = [ORIGINAL[0].replace('"role": "SERVER"', '"role": "BROKER"')] + ORIGINAL[1:]
        with self.assertRaises(v.Malformed):
            case_result(self.case, [(timeline(self.case, wrong), GOOD_ORIGINAL)])


GOOD_RUNS = {
    "MATRIX:expiry with stalled Python": (STALL, live(890) + [answer(1_065 * S, "GATE", "REFUSED")]),
    "MATRIX:suspend": (SUSPEND, live(490)[:3] + [answer(1_102 * S, "GATE", "REFUSED")]),
    "MATRIX:wall-clock rollback": (ROLLBACK, live(590)[:3] + [answer(1_010 * S, "GATE", "REFUSED")]),
    "MATRIX:original deadlines": (ORIGINAL, GOOD_ORIGINAL),
}


class Inputs(unittest.TestCase):
    def test_the_check_ids_are_the_cases(self):
        self.assertEqual(set(v.CHECKS), set(v.CASES))
        self.assertEqual(set(v.CHECKS), set(v.BINDING_KEYS))
        self.assertEqual(set(v.CHECKS), set(v.RECORDS))
        self.assertLessEqual(v.READER_CHECKS, {check for checks in v.CHECKS.values() for check in checks})

    def test_each_case_needs_every_record_it_lists_and_no_other(self):
        # Review D5-7: RECORDS is what the verdicts read; dropping one makes the run malformed, and a run holding only
        # those records is judged.
        def needed(record, kind, key):
            row = json.loads(record)
            return (row["kind"], row.get("fault", row.get("name", row.get("what")))) == (kind, key)
        for case, items in v.RECORDS.items():
            items = items + v.OPTIONAL_RECORDS.get(case, [])
            records, answers = GOOD_RUNS.get(case, (peer_run("BROKER", broker_answers())[0][2:-1], broker_answers()))
            kept = [record for record in records if any(needed(record, kind, key) for kind, key in items)]
            bound = binding(peer="BROKER") if case == "MATRIX:peer death/restart" else None
            with self.subTest(case=case, record="all"):
                self.assertEqual(v.judge_run(timeline(case, kept, bound), answers, TREE)["faultResult"], "PASS")
            for kind, key in v.RECORDS[case]:
                with self.subTest(case=case, record=(kind, key)):
                    dropped = [record for record in kept if not needed(record, kind, key)]
                    with self.assertRaises(v.Malformed):
                        v.judge_run(timeline(case, dropped, bound, deadline=kind != "deadline"), answers, TREE)

    def test_malformed_or_foreign_inputs_are_refused_not_judged(self):
        case = "MATRIX:suspend"
        good = timeline(case, SUSPEND)
        no_route = {"policyDigest": POLICY, "expiresAt": "2026-10-14T00:00:00Z", "execution": "E1"}
        bad_inputs = (
            (good[:-1], []),                                                          # no end record
            ([good[0].replace(v.TIMELINE, "other/v1")] + good[1:], []),               # wrong schema
            (timeline(case, SUSPEND, tree="0" * 64), []),                             # D2-8: not the reviewed probe tree
            (timeline(case, SUSPEND, boot=""), []),                                   # D2-8: no boot
            (timeline(case, SUSPEND, boot="boot-1"), []),                             # D3-6: not a boot ID
            (timeline(case, SUSPEND, bound=no_route), []),                            # Q-T14: no route
            (timeline(case, SUSPEND, bound=dict(no_route, route="x y")), []),         # malformed route
            (timeline(case, SUSPEND, bound=dict(no_route, route="R", policyDigest="sha256:1")), []),  # malformed digest
            (timeline(case, SUSPEND, bound=dict(no_route, route="R", peer="BROKER")), []),  # a key the case does not take
            (good, [answer(1_102 * S, "GATE", "SERVED")]),                            # a gate cannot serve
            (good, [answer(1_102 * S, "GATE", "REFUSED", operation="DELETE_EVERYTHING")]),  # D4-6: an unknown operation
            (good, [answer(1_102 * S, "SERVER", "FAILED", operation="HTTP_REQUEST")]),  # a reader exchange is a REQUEST
            (good, [answer(1_102 * S, "GATE", "ALLOWED", execution="-", generation=None, operation="CHANNEL_OPEN")]),  # D5-2
            (good, [answer(1_102 * S, "GATE", "REFUSED", generation=None)]),          # D6-1: a gate row names its generation
            (good, [answer(1_102 * S, "GATE", "REFUSED", boot="another-boot")]),      # BOOTTIME from another boot
            (good, [answer(1_102 * S, "GATE", "ALLOWED", reason="X")]),               # a reason on an allowed answer
            (good, [answer(1_102 * S, "GATE", "REFUSED")[:-1] + ', "extra": 1}']),    # closed fields
            (good, ['{"a": 1, "a": 2}']),                                             # duplicate key
            ([good[0].replace(case, "S8-FREEZE")] + good[1:], []),                    # no probe for this case
        )
        for index, (timeline_lines, answers) in enumerate(bad_inputs):
            with self.subTest(index=index), self.assertRaises(v.Malformed):
                case_result(case, [(timeline_lines, answers)])
        with self.assertRaises(v.Malformed):
            case_result("MATRIX:wall-clock rollback", [(good, [])])                  # a run of another case

    def test_a_malformed_case_of_any_shape_is_recorded_not_run_never_pass(self):
        # Reviews D4-7, D5-5: W06 records only AGENTS rule 14's results.
        case = "MATRIX:suspend"
        no_time = [line("deadline", expiresAt="2026-10-14T00:00:00Z", clocks=clocks(0))]
        shapes = ([(timeline(case, SUSPEND, tree="0" * 64), [])],
                  [(timeline(case, no_time + SUSPEND, deadline=False), [])],          # a deadline record without its time
                  [(timeline(case, SUSPEND), ['["not", "an", "object"]'])],
                  [(timeline(case, SUSPEND), ["[" * 100_000 + "]" * 100_000])])       # D6-7: deep nesting
        for index, runs in enumerate(shapes):
            with self.subTest(index=index):
                recorded = v.verdict(case, runs, TREE)
                self.assertEqual(recorded["result"], "NOT_RUN_ENV_UNAVAILABLE")
                self.assertIn("malformed input", recorded["reason"])


if __name__ == "__main__":
    unittest.main()
