from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from crypto_utils import enc
from election import ElectionEnvironment
from main import SCENARIOS, TerminalApplication


def application_with_vote() -> TerminalApplication:
    app = TerminalApplication()
    app.environment = ElectionEnvironment(app.accounts)
    student_id = "studente-001"
    voter = app.environment.new_voter()
    voter.authenticate(app.environment.idp, student_id, app.accounts[student_id])
    request = voter.prepare_cast(1)
    receipt = app.environment.collector.cast(request)
    app.voters[student_id] = voter
    app.requests[student_id] = request
    app.receipts[student_id] = receipt
    return app


def snapshot(app: TerminalApplication) -> tuple:
    environment = app.environment
    published = [environment.manifest, environment.collector.entries]
    for value in (
        environment.collector.final_root, environment.mix_result, environment.tally_result,
    ):
        if value is not None:
            published.append(value)
    published.extend([app.requests, app.receipts])
    return (
        id(environment), environment.phase, environment.now, enc(published),
        tuple(environment.idp.serial_for_student(identity) for identity in app.accounts),
        tuple(app.voters),
    )


class MenuTests(unittest.TestCase):

    def test_scenarios_reject_without_changing_current_election(self) -> None:
        app = application_with_vote()
        environment = app.environment
        environment.finalize_board(at_time=environment.manifest.body.closes_at)
        environment.mix_ballots()
        environment.tally_votes()
        original = snapshot(app)
        output = io.StringIO()
        with redirect_stdout(output):
            for name, _ in SCENARIOS:
                with self.subTest(scenario=name):
                    self.assertTrue(app.run_scenario(name, "studente-001"))
                    self.assertEqual(snapshot(app), original)
        self.assertEqual(output.getvalue().count("Rifiuto atteso:"), len(SCENARIOS))

    def test_scenarios_require_the_current_election_and_its_data(self) -> None:
        app = TerminalApplication()
        with redirect_stdout(io.StringIO()):
            for name, _ in SCENARIOS:
                with self.subTest(scenario=name):
                    self.assertFalse(app.run_scenario(name))
                    self.assertIsNone(app.environment)
        app = TerminalApplication()
        app.environment = ElectionEnvironment(app.accounts)
        environment = app.environment
        original = snapshot(app)
        with redirect_stdout(io.StringIO()):
            for name, _ in SCENARIOS:
                if name != "wrong_password":
                    with self.subTest(scenario=name):
                        self.assertFalse(app.run_scenario(name))
                        self.assertEqual(snapshot(app), original)
            self.assertTrue(app.run_scenario("wrong_password"))
            self.assertEqual(snapshot(app), original)

        app = application_with_vote()
        environment = app.environment
        with redirect_stdout(io.StringIO()):
            original = snapshot(app)
            self.assertFalse(app.run_scenario("tampered_proof"))
            self.assertEqual(snapshot(app), original)
            environment.finalize_board(at_time=environment.manifest.body.closes_at)
            original = snapshot(app)
            for name in ("tampered_mix", "tampered_tally", "insufficient_quorum"):
                self.assertFalse(app.run_scenario(name))
                self.assertEqual(snapshot(app), original)
            environment.mix_ballots()
            original = snapshot(app)
            self.assertFalse(app.run_scenario("tampered_tally"))
            self.assertTrue(app.run_scenario("insufficient_quorum"))
            self.assertEqual(snapshot(app), original)
