"""Flusso del referendum, controlli delle registrazioni e risultati pubblici."""

from dataclasses import replace
from unittest import TestCase

from crypto_utils import (
    ThresholdError, ValidationError, enc, sign_object,
)
from election import ElectionEnvironment
from models import manifest_key, verify_manifest


def students(count: int) -> dict[str, str]:
    return {f"s{index}": "aps-test" for index in range(count)}


def cast_vote(environment: ElectionEnvironment, student_id: str, choice: int):
    voter = environment.new_voter()
    voter.authenticate(environment.idp, student_id, "aps-test")
    request = voter.prepare_cast(choice)
    receipt = environment.collector.cast(request)
    environment.verifier.verify_receipt_for_request(receipt, request)
    return voter, request, receipt


def close_board(environment: ElectionEnvironment):
    return environment.finalize_board(at_time=environment.manifest.body.closes_at)


class ProtocolTests(TestCase):

    def test_complete_flow_receipts_tally_and_public_audit(self):
        env = ElectionEnvironment(students(3))
        tampered = replace(env.manifest, body=replace(env.manifest.body, question="Quesito sostituito"))
        with self.assertRaises(ValidationError):
            verify_manifest(tampered, env.commission_manifest_public)
        with self.assertRaises(ValidationError):
            verify_manifest(env.manifest, manifest_key(env.manifest, "idp_signing"))
        with self.assertRaises(ValidationError):
            env.collector.finalize()
        self.assertFalse(env.collector.closed)
        votes = [cast_vote(env, f"s{i}", choice) for i, choice in enumerate((1, 0, 1))]
        root = close_board(env)
        for _, request, receipt in votes:
            index = receipt.body.index
            env.verifier.verify_individual(
                receipt, request, env.collector.entries[index], root, env.collector.proof(index)
            )
        wrong_request, receipt = votes[1][1], votes[0][2]
        with self.assertRaises(ValidationError):
            env.verifier.verify_receipt_for_request(receipt, wrong_request)
        with self.assertRaises(ValidationError):
            env.verifier.verify_individual(
                receipt, wrong_request, env.collector.entries[0], root, env.collector.proof(0)
            )
        self.assertNotIn(b'"choice"', enc(votes[0][1]))
        self.assertEqual(env.phase, "CLOSED")
        mix = env.mix_ballots()
        self.assertEqual(env.phase, "MIXED")
        self.assertNotIn(b'"credential"', enc(mix))
        with self.assertRaises(ValidationError):
            env.mix_ballots()
        tally = env.tally_votes()
        self.assertEqual(env.phase, "TALLIED")
        with self.assertRaises(ValidationError):
            env.tally_votes()
        self.assertEqual((tally.body.yes, tally.body.no, tally.body.valid_count), (2, 1, 3))
        report = env.verifier.audit(
            entries=env.collector.entries, final_root=root, mix_result=mix, tally_result=tally
        )
        self.assertEqual(report["board_and_merkle_root"], "valid")

    def test_audit_rejects_tampered_transcripts(self):
        env = ElectionEnvironment(students(1))
        cast_vote(env, "s0", 1)
        root = close_board(env)
        mix, tally = env.mix_and_tally()
        entries = env.collector.entries
        changed_entry = replace(entries[0], body=replace(
            entries[0].body, accepted_at=entries[0].body.accepted_at + 1
        ))
        inner = mix.inner_envelopes[0]
        nonce = ("A" if inner.nonce[0] != "A" else "B") + inner.nonce[1:]
        changed_mix = replace(mix, inner_envelopes=(replace(inner, nonce=nonce),))
        cases = (
            (entries, root, changed_mix, tally),
            ((changed_entry,), root, mix, tally),
            (entries, replace(root, body=replace(root.body, board_size=0)), mix, tally),
            (entries, root, replace(mix, body=replace(mix.body, output_count=2)), tally),
            (entries, root, mix, replace(tally, body=replace(tally.body, yes=2))),
        )
        for index, (board, final, shuffled, counted) in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValidationError):
                env.verifier.audit(
                    entries=board, final_root=final, mix_result=shuffled, tally_result=counted
                )

    def test_valid_votes_and_outer_inner_errors_are_counted_separately(self):
        env = ElectionEnvironment(students(4))
        cast_vote(env, "s0", 1)
        for identity, choice in (("s1", 2), ("s2", True)):
            voter = env.new_voter()
            voter.authenticate(env.idp, identity, "aps-test")
            payload = {"election_id": env.manifest.body.election_id, "choice": choice}
            env.collector.cast(voter.prepare_payload(payload))
        voter = env.new_voter()
        voter.authenticate(env.idp, "s3", "aps-test")
        request = voter.prepare_cast(0)
        ciphertext = request.body.outer_envelope.ciphertext
        altered = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        envelope = replace(request.body.outer_envelope, ciphertext=altered)
        body = replace(request.body, outer_envelope=envelope)
        request = replace(request, body=body, signature=sign_object(voter._private, "CastRequest", body))
        env.collector.cast(request)
        root = close_board(env)
        mix, tally = env.mix_and_tally()
        self.assertEqual((tally.body.yes, tally.body.no, tally.body.valid_count), (1, 0, 1))
        self.assertEqual((tally.body.invalid_outer, tally.body.invalid_inner), (1, 2))
        env.verifier.audit(entries=env.collector.entries, final_root=root, mix_result=mix, tally_result=tally)

    def test_tally_requires_distinct_trustees_including_an_empty_election(self):
        for count in (0, 1):
            with self.subTest(votes=count):
                env = ElectionEnvironment(students(count))
                if count:
                    cast_vote(env, "s0", 1)
                root = close_board(env)
                mix = env.mix_ballots()
                for participants, error in (
                    (env.trustee_ids[:1], ThresholdError),
                    ((env.trustee_ids[0], env.trustee_ids[0]), ValidationError),
                ):
                    with self.subTest(participants=participants), self.assertRaises(error):
                        env.tally_votes(participants)
                    self.assertEqual(env.phase, "MIXED")
                    self.assertIsNone(env.tally_result)
                tally = env.tally_votes()
                self.assertEqual((tally.body.yes, tally.body.no, tally.body.valid_count), (count, 0, count))
                self.assertEqual(len(tally.signatures), 2)
                env.verifier.audit(
                    entries=env.collector.entries, final_root=root, mix_result=mix, tally_result=tally
                )
