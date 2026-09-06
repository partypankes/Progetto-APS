"""Identità, recuperi, concorrenza, chiusura e controllo del conteggio."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from threading import Barrier
from unittest import TestCase
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import (
    AuthenticationError, CredentialAlreadyUsed, ElectionClosed,
    ValidationError, enc, public_key_to_b64,
)
from election import ElectionEnvironment


def environment(count=1):
    return ElectionEnvironment({f"s{i}": "aps-test" for i in range(count)})


def prepare(env, identity="s0", choice=1):
    voter = env.new_voter()
    voter.authenticate(env.idp, identity, "aps-test")
    return voter, voter.prepare_cast(choice)


def cast(env, identity="s0", choice=1):
    voter, request = prepare(env, identity, choice)
    return voter, request, env.collector.cast(request)


def close(env):
    return env.finalize_board(at_time=env.manifest.body.closes_at)


class RegressionTests(TestCase):

    def test_password_and_original_credential_recovery_after_close(self):
        env = environment()
        voter = env.new_voter()
        with self.assertRaises(AuthenticationError):
            voter.authenticate(env.idp, "s0", "errata")
        self.assertIsNone(env.idp.serial_for_student("s0"))
        with self.assertRaises(AuthenticationError):
            voter.authenticate(env.idp, "non-ammesso", "aps-test")
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with self.assertRaises(ValidationError):
            env.idp.issue("s0", wrong_key.public_key(), "aps-test")
        self.assertIsNone(env.idp.serial_for_student("s0"))
        credential = voter.authenticate(env.idp, "s0", "aps-test")
        self.assertIs(credential, voter.authenticate(env.idp, "s0", "aps-test"))
        self.assertEqual(credential.body.voter_key, public_key_to_b64(voter.public_key))
        self.assertEqual(env.idp.serial_for_student("s0"), credential.body.serial)
        close(env)
        with patch("actors.sign_object", side_effect=AssertionError("Firma rigenerata")):
            self.assertIs(credential, voter.authenticate(env.idp, "s0", "aps-test"))
        with self.assertRaises(AuthenticationError):
            voter.authenticate(env.idp, "s0", "errata")
        with self.assertRaises(AuthenticationError):
            env.new_voter().authenticate(env.idp, "s0", "aps-test")

    def test_concurrent_issuance_and_first_accepted_preserve_one_original(self):
        env = environment()
        voter = env.new_voter()
        gate = Barrier(2)
        def issue(_):
            gate.wait(timeout=5)
            return env.idp.issue("s0", voter.public_key, "aps-test")
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.map(issue, range(2))
        self.assertIs(a, b)
        voter.authenticate(env.idp, "s0", "aps-test")
        first, second = voter.prepare_cast(1), voter.prepare_cast(0)
        gate = Barrier(2)
        def send(request):
            gate.wait(timeout=5)
            try:
                return env.collector.cast(request)
            except CredentialAlreadyUsed:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(send, (first, second)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(tuple(item.body.index for item in env.collector.entries), (0,))

    def test_recovery_preserves_immutable_entry_receipt_and_root(self):
        env = environment()
        voter, request, receipt = cast(env)
        entry = env.collector.entries[0]
        self.assertIs(env.collector.cast(request), receipt)
        with self.assertRaises(CredentialAlreadyUsed):
            env.collector.cast(voter.prepare_cast(0))
        root = close(env)
        snapshot = enc([entry, receipt, root])
        with patch("board.sign_object", side_effect=AssertionError("Firma rigenerata")):
            self.assertIs(receipt, env.collector.cast(request))
            self.assertEqual((entry, receipt), env.collector.recorded(request))
            self.assertIs(root, env.collector.finalize())
        with self.assertRaises(FrozenInstanceError):
            entry.body.index = 9
        with self.assertRaises(CredentialAlreadyUsed):
            env.collector.cast(voter.prepare_cast(0))
        self.assertEqual(snapshot, enc([env.collector.entries[0], env.collector.cast(request), env.collector.final_root]))

    def test_time_boundaries_and_future_root_do_not_advance_mix(self):
        env = environment(3)
        opening, closing = env.manifest.body.opens_at, env.manifest.body.closes_at
        requests = [prepare(env, f"s{i}")[1] for i in range(3)]
        with self.assertRaises(ElectionClosed):
            env.collector.cast(requests[0], at_time=opening-1)
        env.collector.cast(requests[0], at_time=opening)
        env.collector.cast(requests[1], at_time=closing-1)
        for timestamp in (closing, closing+1):
            with self.assertRaises(ElectionClosed):
                env.collector.cast(requests[2], at_time=timestamp)
        for timestamp in (True, -1):
            with self.assertRaises(ValidationError):
                env.collector.cast(requests[2], at_time=timestamp)
        root = env.collector.finalize(at_time=closing)
        with self.assertRaises(ValidationError):
            env.mix.process(env.collector.entries, root, env.verifier)
        with self.assertRaises(ElectionClosed):
            env.collector.cast(requests[2], at_time=closing-1)
        env.advance_to(closing)
        self.assertEqual(env.mix.process(env.collector.entries, root, env.verifier).body.input_count, 2)

    def test_trustee_refuses_false_count_even_when_quadratures_match(self):
        env = environment()
        cast(env)
        root = close(env)
        mix, tally = env.mix_and_tally()
        false = replace(tally.body, yes=0, no=1)
        participants = [env.commission.trustees[name] for name in env.trustee_ids[:2]]
        key = env.commission._unlock(participants)
        with self.assertRaises(ValidationError):
            participants[0].review_and_sign(false, mix, root, env.verifier,
                entries=env.collector.entries, manifest=env.manifest, private_key=key)
