"""Contratti JSON e verifiche delle primitive indipendenti dai ruoli."""

import hashlib
import json
import os
from dataclasses import asdict, replace
from itertools import combinations
from unittest import TestCase

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from board import merkle_proof, merkle_root, verify_merkle_proof
from crypto_utils import (
    ThresholdError, ValidationError, aes_protect, aes_unprotect, b64d, b64e,
    combine_secret, decode_json, enc, generate_rsa_key, hash_object,
    hybrid_decrypt, hybrid_encrypt, public_key_from_b64, public_key_to_b64,
    serialized_size, sign_object, split_secret, verify_signature,
)
from models import Ballot, Credential, CredentialBody


class CryptoTests(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = generate_rsa_key()
        cls.other_key = generate_rsa_key()

    def test_json_determinism_and_explicit_fields(self):
        ballot = Ballot("consultazione-à", 1)
        expected = '{"choice":1,"election_id":"consultazione-à"}'.encode()
        self.assertEqual(enc(ballot), expected)
        self.assertEqual(enc(dict(reversed(list(asdict(ballot).items())))), expected)
        self.assertEqual(decode_json(expected), asdict(ballot))
        self.assertEqual(serialized_size(ballot), len(expected))
        self.assertNotEqual(enc([1, 0]), enc([0, 1]))
        self.assertEqual(enc((1, 0)), enc([1, 0]))
        self.assertNotEqual(enc(True), enc(1))
        self.assertNotEqual(enc("1"), enc(1))
        with self.assertRaises(ValidationError):
            Ballot("E1", True)

    def test_json_rejects_invalid_types_fields_and_representations(self):
        for value in (None, -1, 1.0, float("nan"), float("inf"), b"bytes", {1: "x"}, {"x": None}):
            with self.subTest(value=repr(value)), self.assertRaises(ValidationError):
                enc(value)
        invalid = (
            b'{"x":1,"x":2}', b'{"a":{"x":1,"x":2}}', b'{"x": 1}',
            b'{"b":1,"a":2}', b'{"x":1.0}', b'{"x":1e0}', b'{"x":-0}',
            b'{"x":-1}', b'{"x":null}', b'{"x":NaN}', b'{"x":Infinity}',
            b'{}{}', b'{}\n', b'\xef\xbb\xbf{}', b'{"x":"\xff"}',
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                decode_json(value)
        for value in ({"election_id": "E1"}, {"election_id": "E1", "choice": 1, "extra": 0}):
            with self.assertRaises(ValidationError):
                Ballot.from_dict(value)

    def test_binary_values_and_public_keys_are_canonical(self):
        value = os.urandom(32)
        encoded = b64e(value)
        self.assertEqual(b64d(encoded, 32), value)
        for malformed in (encoded + "=", encoded + "\n", "@@", 5, "é"):
            with self.subTest(value=malformed), self.assertRaises(ValidationError):
                b64d(malformed)
        with self.assertRaises(ValidationError):
            b64d(encoded, 16)
        encoded = public_key_to_b64(self.key.public_key())
        self.assertEqual(public_key_from_b64(encoded).public_numbers(), self.key.public_key().public_numbers())
        with self.assertRaises(ValidationError):
            public_key_from_b64(b64e(b64d(encoded) + b"extra"))

    def test_signature_and_hash_match_independent_json_contexts(self):
        value = {"x": 1, "label": "à"}
        signature = sign_object(self.key, "Credential", value)
        raw = json.dumps(["firma", "Credential", value], sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False).encode()
        self.key.public_key().verify(
            b64d(signature), raw,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256(),
        )
        hash_input = json.dumps(["hash", "CREDENTIAL", value], sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(hash_object("CREDENTIAL", value), b64e(hashlib.sha256(hash_input).digest()))
        with self.assertRaises(ValidationError):
            verify_signature(self.key.public_key(), "Receipt", value, signature)
        with self.assertRaises(ValidationError):
            verify_signature(self.other_key.public_key(), "Credential", value, signature)
        body = CredentialBody("E1", b64e(os.urandom(32)), public_key_to_b64(self.key.public_key()))
        a = Credential(body, sign_object(self.key, "Credential", body))
        b = Credential(body, sign_object(self.key, "Credential", body))
        self.assertNotEqual(a.signature, b.signature)
        self.assertNotEqual(hash_object("CREDENTIAL", a), hash_object("CREDENTIAL", b))

    def test_hybrid_parameters_and_json_opened_directly(self):
        ballot = Ballot("E1", 1)
        aad = ["E1", "CE", "strato interno"]
        envelope = hybrid_encrypt(self.key.public_key(), ballot, aad=aad)
        aes_key = self.key.decrypt(
            b64d(envelope.encrypted_key), padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"",
            ),
        )
        self.assertEqual(len(aes_key), 32)
        self.assertEqual(len(b64d(envelope.nonce)), 12)
        self.assertEqual(len(b64d(envelope.tag)), 16)
        raw_aad = json.dumps(aad, separators=(",", ":")).encode()
        raw = AESGCM(aes_key).decrypt(
            b64d(envelope.nonce), b64d(envelope.ciphertext) + b64d(envelope.tag), raw_aad,
        )
        self.assertEqual(json.loads(raw), {"election_id": "E1", "choice": 1})
        for private, context, item in (
            (self.other_key, aad, envelope),
            (self.key, ["E2", "CE", "strato interno"], envelope),
            (self.key, aad, replace(envelope, tag=b64e(bytes(16)))),
        ):
            with self.assertRaises(ValidationError):
                hybrid_decrypt(private, item, aad=context)

    def test_shamir_and_aes_key_custody(self):
        secret = os.urandom(32)
        shares = split_secret(secret, 2, ["T1", "T2", "T3"])
        for pair in combinations(shares, 2):
            self.assertEqual(combine_secret(list(pair), 2), secret)
        with self.assertRaises(ThresholdError):
            combine_secret(shares[:1], 2)
        with self.assertRaises(ValidationError):
            combine_secret([shares[0], shares[0]], 2)
        with self.assertRaises(ValidationError):
            combine_secret([replace(shares[0], x=True), shares[1]], 2)
        wrapped = aes_protect(b"secret", secret, b"context")
        self.assertEqual(aes_unprotect(wrapped, secret, b"context"), b"secret")
        with self.assertRaises(ValidationError):
            aes_unprotect(wrapped, secret, b"other")

    def test_merkle_zero_one_and_odd_tree(self):
        self.assertEqual(merkle_root([]), hash_object("MERKLE_EMPTY", []))
        with self.assertRaises(ValidationError):
            merkle_proof([], 0)
        for n in (1, 3, 5):
            hashes_ = [hash_object("BOARD_ENTRY", i) for i in range(n)]
            root = merkle_root(hashes_)
            for index, value in enumerate(hashes_):
                proof = merkle_proof(hashes_, index)
                verify_merkle_proof(value, proof, root, index=index, tree_size=n)
                with self.assertRaises(ValidationError):
                    verify_merkle_proof(value, replace(proof, tree_size=n+1), root, index=index, tree_size=n)
            if n == 1:
                self.assertEqual(proof.path, ())
            else:
                bad_step = replace(proof.path[0], hash=hash_object("BOARD_ENTRY", 99))
                with self.assertRaises(ValidationError):
                    verify_merkle_proof(hashes_[-1], replace(proof, path=(bad_step, *proof.path[1:])),
                                        root, index=n-1, tree_size=n)
