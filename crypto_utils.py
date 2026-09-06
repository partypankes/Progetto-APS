"""Codifica JSON condivisa, primitive crittografiche e quote Shamir."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_BITS = 2048
AES_KEY_BYTES = 32
NONCE_BYTES = 12


class ProtocolError(Exception):
    """Un controllo del protocollo non è stato superato."""


class ValidationError(ProtocolError):
    pass


class AuthenticationError(ProtocolError):
    pass


class CredentialAlreadyUsed(ProtocolError):
    pass


class ElectionClosed(ProtocolError):
    pass


class ThresholdError(ProtocolError):
    pass


def _json_value(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if isinstance(value, dict):
        if any(type(key) is not str for key in value):
            raise ValidationError("Le chiavi JSON devono essere stringhe")
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if type(value) in (str, bool) or (type(value) is int and value >= 0):
        return value
    raise ValidationError("Tipo non ammesso nella codifica JSON")


def enc(value: Any) -> bytes:
    """Stesse regole per messaggi, contenuti cifrati, AAD, firme e hash."""
    try:
        return json.dumps(
            _json_value(value), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ValidationError("Dati JSON non validi") from exc


def decode_json(data: bytes) -> Any:
    def unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError("Chiave JSON duplicata")
            result[key] = value
        return result

    def reject_number(value: str) -> None:
        raise ValidationError("Numero JSON non ammesso")

    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=unique_fields,
            parse_float=reject_number, parse_constant=reject_number,
        )
        if enc(value) != data:
            raise ValidationError("JSON non canonico")
        return value
    except (UnicodeError, ValueError, TypeError, AttributeError) as exc:
        raise ValidationError("Contenuto JSON non valido") from exc


def serialized_size(value: Any) -> int:
    return len(enc(value))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64d(value: str, expected_len: int | None = None) -> bytes:
    if type(value) is not str:
        raise ValidationError("Base64URL non valida")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeError) as exc:
        raise ValidationError("Base64URL non valida") from exc
    if b64e(raw) != value or (expected_len is not None and len(raw) != expected_len):
        raise ValidationError("Base64URL non canonica o lunghezza errata")
    return raw


def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def public_key_to_b64(key: rsa.RSAPublicKey) -> str:
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != RSA_BITS:
        raise ValidationError("È richiesta una chiave RSA-2048")
    return b64e(key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def public_key_from_b64(value: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_der_public_key(b64d(value))
    except (ValueError, TypeError) as exc:
        raise ValidationError("Chiave pubblica non valida") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != RSA_BITS:
        raise ValidationError("È richiesta una chiave RSA-2048")
    if public_key_to_b64(key) != value:
        raise ValidationError("Chiave pubblica non canonica")
    return key


def key_id(key: rsa.RSAPublicKey) -> str:
    return hash_object("PUBLIC_KEY", public_key_to_b64(key))


def private_key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def private_key_from_pem(value: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(value, password=None)
    except (ValueError, TypeError) as exc:
        raise ValidationError("Chiave privata non valida") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != RSA_BITS:
        raise ValidationError("La chiave recuperata deve essere RSA-2048")
    return key


def sign_object(key: rsa.RSAPrivateKey, name: str, value: Any) -> str:
    signature = key.sign(
        enc(["firma", name, value]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return b64e(signature)


def verify_signature(key: rsa.RSAPublicKey, name: str, value: Any, signature: str) -> None:
    try:
        key.verify(
            b64d(signature, RSA_BITS // 8), enc(["firma", name, value]),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValidationError(f"Firma non valida: {name}") from exc


def hash_object(domain: str, value: Any) -> str:
    return b64e(hashlib.sha256(enc(["hash", domain, value])).digest())


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"",
    )


def hybrid_encrypt(key: rsa.RSAPublicKey, payload: Any, *, aad: Any):
    from models import Envelope

    aes_key = os.urandom(AES_KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    encrypted = AESGCM(aes_key).encrypt(nonce, enc(payload), enc(aad))
    return Envelope(
        b64e(key.encrypt(aes_key, _oaep())), b64e(nonce),
        b64e(encrypted[:-16]), b64e(encrypted[-16:]),
    )


def hybrid_decrypt(key: rsa.RSAPrivateKey, envelope, *, aad: Any) -> Any:
    from models import Envelope, expect

    expect(envelope, Envelope)
    try:
        aes_key = key.decrypt(b64d(envelope.encrypted_key, RSA_BITS // 8), _oaep())
        if len(aes_key) != AES_KEY_BYTES:
            raise ValidationError("La chiave della busta deve essere AES-256")
        plaintext = AESGCM(aes_key).decrypt(
            b64d(envelope.nonce, NONCE_BYTES),
            b64d(envelope.ciphertext) + b64d(envelope.tag, 16), enc(aad),
        )
        return decode_json(plaintext)
    except (ValueError, InvalidTag) as exc:
        raise ValidationError("Apertura della busta fallita") from exc


@dataclass(frozen=True)
class ProtectedSecret:
    nonce: str
    ciphertext: str


def aes_protect(plaintext: bytes, key: bytes, aad: bytes) -> ProtectedSecret:
    nonce = os.urandom(NONCE_BYTES)
    return ProtectedSecret(b64e(nonce), b64e(AESGCM(key).encrypt(nonce, plaintext, aad)))


def aes_unprotect(value: ProtectedSecret, key: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(b64d(value.nonce, NONCE_BYTES), b64d(value.ciphertext), aad)
    except (ValueError, InvalidTag, AttributeError) as exc:
        raise ValidationError("Chiave di scrutinio non apribile") from exc


PRIME = 65537


@dataclass(frozen=True)
class Share:
    holder_id: str
    x: int
    values: tuple[int, ...]


def split_secret(secret: bytes, threshold: int, holders: list[str]) -> list[Share]:
    if type(threshold) is not int or not 2 <= threshold <= len(holders) < PRIME:
        raise ValidationError("Soglia non valida")
    if len(set(holders)) != len(holders):
        raise ValidationError("Custodi duplicati")
    rows = [[] for _ in holders]
    for byte in secret:
        coefficients = [byte] + [secrets.randbelow(PRIME) for _ in range(threshold - 1)]
        for index, row in enumerate(rows, 1):
            value = 0
            for coefficient in reversed(coefficients):
                value = (value * index + coefficient) % PRIME
            row.append(value)
    return [Share(holder, index, tuple(row))
            for index, (holder, row) in enumerate(zip(holders, rows, strict=True), 1)]


def combine_secret(shares: list[Share], threshold: int) -> bytes:
    if type(threshold) is not int or threshold < 2:
        raise ValidationError("Soglia non valida")
    if len(shares) < threshold:
        raise ThresholdError(f"Servono almeno {threshold} quote")
    selected = shares[:threshold]
    for share in selected:
        if (type(share) is not Share or type(share.x) is not int
                or not 0 < share.x < PRIME or type(share.values) is not tuple
                or any(type(value) is not int or not 0 <= value < PRIME for value in share.values)):
            raise ValidationError("Valori delle quote non validi")
    if len({share.x for share in selected}) != threshold:
        raise ValidationError("Quote duplicate")
    lengths = {len(share.values) for share in selected}
    if len(lengths) != 1:
        raise ValidationError("Quote incompatibili")
    result = bytearray()
    for position in range(lengths.pop()):
        value = 0
        for i, left in enumerate(selected):
            numerator = denominator = 1
            for j, right in enumerate(selected):
                if i != j:
                    numerator = numerator * (-right.x) % PRIME
                    denominator = denominator * (left.x - right.x) % PRIME
            value += left.values[position] * numerator * pow(denominator, -1, PRIME)
        recovered = value % PRIME
        if recovered > 255:
            raise ValidationError("Le quote non ricostruiscono byte validi")
        result.append(recovered)
    return bytes(result)
