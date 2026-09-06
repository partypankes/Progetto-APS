"""Messaggi immutabili, dati firmati e controlli condivisi del protocollo."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import (
    ValidationError, b64d, hash_object, public_key_from_b64,
    public_key_to_b64, sign_object, verify_signature,
)


def expect(value: Any, cls: type) -> None:
    if type(value) is not cls:
        raise ValidationError(f"È richiesto un oggetto {cls.__name__}")


def text(*values: str) -> None:
    if any(type(value) is not str or not value for value in values):
        raise ValidationError("È richiesta una stringa non vuota")


def nonnegative(*values: int) -> None:
    if any(type(value) is not int or value < 0 for value in values):
        raise ValidationError("È richiesto un intero non negativo")


def sequence(value: tuple, element_type: type) -> None:
    expect(value, tuple)
    for item in value:
        expect(item, element_type)


def _fields(value: Any, names: set[str]) -> dict:
    if type(value) is not dict or set(value) != names:
        raise ValidationError("Campi JSON mancanti o non previsti")
    return value


def _signed(body: Any, body_type: type, signature: str) -> None:
    expect(body, body_type)
    b64d(signature, 256)


@dataclass(frozen=True)
class TrusteeKey:
    trustee_id: str
    public_key: str

    def __post_init__(self):
        text(self.trustee_id, self.public_key)


@dataclass(frozen=True)
class AuthorityKeys:
    idp_signing: str
    collector_signing: str
    mix_signing: str
    mix_encryption: str
    tally_encryption: str
    trustees: tuple[TrusteeKey, ...]

    def __post_init__(self):
        text(self.idp_signing, self.collector_signing, self.mix_signing,
             self.mix_encryption, self.tally_encryption)
        sequence(self.trustees, TrusteeKey)


@dataclass(frozen=True)
class Threshold:
    k: int = 2
    n: int = 3

    def __post_init__(self):
        nonnegative(self.k, self.n)


@dataclass(frozen=True)
class VotingRules:
    duplicate: str = "FIRST_ACCEPTED"
    revote: bool = False

    def __post_init__(self):
        text(self.duplicate)
        expect(self.revote, bool)


@dataclass(frozen=True)
class ManifestBody:
    election_id: str
    question: str
    opens_at: int
    closes_at: int
    keys: AuthorityKeys
    threshold: Threshold
    rules: VotingRules

    def __post_init__(self):
        text(self.election_id, self.question)
        nonnegative(self.opens_at, self.closes_at)
        expect(self.keys, AuthorityKeys)
        expect(self.threshold, Threshold)
        expect(self.rules, VotingRules)


@dataclass(frozen=True)
class SignedManifest:
    body: ManifestBody
    signature: str

    def __post_init__(self):
        _signed(self.body, ManifestBody, self.signature)

    def signing_data(self):
        return self.body


@dataclass(frozen=True)
class CredentialBody:
    election_id: str
    serial: str
    voter_key: str

    def __post_init__(self):
        text(self.election_id, self.voter_key)
        b64d(self.serial, 32)


@dataclass(frozen=True)
class Credential:
    body: CredentialBody
    signature: str

    def __post_init__(self):
        _signed(self.body, CredentialBody, self.signature)

    def signing_data(self):
        return self.body


@dataclass(frozen=True)
class Ballot:
    election_id: str
    choice: int

    def __post_init__(self):
        text(self.election_id)
        nonnegative(self.choice)
        if self.choice not in (0, 1):
            raise ValidationError("La preferenza deve essere 0 oppure 1")

    @classmethod
    def from_dict(cls, value):
        return cls(**_fields(value, {"election_id", "choice"}))


@dataclass(frozen=True)
class Envelope:
    encrypted_key: str
    nonce: str
    ciphertext: str
    tag: str

    def __post_init__(self):
        b64d(self.encrypted_key, 256)
        b64d(self.nonce, 12)
        b64d(self.ciphertext)
        b64d(self.tag, 16)

    @classmethod
    def from_dict(cls, value):
        return cls(**_fields(value, {"encrypted_key", "nonce", "ciphertext", "tag"}))


@dataclass(frozen=True)
class OuterPayload:
    election_id: str
    inner_envelope: Envelope

    def __post_init__(self):
        text(self.election_id)
        expect(self.inner_envelope, Envelope)

    @classmethod
    def from_dict(cls, value):
        data = _fields(value, {"election_id", "inner_envelope"})
        return cls(data["election_id"], Envelope.from_dict(data["inner_envelope"]))


@dataclass(frozen=True)
class CastRequestBody:
    election_id: str
    collector: str
    credential: Credential
    outer_envelope: Envelope

    def __post_init__(self):
        text(self.election_id, self.collector)
        expect(self.credential, Credential)
        expect(self.outer_envelope, Envelope)


@dataclass(frozen=True)
class CastRequest:
    body: CastRequestBody
    signature: str

    def __post_init__(self):
        _signed(self.body, CastRequestBody, self.signature)

    def signing_data(self):
        return self.body


@dataclass(frozen=True)
class BoardEntryBody:
    election_id: str
    index: int
    accepted_at: int
    submission_hash: str
    cast_request: CastRequest

    def __post_init__(self):
        text(self.election_id)
        nonnegative(self.index, self.accepted_at)
        b64d(self.submission_hash, 32)
        expect(self.cast_request, CastRequest)


@dataclass(frozen=True)
class BoardEntry:
    body: BoardEntryBody
    entry_hash: str
    signature: str

    def __post_init__(self):
        _signed(self.body, BoardEntryBody, self.signature)
        b64d(self.entry_hash, 32)

    def signing_data(self):
        return [self.body, self.entry_hash]


@dataclass(frozen=True)
class ReceiptBody:
    election_id: str
    index: int
    submission_hash: str
    entry_hash: str

    def __post_init__(self):
        text(self.election_id)
        nonnegative(self.index)
        b64d(self.submission_hash, 32)
        b64d(self.entry_hash, 32)


@dataclass(frozen=True)
class Receipt:
    body: ReceiptBody
    signature: str

    def __post_init__(self):
        _signed(self.body, ReceiptBody, self.signature)

    def signing_data(self):
        return self.body


@dataclass(frozen=True)
class FinalBoardRootBody:
    election_id: str
    board_size: int
    merkle_root: str
    finalized_at: int

    def __post_init__(self):
        text(self.election_id)
        nonnegative(self.board_size, self.finalized_at)
        b64d(self.merkle_root, 32)


@dataclass(frozen=True)
class FinalBoardRoot:
    body: FinalBoardRootBody
    signature: str

    def __post_init__(self):
        _signed(self.body, FinalBoardRootBody, self.signature)

    def signing_data(self):
        return self.body


@dataclass(frozen=True)
class MerkleStep:
    side: str
    hash: str

    def __post_init__(self):
        if self.side not in ("left", "right"):
            raise ValidationError("Direzione Merkle non valida")
        b64d(self.hash, 32)


@dataclass(frozen=True)
class MerkleProof:
    index: int
    tree_size: int
    path: tuple[MerkleStep, ...]

    def __post_init__(self):
        nonnegative(self.index, self.tree_size)
        sequence(self.path, MerkleStep)


@dataclass(frozen=True)
class MixRecordBody:
    election_id: str
    final_root_hash: str
    input_count: int
    output_count: int
    invalid_outer: int
    output_hash: str

    def __post_init__(self):
        text(self.election_id)
        b64d(self.final_root_hash, 32)
        b64d(self.output_hash, 32)
        nonnegative(self.input_count, self.output_count, self.invalid_outer)


@dataclass(frozen=True)
class MixRecord:
    body: MixRecordBody
    inner_envelopes: tuple[Envelope, ...]
    signature: str

    def __post_init__(self):
        _signed(self.body, MixRecordBody, self.signature)
        sequence(self.inner_envelopes, Envelope)

    def signing_data(self):
        return self.body


@dataclass(frozen=True)
class TallyResultBody:
    election_id: str
    final_root_hash: str
    mix_hash: str
    no: int
    yes: int
    valid_count: int
    invalid_outer: int
    invalid_inner: int

    def __post_init__(self):
        text(self.election_id)
        b64d(self.final_root_hash, 32)
        b64d(self.mix_hash, 32)
        nonnegative(self.no, self.yes, self.valid_count, self.invalid_outer, self.invalid_inner)


@dataclass(frozen=True)
class TrusteeSignature:
    trustee_id: str
    signature: str

    def __post_init__(self):
        text(self.trustee_id)
        b64d(self.signature, 256)


@dataclass(frozen=True)
class TallyResult:
    body: TallyResultBody
    signatures: tuple[TrusteeSignature, ...]

    def __post_init__(self):
        expect(self.body, TallyResultBody)
        sequence(self.signatures, TrusteeSignature)

    def signing_data(self):
        return self.body


def manifest_key(manifest: SignedManifest, role: str) -> rsa.RSAPublicKey:
    roles = {"idp_signing", "collector_signing", "mix_signing", "mix_encryption", "tally_encryption"}
    if role not in roles:
        raise ValidationError("Ruolo non previsto nel manifesto")
    return public_key_from_b64(getattr(manifest.body.keys, role))


def trustee_keys(manifest: SignedManifest) -> dict[str, rsa.RSAPublicKey]:
    records = manifest.body.keys.trustees
    if tuple(record.trustee_id for record in records) != ("trustee-1", "trustee-2", "trustee-3"):
        raise ValidationError("Il manifesto deve identificare i tre trustee in ordine")
    return {record.trustee_id: public_key_from_b64(record.public_key) for record in records}


def verify_manifest(manifest: SignedManifest, trust_anchor: rsa.RSAPublicKey) -> None:
    expect(manifest, SignedManifest)
    body = manifest.body
    if body.opens_at >= body.closes_at or body.threshold != Threshold() or body.rules != VotingRules():
        raise ValidationError("Tempi, soglia o regole del manifesto non validi")
    role_names = ("idp_signing", "collector_signing", "mix_signing", "mix_encryption", "tally_encryption")
    keys = [manifest_key(manifest, role) for role in role_names]
    keys.extend(trustee_keys(manifest).values())
    encodings = [public_key_to_b64(key) for key in [trust_anchor, *keys]]
    if len(set(encodings)) != len(encodings):
        raise ValidationError("Le chiavi devono essere distinte per ruolo e uso")
    verify_signature(trust_anchor, "Manifest", manifest.signing_data(), manifest.signature)


def build_manifest(*, election_id, question, opens_at, closes_at,
                   commission_manifest_private, idp_public, collector_public,
                   mix_encryption_public, mix_signing_public, tally_encryption_public,
                   trustees, threshold=2) -> SignedManifest:
    keys = AuthorityKeys(
        public_key_to_b64(idp_public), public_key_to_b64(collector_public),
        public_key_to_b64(mix_signing_public), public_key_to_b64(mix_encryption_public),
        public_key_to_b64(tally_encryption_public),
        tuple(TrusteeKey(name, public_key_to_b64(key)) for name, key in sorted(trustees.items())),
    )
    body = ManifestBody(election_id, question, opens_at, closes_at, keys,
                        Threshold(threshold, len(trustees)), VotingRules())
    result = SignedManifest(body, sign_object(commission_manifest_private, "Manifest", body))
    verify_manifest(result, commission_manifest_private.public_key())
    return result


def verify_credential(credential: Credential, manifest: SignedManifest, idp_public=None) -> None:
    expect(credential, Credential)
    if credential.body.election_id != manifest.body.election_id:
        raise ValidationError("Credenziale di un'altra consultazione")
    public_key_from_b64(credential.body.voter_key)
    key = manifest_key(manifest, "idp_signing") if idp_public is None else idp_public
    verify_signature(key, "Credential", credential.signing_data(), credential.signature)


def verify_cast_request(request: CastRequest, manifest: SignedManifest, idp_public=None) -> str:
    expect(request, CastRequest)
    body = request.body
    if body.election_id != manifest.body.election_id or body.collector != "C":
        raise ValidationError("Consultazione o destinatario della richiesta non validi")
    verify_credential(body.credential, manifest, idp_public)
    verify_signature(public_key_from_b64(body.credential.body.voter_key),
                     "CastRequest", request.signing_data(), request.signature)
    return hash_object("CAST_REQUEST", request)


def inner_aad(manifest: SignedManifest) -> list:
    return [manifest.body.election_id, "CE", "strato interno"]


def outer_aad(manifest: SignedManifest, credential: Credential) -> list:
    return [manifest.body.election_id, "M", "strato esterno", hash_object("CREDENTIAL", credential)]
