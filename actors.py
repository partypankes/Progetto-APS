"""Autenticazione, preparazione delle buste, Mix e scrutinio collegiale."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING, Any, Callable

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import (
    AuthenticationError, ProtectedSecret, ProtocolError, Share, ThresholdError,
    ValidationError, aes_protect, aes_unprotect, b64e, combine_secret, enc,
    generate_rsa_key, hash_object, hybrid_decrypt, hybrid_encrypt, key_id,
    private_key_from_pem, private_key_to_pem, public_key_to_b64, sign_object,
    split_secret,
)
from models import (
    Ballot, BoardEntry, CastRequest, CastRequestBody, Credential, CredentialBody,
    FinalBoardRoot, MixRecord, MixRecordBody, OuterPayload, SignedManifest,
    TallyResult, TallyResultBody, TrusteeSignature, inner_aad, manifest_key,
    outer_aad, trustee_keys, verify_credential, verify_manifest,
)

if TYPE_CHECKING:
    from audit import UniversalVerifier


def _timestamp(clock: Callable[[], int], at_time: int | None = None) -> int:
    timestamp = clock() if at_time is None else at_time
    if type(timestamp) is not int or timestamp < 0:
        raise ValidationError("L'istante deve essere un intero non negativo")
    return timestamp


def _password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )


class IdentityProvider:
    def __init__(
        self, accounts: dict[str, str], signing_private: rsa.RSAPrivateKey,
        election_id: str, opens_at: int, closes_at: int, *,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        if not isinstance(accounts, dict) or any(
            not isinstance(identity, str) or not identity
            or not isinstance(password, str) or not password
            for identity, password in accounts.items()
        ):
            raise ValueError("Servono account locali con identificativo e password")
        self._signing_private = signing_private
        self.election_id = election_id
        self.opens_at = opens_at
        self.closes_at = closes_at
        self._clock = clock
        self._lock = Lock()
        self._accounts: dict[str, tuple[bytes, bytes]] = {}
        for identity, password in accounts.items():
            salt = os.urandom(16)
            self._accounts[identity] = salt, _password_hash(password, salt)

        self._credentials: dict[str, Credential] = {}
        self._issued_serials: set[str] = set()

    def issue(
        self, student_id: str, voter_public: rsa.RSAPublicKey, password: str, *,
        at_time: int | None = None,
    ) -> Credential:
        with self._lock:
            if not isinstance(student_id, str) or not isinstance(password, str):
                raise AuthenticationError("Identificativo o password non validi")
            account = self._accounts.get(student_id)
            if account is None or not hmac.compare_digest(
                _password_hash(password, account[0]), account[1]
            ):
                raise AuthenticationError("Identificativo o password non validi")
            voter_key = public_key_to_b64(voter_public)
            existing = self._credentials.get(student_id)
            if existing is not None:
                if existing.body.voter_key != voter_key:
                    raise AuthenticationError("Credenziale già emessa per un'altra chiave")
                return existing
            timestamp = _timestamp(self._clock, at_time)
            if not self.opens_at <= timestamp < self.closes_at:
                raise AuthenticationError("Elezione non aperta")
            serial = b64e(os.urandom(32))
            while serial in self._issued_serials:
                serial = b64e(os.urandom(32))
            body = CredentialBody(self.election_id, serial, voter_key)
            credential = Credential(
                body, sign_object(self._signing_private, "Credential", body)
            )

            self._credentials[student_id] = credential
            self._issued_serials.add(serial)
            return credential

    def serial_for_student(self, student_id: str) -> str | None:
        with self._lock:
            credential = self._credentials.get(student_id)
            return None if credential is None else credential.body.serial


class VoterClient:
    def __init__(
        self, manifest: SignedManifest,
        commission_manifest_public: rsa.RSAPublicKey,
    ) -> None:
        verify_manifest(manifest, commission_manifest_public)
        self.manifest = manifest
        self._private = generate_rsa_key()
        self.credential: Credential | None = None

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._private.public_key()

    def authenticate(
        self, idp: IdentityProvider, student_id: str, password: str, *,
        at_time: int | None = None,
    ) -> Credential:
        credential = idp.issue(student_id, self.public_key, password, at_time=at_time)
        verify_credential(credential, self.manifest)
        if credential.body.voter_key != public_key_to_b64(self.public_key):
            raise ValidationError("Credenziale legata a un altro client")
        self.credential = credential
        return credential

    def prepare_cast(self, choice: int) -> CastRequest:
        return self.prepare_payload(Ballot(self.manifest.body.election_id, choice))

    def prepare_payload(self, ballot: Any) -> CastRequest:
        """Prepara le buste; i test possono fornire una scheda JSON non valida."""
        if self.credential is None:
            raise ValidationError("Prima del voto serve una credenziale")
        inner = hybrid_encrypt(
            manifest_key(self.manifest, "tally_encryption"), ballot,
            aad=inner_aad(self.manifest),
        )
        payload = OuterPayload(self.manifest.body.election_id, inner)
        outer = hybrid_encrypt(
            manifest_key(self.manifest, "mix_encryption"), payload,
            aad=outer_aad(self.manifest, self.credential),
        )
        body = CastRequestBody(
            self.manifest.body.election_id, "C", self.credential, outer
        )
        return CastRequest(body, sign_object(self._private, "CastRequest", body))


class MixAuthority:
    def __init__(
        self, manifest: SignedManifest, encryption_private: rsa.RSAPrivateKey,
        signing_private: rsa.RSAPrivateKey, *,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        self.manifest = manifest
        self._clock = clock
        self._encryption_private = encryption_private
        self._signing_private = signing_private
        for private_key, role in (
            (encryption_private, "mix_encryption"), (signing_private, "mix_signing")
        ):
            if public_key_to_b64(private_key.public_key()) != public_key_to_b64(
                manifest_key(manifest, role)
            ):
                raise ValidationError("Chiave privata del Mix non coerente")

    def process(
        self, entries: tuple[BoardEntry, ...], final_root: FinalBoardRoot,
        verifier: UniversalVerifier,
    ) -> MixRecord:
        if _timestamp(self._clock) < self.manifest.body.closes_at:
            raise ValidationError("Il Mix richiede la chiusura della consultazione")
        verifier.verify_final_root(final_root, entries)
        inner_envelopes = []
        invalid_outer = 0
        for entry in entries:
            request = entry.body.cast_request
            try:
                payload = OuterPayload.from_dict(hybrid_decrypt(
                    self._encryption_private, request.body.outer_envelope,
                    aad=outer_aad(self.manifest, request.body.credential),
                ))
                if payload.election_id != self.manifest.body.election_id:
                    raise ValidationError("Busta esterna di un'altra consultazione")
                inner_envelopes.append(payload.inner_envelope)
            except ProtocolError:
                invalid_outer += 1
        secrets.SystemRandom().shuffle(inner_envelopes)
        output = tuple(inner_envelopes)
        body = MixRecordBody(
            election_id=self.manifest.body.election_id,
            final_root_hash=hash_object("FINAL_BOARD_ROOT", final_root),
            input_count=len(entries), output_count=len(output),
            invalid_outer=invalid_outer, output_hash=hash_object("LIST", output),
        )
        return MixRecord(body, output, sign_object(self._signing_private, "MixRecord", body))


def _compute_tally_body(
    manifest: SignedManifest, mix_result: MixRecord, final_root: FinalBoardRoot,
    private_key: rsa.RSAPrivateKey | None,
) -> TallyResultBody:
    """La CE e ogni firmatario aprono e conteggiano la medesima lista."""
    if mix_result.body.output_count:
        if private_key is None or public_key_to_b64(private_key.public_key()) != public_key_to_b64(
            manifest_key(manifest, "tally_encryption")
        ):

            raise ValidationError("Chiave di scrutinio assente o non coerente")
    yes = no = invalid_inner = 0
    for envelope in mix_result.inner_envelopes:
        try:
            ballot = Ballot.from_dict(hybrid_decrypt(
                private_key, envelope, aad=inner_aad(manifest)
            ))
            if ballot.election_id != manifest.body.election_id:
                raise ValidationError("Scheda di un'altra consultazione")
            if ballot.choice == 1:
                yes += 1
            else:
                no += 1
        except ProtocolError:
            invalid_inner += 1
    valid_count = yes + no
    if valid_count + invalid_inner != mix_result.body.output_count:
        raise ValidationError("Il conteggio non corrisponde alla lista del Mix")
    return TallyResultBody(
        election_id=manifest.body.election_id,
        final_root_hash=hash_object("FINAL_BOARD_ROOT", final_root),
        mix_hash=hash_object("MIX_RECORD", mix_result),
        no=no, yes=yes, valid_count=valid_count,
        invalid_outer=mix_result.body.invalid_outer, invalid_inner=invalid_inner,
    )


class Trustee:
    def __init__(
        self, trustee_id: str, share: Share, signing_private: rsa.RSAPrivateKey,
    ) -> None:
        self.trustee_id = trustee_id
        self.share = share
        self._signing_private = signing_private

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._signing_private.public_key()

    def review_and_sign(
        self, body: TallyResultBody, mix_result: MixRecord,
        final_root: FinalBoardRoot, verifier: UniversalVerifier, *,
        entries: tuple[BoardEntry, ...], manifest: SignedManifest,
        private_key: rsa.RSAPrivateKey | None,
    ) -> TrusteeSignature:
        verifier.verify_final_root(final_root, entries)
        verifier.verify_mix(mix_result, final_root)
        expected = _compute_tally_body(manifest, mix_result, final_root, private_key)
        if not isinstance(body, TallyResultBody) or body != expected:
            raise ValidationError("Il trustee rifiuta un risultato diverso dal proprio conteggio")
        return TrusteeSignature(
            self.trustee_id, sign_object(self._signing_private, "TallyResult", body)
        )


@dataclass(frozen=True)
class ProtectedTallyKey:
    tally_key_id: str
    encrypted_private_key: ProtectedSecret


def _custody_aad(election_id: str, tally_key_id: str) -> bytes:
    return enc(["custodia", election_id, tally_key_id])


def protect_tally_key(
    private_key: rsa.RSAPrivateKey, election_id: str, threshold: int,
    trustee_ids: list[str] | tuple[str, ...],
) -> tuple[ProtectedTallyKey, list[Share]]:
    unlock_key = os.urandom(32)
    identifier = key_id(private_key.public_key())
    encrypted = aes_protect(
        private_key_to_pem(private_key), unlock_key,
        _custody_aad(election_id, identifier),
    )
    return ProtectedTallyKey(identifier, encrypted), split_secret(
        unlock_key, threshold, trustee_ids
    )


class ElectionCommission:
    def __init__(
        self, manifest: SignedManifest, protected_key: ProtectedTallyKey,
        trustees: list[Trustee], *,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        self.manifest = manifest
        self.protected_key = protected_key
        self._clock = clock
        self.trustees = {trustee.trustee_id: trustee for trustee in trustees}
        public_keys = trustee_keys(manifest)
        if len(self.trustees) != len(trustees) or set(self.trustees) != set(public_keys):
            raise ValidationError("Trustee non coerenti col manifesto")
        for trustee in trustees:
            if (
                trustee.share.holder_id != trustee.trustee_id
                or public_key_to_b64(trustee.public_key)
                != public_key_to_b64(public_keys[trustee.trustee_id])
            ):
                raise ValidationError("Quota o chiave del trustee non coerente")
        if len({trustee.share.x for trustee in trustees}) != len(trustees):
            raise ValidationError("Coordinate delle quote duplicate")
        if protected_key.tally_key_id != key_id(manifest_key(manifest, "tally_encryption")):
            raise ValidationError("Chiave protetta non coerente col manifesto")

    def _unlock(self, participants: list[Trustee]) -> rsa.RSAPrivateKey:
        threshold = self.manifest.body.threshold.k
        if len(participants) < threshold:
            raise ThresholdError(f"Servono almeno {threshold} trustee")
        unlock_key = combine_secret([trustee.share for trustee in participants], threshold)
        private_key = private_key_from_pem(aes_unprotect(
            self.protected_key.encrypted_private_key, unlock_key,
            _custody_aad(self.manifest.body.election_id, self.protected_key.tally_key_id),
        ))
        if key_id(private_key.public_key()) != key_id(manifest_key(self.manifest, "tally_encryption")):
            raise ValidationError("Chiave di scrutinio ricostruita non coerente")
        return private_key

    def tally(
        self, mix_result: MixRecord, final_root: FinalBoardRoot,
        participant_ids: list[str] | tuple[str, ...], verifier: UniversalVerifier,
        *, entries: tuple[BoardEntry, ...],
    ) -> TallyResult:
        if _timestamp(self._clock) < self.manifest.body.closes_at:
            raise ValidationError("Lo scrutinio richiede la chiusura della consultazione")
        verifier.verify_final_root(final_root, entries)
        verifier.verify_mix(mix_result, final_root)
        if not isinstance(participant_ids, (list, tuple)) or any(
            not isinstance(name, str) for name in participant_ids
        ):
            raise ValidationError("Elenco dei trustee non valido")
        if len(set(participant_ids)) != len(participant_ids):
            raise ValidationError("Trustee duplicato")
        if any(name not in self.trustees for name in participant_ids):
            raise ValidationError("Trustee sconosciuto")
        participants = [self.trustees[name] for name in sorted(participant_ids)]
        threshold = self.manifest.body.threshold.k
        if len(participants) < threshold:
            raise ThresholdError(f"Servono almeno {threshold} trustee")
        private_key = self._unlock(participants) if mix_result.body.output_count else None
        body = _compute_tally_body(self.manifest, mix_result, final_root, private_key)
        signatures = tuple(
            trustee.review_and_sign(
                body, mix_result, final_root, verifier, entries=entries,
                manifest=self.manifest, private_key=private_key,
            )
            for trustee in participants
        )
        result = TallyResult(body, signatures)
        verifier.verify_tally(result, mix_result, final_root)
        return result
