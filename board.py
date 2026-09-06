"""Raccolta delle richieste, registrazioni firmate e Merkle tree finale."""

from __future__ import annotations

import time
from threading import RLock
from typing import Callable, Sequence

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import (
    CredentialAlreadyUsed,
    ElectionClosed,
    ValidationError,
    b64d,
    hash_object,
    key_id,
    sign_object,
)
from models import (
    BoardEntry,
    BoardEntryBody,
    CastRequest,
    FinalBoardRoot,
    FinalBoardRootBody,
    MerkleProof,
    MerkleStep,
    Receipt,
    ReceiptBody,
    SignedManifest,
    expect,
    manifest_key,
    nonnegative,
    verify_cast_request,
)


def _leaf(entry_hash: str, index: int, tree_size: int) -> str:
    b64d(entry_hash, 32)
    return hash_object("MERKLE_LEAF", [index, tree_size, entry_hash])


def _node(left: str, right: str) -> str:
    return hash_object("MERKLE_NODE", [left, right])


def _next_level(level: list[str]) -> list[str]:
    """Il nodo dispari viene duplicato soltanto per il calcolo del genitore."""
    if len(level) % 2:
        level = [*level, level[-1]]
    return [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]


def merkle_root(entry_hashes: Sequence[str]) -> str:
    if not entry_hashes:
        return hash_object("MERKLE_EMPTY", [])
    size = len(entry_hashes)
    level = [_leaf(value, index, size) for index, value in enumerate(entry_hashes)]
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def merkle_proof(entry_hashes: Sequence[str], index: int) -> MerkleProof:
    if type(index) is not int or not 0 <= index < len(entry_hashes):
        raise ValidationError("Indice Merkle fuori intervallo")
    size = len(entry_hashes)
    level = [_leaf(value, position, size) for position, value in enumerate(entry_hashes)]
    position = index
    path = []
    while len(level) > 1:
        side = "left" if position % 2 else "right"
        sibling = position - 1 if position % 2 else min(position + 1, len(level) - 1)
        path.append(MerkleStep(side, level[sibling]))
        level = _next_level(level)
        position //= 2
    return MerkleProof(index, size, tuple(path))


def verify_merkle_proof(
    entry_hash: str,
    proof: MerkleProof,
    expected_root: str,
    *,
    index: int,
    tree_size: int,
) -> None:
    expect(proof, MerkleProof)
    nonnegative(index)
    nonnegative(tree_size)
    if index >= tree_size or proof.index != index or proof.tree_size != tree_size:
        raise ValidationError("Posizione o dimensione della prova Merkle non valida")
    b64d(expected_root, 32)

    expected_steps, width = 0, tree_size
    while width > 1:
        expected_steps += 1
        width = (width + 1) // 2
    if len(proof.path) != expected_steps:
        raise ValidationError("Lunghezza della prova Merkle non valida")

    current = _leaf(entry_hash, index, tree_size)
    position, width = index, tree_size
    for step in proof.path:
        expected_side = "left" if position % 2 else "right"
        if step.side != expected_side:
            raise ValidationError("Direzione Merkle incoerente con l'indice")
        if position % 2 == 0 and position + 1 == width and step.hash != current:
            raise ValidationError("Duplicazione Merkle finale non valida")
        current = _node(step.hash, current) if expected_side == "left" else _node(current, step.hash)
        position //= 2
        width = (width + 1) // 2
    if current != expected_root:
        raise ValidationError("Prova Merkle non valida")


class Collector:
    """Conserva la prima richiesta accettata e restituisce gli originali ai reinvii."""

    def __init__(
        self,
        manifest: SignedManifest,
        idp_public: rsa.RSAPublicKey,
        signing_private: rsa.RSAPrivateKey,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        expect(manifest, SignedManifest)
        self.manifest = manifest
        self.idp_public = idp_public
        self._signing_private = signing_private
        self._clock = clock or (lambda: int(time.time()))
        self._lock = RLock()
        if key_id(idp_public) != key_id(manifest_key(manifest, "idp_signing")):
            raise ValidationError("Chiave dell'IdP non coerente col manifesto")
        if key_id(signing_private.public_key()) != key_id(manifest_key(manifest, "collector_signing")):
            raise ValidationError("Chiave del collector non coerente col manifesto")
        self._entries: list[BoardEntry] = []
        self._registrations: dict[str, tuple[BoardEntry, Receipt]] = {}
        self._closed = False
        self._final_root: FinalBoardRoot | None = None

    @property
    def entries(self) -> tuple[BoardEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def final_root(self) -> FinalBoardRoot | None:
        with self._lock:
            return self._final_root

    def _timestamp(self, at_time: int | None) -> int:
        value = self._clock() if at_time is None else at_time
        nonnegative(value)
        return value

    def cast(self, request: CastRequest, *, at_time: int | None = None) -> Receipt:
        submission_hash = verify_cast_request(request, self.manifest, self.idp_public)
        with self._lock:
            serial = request.body.credential.body.serial
            if serial in self._registrations:
                return self._recorded(request)[1]
            received_at = self._timestamp(at_time)
            window = self.manifest.body
            if self._closed or not window.opens_at <= received_at < window.closes_at:
                raise ElectionClosed("ELECTION_CLOSED")

            body = BoardEntryBody(window.election_id, len(self._entries), received_at, submission_hash, request)
            entry_hash = hash_object("BOARD_ENTRY", body)
            entry = BoardEntry(body, entry_hash, sign_object(self._signing_private, "BoardEntry", [body, entry_hash]))
            receipt_body = ReceiptBody(window.election_id, body.index, submission_hash, entry_hash)
            receipt = Receipt(receipt_body, sign_object(self._signing_private, "Receipt", receipt_body))
            # Le due firme precedono ogni modifica dello stato della raccolta.
            self._entries.append(entry)
            self._registrations[serial] = (entry, receipt)
            return receipt

    def _recorded(self, request: CastRequest) -> tuple[BoardEntry, Receipt]:
        serial = request.body.credential.body.serial
        if serial not in self._registrations:
            raise ValidationError("Richiesta non registrata")
        entry, receipt = self._registrations[serial]
        if entry.body.cast_request != request:
            raise CredentialAlreadyUsed("CREDENTIAL_ALREADY_USED")
        return entry, receipt

    def recorded(self, request: CastRequest) -> tuple[BoardEntry, Receipt]:
        verify_cast_request(request, self.manifest, self.idp_public)
        with self._lock:
            return self._recorded(request)

    def finalize(self, *, at_time: int | None = None) -> FinalBoardRoot:
        with self._lock:
            if self._final_root is not None:
                return self._final_root
            finalized_at = self._timestamp(at_time)
            if finalized_at < self.manifest.body.closes_at:
                raise ValidationError("Finalizzazione precedente alla chiusura")
            body = FinalBoardRootBody(
                self.manifest.body.election_id,
                len(self._entries),
                merkle_root([entry.entry_hash for entry in self._entries]),
                finalized_at,
            )
            final_root = FinalBoardRoot(body, sign_object(self._signing_private, "FinalBoardRoot", body))
            self._final_root = final_root
            self._closed = True
            return final_root

    def proof(self, index: int) -> MerkleProof:
        with self._lock:
            if self._final_root is None:
                raise ValidationError("La prova richiede una bacheca finalizzata")
            return merkle_proof([entry.entry_hash for entry in self._entries], index)
