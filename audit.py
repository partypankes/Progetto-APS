"""Controlli individuali e pubblici su richieste, bacheca e risultati."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa

from board import merkle_root, verify_merkle_proof
from crypto_utils import ValidationError, hash_object, verify_signature
from models import (
    BoardEntry,
    BoardEntryBody,
    CastRequest,
    FinalBoardRoot,
    FinalBoardRootBody,
    MerkleProof,
    MixRecord,
    Receipt,
    ReceiptBody,
    SignedManifest,
    TallyResult,
    expect,
    manifest_key,
    sequence,
    trustee_keys,
    verify_cast_request,
    verify_manifest,
)


class UniversalVerifier:
    def __init__(self, manifest: SignedManifest, commission_manifest_public: rsa.RSAPublicKey) -> None:
        verify_manifest(manifest, commission_manifest_public)
        self.manifest = manifest
        self.commission_manifest_public = commission_manifest_public
        self.election_id = manifest.body.election_id
        self.idp_public = manifest_key(manifest, "idp_signing")
        self.collector_public = manifest_key(manifest, "collector_signing")

    def _election(self, election_id: str) -> None:
        if election_id != self.election_id:
            raise ValidationError("Oggetto riferito a un'altra consultazione")

    def _entry(self, entry: BoardEntry) -> tuple[BoardEntryBody, str]:
        expect(entry, BoardEntry)
        body = entry.body
        self._election(body.election_id)
        if not self.manifest.body.opens_at <= body.accepted_at < self.manifest.body.closes_at:
            raise ValidationError("Istante della voce fuori dalla raccolta")
        if entry.entry_hash != hash_object("BOARD_ENTRY", body):
            raise ValidationError("Hash della voce non valido")
        verify_signature(self.collector_public, "BoardEntry", entry.signing_data(), entry.signature)
        return body, entry.entry_hash

    def verify_board(self, entries: tuple[BoardEntry, ...]) -> None:
        sequence(entries, BoardEntry)
        serials: set[str] = set()
        for index, entry in enumerate(entries):
            body, _ = self._entry(entry)
            if body.index != index:
                raise ValidationError("Indici della bacheca non contigui")
            submission_hash = verify_cast_request(body.cast_request, self.manifest, self.idp_public)
            if body.submission_hash != submission_hash:
                raise ValidationError("Hash della richiesta non coerente")
            serial = body.cast_request.body.credential.body.serial
            if serial in serials:
                raise ValidationError("Seriale duplicato nella bacheca")
            serials.add(serial)

    def verify_receipt(self, receipt: Receipt) -> ReceiptBody:
        expect(receipt, Receipt)
        body = receipt.body
        self._election(body.election_id)
        verify_signature(self.collector_public, "Receipt", receipt.signing_data(), receipt.signature)
        return body

    def _root_body(self, final_root: FinalBoardRoot) -> FinalBoardRootBody:
        expect(final_root, FinalBoardRoot)
        body = final_root.body
        self._election(body.election_id)
        if body.finalized_at < self.manifest.body.closes_at:
            raise ValidationError("Radice finale precedente alla chiusura")
        verify_signature(self.collector_public, "FinalBoardRoot", final_root.signing_data(), final_root.signature)
        return body

    def verify_final_root(self, final_root: FinalBoardRoot, entries: tuple[BoardEntry, ...]) -> None:
        body = self._root_body(final_root)
        self.verify_board(entries)
        if body.board_size != len(entries):
            raise ValidationError("Dimensione della bacheca non coerente")
        if body.merkle_root != merkle_root([entry.entry_hash for entry in entries]):
            raise ValidationError("Radice Merkle non coerente")

    def verify_receipt_for_request(self, receipt: Receipt, request: CastRequest) -> ReceiptBody:
        body = self.verify_receipt(receipt)
        if body.submission_hash != verify_cast_request(request, self.manifest, self.idp_public):
            raise ValidationError("Ricevuta riferita a un'altra richiesta")
        return body

    def verify_individual(
        self,
        receipt: Receipt,
        request: CastRequest,
        entry: BoardEntry,
        final_root: FinalBoardRoot,
        proof: MerkleProof,
    ) -> None:
        received = self.verify_receipt_for_request(receipt, request)
        registered, entry_hash = self._entry(entry)
        if (
            registered.index != received.index
            or entry_hash != received.entry_hash
            or registered.submission_hash != received.submission_hash
            or registered.cast_request != request
        ):
            raise ValidationError("Richiesta, voce e ricevuta non coincidono")
        root = self._root_body(final_root)
        verify_merkle_proof(
            entry_hash, proof, root.merkle_root,
            index=received.index, tree_size=root.board_size,
        )

    def verify_mix(self, mix_result: MixRecord, final_root: FinalBoardRoot) -> None:
        expect(mix_result, MixRecord)
        body = mix_result.body
        self._election(body.election_id)
        root = self._root_body(final_root)
        if body.final_root_hash != hash_object("FINAL_BOARD_ROOT", final_root):
            raise ValidationError("Il mix si riferisce a un'altra bacheca")
        if (
            body.input_count != root.board_size
            or body.input_count != body.output_count + body.invalid_outer
            or len(mix_result.inner_envelopes) != body.output_count
            or body.output_hash != hash_object("LIST", mix_result.inner_envelopes)
        ):
            raise ValidationError("Risultato del mix non coerente")
        verify_signature(manifest_key(self.manifest, "mix_signing"), "MixRecord", mix_result.signing_data(), mix_result.signature)

    def verify_tally(self, tally_result: TallyResult, mix_result: MixRecord, final_root: FinalBoardRoot) -> None:
        self.verify_mix(mix_result, final_root)
        expect(tally_result, TallyResult)
        body = tally_result.body
        self._election(body.election_id)
        if (
            body.final_root_hash != hash_object("FINAL_BOARD_ROOT", final_root)
            or body.mix_hash != hash_object("MIX_RECORD", mix_result)
        ):
            raise ValidationError("Riferimenti dello scrutinio non validi")
        if (
            body.valid_count != body.yes + body.no
            or body.valid_count + body.invalid_inner != mix_result.body.output_count
            or mix_result.body.input_count != body.valid_count + body.invalid_outer + body.invalid_inner
            or body.invalid_outer != mix_result.body.invalid_outer
        ):
            raise ValidationError("Conteggi dello scrutinio non coerenti")
        keys = trustee_keys(self.manifest)
        ids = tuple(item.trustee_id for item in tally_result.signatures)
        if ids != tuple(sorted(ids)):
            raise ValidationError("Firme dei trustee non ordinate per identificativo")
        seen: set[str] = set()
        for record in tally_result.signatures:
            if record.trustee_id not in keys or record.trustee_id in seen:
                raise ValidationError("Trustee sconosciuto o duplicato")
            verify_signature(keys[record.trustee_id], "TallyResult", tally_result.signing_data(), record.signature)
            seen.add(record.trustee_id)
        if len(seen) < self.manifest.body.threshold.k:
            raise ValidationError("Firme del quorum insufficienti")

    def audit(
        self,
        *,
        entries: tuple[BoardEntry, ...],
        final_root: FinalBoardRoot,
        mix_result: MixRecord,
        tally_result: TallyResult,
    ) -> dict[str, str | int]:
        verify_manifest(self.manifest, self.commission_manifest_public)
        self.verify_final_root(final_root, entries)
        self.verify_tally(tally_result, mix_result, final_root)
        hashes = [hash_object("ENVELOPE", item) for item in mix_result.inner_envelopes]
        return {
            "manifest": "valid",
            "board_and_merkle_root": "valid",
            "accepted_ballots": len(entries),
            "mix": "internally-consistent",
            "tally": "internally-consistent",
            "duplicate_inner_envelopes": len(hashes) - len(set(hashes)),
        }
