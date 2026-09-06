"""Configurazione e passaggio fra le fasi della simulazione locale."""

from __future__ import annotations

import os
import time
from threading import Lock, RLock

from actors import (
    ElectionCommission, IdentityProvider, MixAuthority, Trustee, VoterClient,
    protect_tally_key,
)
from audit import UniversalVerifier
from board import Collector
from crypto_utils import ValidationError, b64e, generate_rsa_key
from models import FinalBoardRoot, MixRecord, TallyResult, build_manifest


class SimulationClock:
    """Un solo istante condiviso, avanzabile fino alla chiusura senza attese."""

    def __init__(self, timestamp: int) -> None:
        if type(timestamp) is not int or timestamp < 0:
            raise ValidationError("L'istante deve essere un intero non negativo")
        self._timestamp = timestamp
        self._lock = Lock()

    def __call__(self) -> int:
        with self._lock:
            return self._timestamp

    def advance_to(self, timestamp: int) -> None:
        with self._lock:
            if type(timestamp) is not int or timestamp < self._timestamp:
                raise ValidationError("L'orologio deve avanzare a un intero non negativo")
            self._timestamp = timestamp


class ElectionEnvironment:
    def __init__(
        self, accounts: dict[str, str], *,
        question: str = "Approvi la proposta sottoposta a referendum?",
        election_id: str | None = None, opens_at: int | None = None,
        closes_at: int | None = None,
    ) -> None:
        if not isinstance(accounts, dict):
            raise ValueError("Servono account locali con identificativo e password")
        now = int(time.time())
        self.clock = SimulationClock(now)
        opens_at = now - 5 if opens_at is None else opens_at
        closes_at = now + 3600 if closes_at is None else closes_at
        election_id = "aps-" + b64e(os.urandom(10)) if election_id is None else election_id
        self._lock = RLock()

        manifest_key = generate_rsa_key()
        idp_key = generate_rsa_key()
        collector_key = generate_rsa_key()
        mix_encryption_key = generate_rsa_key()
        mix_signing_key = generate_rsa_key()
        tally_key = generate_rsa_key()
        trustee_keys = {f"trustee-{i}": generate_rsa_key() for i in range(1, 4)}
        self.trustee_ids = tuple(sorted(trustee_keys))
        self.commission_manifest_public = manifest_key.public_key()
        self.manifest = build_manifest(
            election_id=election_id, question=question,
            opens_at=opens_at, closes_at=closes_at,
            commission_manifest_private=manifest_key,
            idp_public=idp_key.public_key(), collector_public=collector_key.public_key(),
            mix_encryption_public=mix_encryption_key.public_key(),
            mix_signing_public=mix_signing_key.public_key(),
            tally_encryption_public=tally_key.public_key(),
            trustees={name: key.public_key() for name, key in trustee_keys.items()},
            threshold=2,
        )
        protected_key, shares = protect_tally_key(tally_key, election_id, 2, self.trustee_ids)
        trustees = [
            Trustee(share.holder_id, share, trustee_keys[share.holder_id])
            for share in shares
        ]
        self.idp = IdentityProvider(
            accounts, idp_key, election_id, opens_at, closes_at, clock=self.clock
        )
        self.collector = Collector(
            self.manifest, idp_key.public_key(), collector_key, clock=self.clock
        )
        self.verifier = UniversalVerifier(self.manifest, self.commission_manifest_public)
        self.mix = MixAuthority(
            self.manifest, mix_encryption_key, mix_signing_key, clock=self.clock
        )
        self.commission = ElectionCommission(
            self.manifest, protected_key, trustees, clock=self.clock
        )
        self._mix_result: MixRecord | None = None
        self._tally_result: TallyResult | None = None

    @property
    def now(self) -> int:
        return self.clock()

    def advance_to(self, timestamp: int) -> None:
        self.clock.advance_to(timestamp)

    @property
    def phase(self) -> str:
        with self._lock:
            if self._tally_result is not None:
                return "TALLIED"
            if self._mix_result is not None:
                return "MIXED"
            return "CLOSED" if self.collector.closed else "OPEN"

    @property
    def mix_result(self) -> MixRecord | None:
        with self._lock:
            return self._mix_result

    @property
    def tally_result(self) -> TallyResult | None:
        with self._lock:
            return self._tally_result

    def new_voter(self) -> VoterClient:
        return VoterClient(self.manifest, self.commission_manifest_public)

    def finalize_board(self, *, at_time: int | None = None) -> FinalBoardRoot:
        with self._lock:
            if at_time is not None:
                self.advance_to(at_time)
            return self.collector.finalize()

    def mix_ballots(self) -> MixRecord:
        with self._lock:
            final_root = self.collector.final_root
            if final_root is None:
                raise ValidationError("Prima occorre chiudere la bacheca")
            if self._mix_result is not None:
                raise ValidationError("Il Mix è già stato eseguito per questa consultazione")
            result = self.mix.process(self.collector.entries, final_root, self.verifier)
            self._mix_result = result
            return result

    def tally_votes(self, participant_ids: list[str] | tuple[str, ...] | None = None) -> TallyResult:
        with self._lock:
            final_root = self.collector.final_root
            if final_root is None:
                raise ValidationError("Prima occorre chiudere la bacheca")
            if self._mix_result is None:
                raise ValidationError("Prima occorre completare il Mix")
            if self._tally_result is not None:
                raise ValidationError("Lo scrutinio è già stato eseguito per questa consultazione")
            participants = self.trustee_ids[:2] if participant_ids is None else participant_ids
            result = self.commission.tally(
                self._mix_result, final_root, participants, self.verifier,
                entries=self.collector.entries,
            )
            self._tally_result = result
            return result

    def mix_and_tally(self) -> tuple[MixRecord, TallyResult]:
        with self._lock:
            if self._mix_result is not None or self._tally_result is not None:
                raise ValidationError("Mix o scrutinio già avviati per questa consultazione")
            return self.mix_ballots(), self.tally_votes()
