"""Menu e dimostrazione del protocollo sulla consultazione locale."""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from typing import Any, Callable

from actors import VoterClient
from crypto_utils import (
    AuthenticationError, CredentialAlreadyUsed, ProtocolError,
    ThresholdError, ValidationError, b64d, b64e,
)
from election import ElectionEnvironment
from models import CastRequest, Receipt


SCENARIOS = (
    ("wrong_password", "Password errata"),
    ("second_vote", "Seconda richiesta con credenziale già utilizzata"),
    ("tampered_request", "Richiesta alterata"),
    ("tampered_receipt", "Ricevuta alterata"),
    ("tampered_proof", "Prova Merkle alterata"),
    ("tampered_mix", "Record del Mix alterato"),
    ("tampered_tally", "Risultato alterato"),
    ("insufficient_quorum", "Scrutinio con un solo trustee"),
)


def _alter_bytes(value: str) -> str:
    raw = b64d(value)
    return b64e(bytes([raw[0] ^ 1]) + raw[1:])


def run_demo(voter_count: int = 6, *, quiet: bool = False) -> dict[str, Any]:
    if type(voter_count) is not int or voter_count < 0:
        raise ValueError("Il numero di elettori deve essere un intero non negativo")
    accounts = {f"studente-{index + 1:03d}": "aps-demo" for index in range(voter_count)}
    environment = ElectionEnvironment(accounts)
    voters, requests, receipts = [], [], []

    def step(number: int, message: str) -> None:
        if not quiet:
            print(f"{number}. {message}")

    step(1, "Commissione: prepara e firma il manifesto.")
    step(2, "Elettori: si autenticano, preparano la doppia busta e verificano la ricevuta.")
    for index, (student_id, password) in enumerate(accounts.items()):
        voter = environment.new_voter()
        voter.authenticate(environment.idp, student_id, password)
        request = voter.prepare_cast(index % 2)
        receipt = environment.collector.cast(request)
        environment.verifier.verify_receipt_for_request(receipt, request)
        voters.append(voter)
        requests.append(request)
        receipts.append(receipt)

    step(3, "Raccoglitore: recupera l'originale e rifiuta una richiesta diversa.")
    retry_recovered = duplicate_rejected = None
    if requests:
        entry, recovered = environment.collector.recorded(requests[0])
        retry_recovered = environment.collector.cast(requests[0]) == receipts[0] == recovered
        if not retry_recovered or entry != environment.collector.entries[0]:
            raise AssertionError("Il recupero deve conservare gli oggetti originali")
        try:
            environment.collector.cast(voters[0].prepare_cast(1))
        except CredentialAlreadyUsed:
            duplicate_rejected = True
        else:
            raise AssertionError("Una richiesta diversa doveva essere rifiutata")

    step(4, "Raccoglitore: chiude la bacheca e firma la radice Merkle.")
    final_root = environment.finalize_board(at_time=environment.manifest.body.closes_at)
    entries = environment.collector.entries
    if requests and environment.collector.cast(requests[0]) != receipts[0]:
        raise AssertionError("Recupero dopo la chiusura non coerente")

    step(5, "Elettori: verificano l'inclusione delle proprie registrazioni.")
    for request, receipt in zip(requests, receipts, strict=True):
        index = receipt.body.index
        environment.verifier.verify_individual(
            receipt, request, entries[index], final_root, environment.collector.proof(index),
        )

    step(6, "Mix: apre lo strato esterno, mescola e pubblica le buste interne.")
    mix_result = environment.mix_ballots()
    step(7, "Commissione e trustee: eseguono e controllano lo scrutinio.")
    tally_result = environment.tally_votes()
    step(8, "Verificatore: controlla bacheca, radice e risultati pubblicati.")
    audit = environment.verifier.audit(
        entries=entries, final_root=final_root,
        mix_result=mix_result, tally_result=tally_result,
    )
    tally = tally_result.body
    result = {
        "election_id": environment.manifest.body.election_id,
        "voters": voter_count, "yes": tally.yes, "no": tally.no,
        "valid_count": tally.valid_count, "invalid_outer": tally.invalid_outer,
        "invalid_inner": tally.invalid_inner, "retry_recovered": retry_recovered,
        "duplicate_rejected": duplicate_rejected,
        "merkle_root": final_root.body.merkle_root, "audit": audit,
    }
    if not quiet:
        print("\nRisultato")
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


class TerminalApplication:
    def __init__(self) -> None:
        self.accounts = {f"studente-{index:03d}": "aps-demo" for index in range(1, 4)}
        self.environment: ElectionEnvironment | None = None
        self.voters: dict[str, VoterClient] = {}
        self.requests: dict[str, CastRequest] = {}
        self.receipts: dict[str, Receipt] = {}

    def _environment(self) -> ElectionEnvironment | None:
        if self.environment is None:
            print("Prima inizializza la consultazione.")
        return self.environment

    def setup(self) -> None:
        question = input("Quesito [Approvi la proposta sottoposta a referendum?]: ").strip()
        self.environment = ElectionEnvironment(
            self.accounts, question=question or "Approvi la proposta sottoposta a referendum?",
        )
        self.voters.clear()
        self.requests.clear()
        self.receipts.clear()
        print("Account di prova (password: aps-demo): " + ", ".join(self.accounts))
        print("Commissione: manifesto firmato. La votazione è aperta.")

    def vote(self) -> None:
        environment = self._environment()
        if environment is None:
            return
        if environment.collector.closed:
            print("La bacheca è già chiusa.")
            return
        student_id = input("Identificativo: ").strip()
        if student_id in self.requests:
            print("Richiesta già preparata: usa il recupero della registrazione.")
            return
        choice = input("1 per Sì, 0 per No: ").strip()
        if choice not in {"0", "1"}:
            print("Scelta non valida.")
            return
        password = input("Password di prova: ")
        voter = self.voters.get(student_id)
        if voter is None:
            voter = environment.new_voter()
            self.voters[student_id] = voter
        voter.authenticate(environment.idp, student_id, password)
        request = voter.prepare_cast(int(choice))
        self.requests[student_id] = request
        receipt = environment.collector.cast(request)
        environment.verifier.verify_receipt_for_request(receipt, request)
        self.receipts[student_id] = receipt
        print(f"Raccoglitore: richiesta accettata all'indice {receipt.body.index}.")
        print(f"Elettore: ricevuta verificata; hash della voce {receipt.body.entry_hash}.")

    def show_board(self) -> None:
        environment = self._environment()
        if environment is None:
            return
        print(f"Fase: {environment.phase}. Voci pubblicate: {len(environment.collector.entries)}")
        for entry in environment.collector.entries:
            print(f"  {entry.body.index}: {entry.entry_hash}")
        root = environment.collector.final_root
        if root is not None:
            print(f"Radice Merkle: {root.body.merkle_root}")

    def recover(self) -> None:
        environment = self._environment()
        if environment is None:
            return
        student_id = input("Studente da usare: ").strip()
        request = self.requests.get(student_id)
        if request is None:
            print("Nessuna richiesta preparata per questo studente.")
            return
        receipt = environment.collector.cast(request)
        entry, saved = environment.collector.recorded(request)
        environment.verifier.verify_receipt_for_request(receipt, request)
        if receipt != saved:
            raise AssertionError("Il recupero ha modificato la ricevuta originale")
        self.receipts[student_id] = receipt
        print(f"Raccoglitore: registrazione {entry.body.index} e ricevuta originali recuperate.")

    def finalize(self) -> None:
        environment = self._environment()
        if environment is None:
            return
        print("La simulazione avanza all'istante di chiusura del manifesto.")
        root = environment.finalize_board(at_time=environment.manifest.body.closes_at)
        environment.verifier.verify_final_root(root, environment.collector.entries)
        print(f"Raccoglitore: bacheca chiusa, radice firmata e verificata: {root.body.merkle_root}")

    def verify_receipt(self) -> None:
        environment = self._environment()
        if environment is None:
            return
        root = environment.collector.final_root
        if root is None:
            print("Prima chiudi la bacheca.")
            return
        student_id = input("Studente da verificare: ").strip()
        receipt = self.receipts.get(student_id)
        if receipt is None:
            print("Nessuna ricevuta disponibile per questo studente.")
            return
        index = receipt.body.index
        environment.verifier.verify_individual(
            receipt, self.requests[student_id], environment.collector.entries[index],
            root, environment.collector.proof(index),
        )
        print(f"Elettore: ricevuta valida, voce {index} inclusa nella radice finale.")

    def mix(self) -> None:
        environment = self._environment()
        if environment is not None:
            result = environment.mix_ballots()
            print(f"Mix: {result.body.output_count} buste interne pubblicate, "
                  f"{result.body.invalid_outer} errori esterni.")

    def tally(self) -> None:
        environment = self._environment()
        if environment is not None:
            result = environment.tally_votes().body
            print(f"Commissione e trustee: Sì {result.yes}, No {result.no}, "
                  f"non valide {result.invalid_outer + result.invalid_inner}.")

    def audit(self) -> None:
        environment = self._environment()
        if environment is None:
            return
        if environment.tally_result is None:
            print("Prima completa Mix e scrutinio.")
            return
        result = environment.verifier.audit(
            entries=environment.collector.entries, final_root=environment.collector.final_root,
            mix_result=environment.mix_result, tally_result=environment.tally_result,
        )
        print("Verificatore: controlli pubblici completati.")
        for name, value in result.items():
            print(f"  {name}: {value}")

    def run_scenario(self, name: str, student_id: str | None = None) -> bool:
        """Verifica un rifiuto sulla consultazione corrente; non sostituisce dati validi."""
        environment = self._environment()
        if environment is None:
            return False
        if name not in dict(SCENARIOS):
            raise ValueError("Scenario sconosciuto")
        expected: type[ProtocolError] = ValidationError
        action: Callable[[], Any]
        root = environment.collector.final_root
        mix = environment.mix_result
        tally = environment.tally_result

        if name == "wrong_password":
            student_id = student_id or next(iter(self.accounts), None)
            if student_id not in self.accounts:
                print("Serve un account di prova della consultazione.")
                return False
            voter = self.voters.get(student_id) or environment.new_voter()
            action = lambda: voter.authenticate(environment.idp, student_id, "password-errata")
            expected = AuthenticationError
            description = "IdP: verifica una password errata."
        elif name in {"second_vote", "tampered_request", "tampered_receipt", "tampered_proof"}:
            student_id = student_id or next(iter(self.receipts), None)
            if student_id not in self.receipts:
                print("Prima registra un voto per lo studente selezionato.")
                return False
            request, receipt = self.requests[student_id], self.receipts[student_id]
            if name == "second_vote":
                different = self.voters[student_id].prepare_cast(1)
                action = lambda: environment.collector.cast(different)
                expected = CredentialAlreadyUsed
                description = "Raccoglitore: applica FIRST_ACCEPTED a una seconda richiesta."
            elif name == "tampered_request":
                outer = request.body.outer_envelope
                altered = replace(request, body=replace(
                    request.body, outer_envelope=replace(outer, nonce=_alter_bytes(outer.nonce)),
                ))
                action = lambda: environment.collector.cast(altered)
                description = "Raccoglitore: verifica la firma di una richiesta alterata."
            elif name == "tampered_receipt":
                altered = replace(receipt, body=replace(
                    receipt.body, entry_hash=_alter_bytes(receipt.body.entry_hash),
                ))
                action = lambda: environment.verifier.verify_receipt_for_request(altered, request)
                description = "Elettore: verifica la firma di una ricevuta alterata."
            else:
                if root is None:
                    print("Prima chiudi la bacheca per ottenere la prova Merkle.")
                    return False
                index = receipt.body.index
                proof = environment.collector.proof(index)
                altered = replace(proof, tree_size=proof.tree_size + 1)
                action = lambda: environment.verifier.verify_individual(
                    receipt, request, environment.collector.entries[index], root, altered,
                )
                description = "Elettore: verifica una prova con numerosità alterata."
        else:
            if mix is None or root is None:
                print("Prima completa chiusura e Mix.")
                return False
            if name == "tampered_mix":
                altered = replace(mix, body=replace(mix.body, output_hash=_alter_bytes(mix.body.output_hash)))
                action = lambda: environment.verifier.verify_mix(altered, root)
                description = "Verificatore: controlla il record del Mix alterato."
            elif name == "tampered_tally":
                if tally is None:
                    print("Prima completa lo scrutinio.")
                    return False
                altered = replace(tally, body=replace(tally.body, mix_hash=_alter_bytes(tally.body.mix_hash)))
                action = lambda: environment.verifier.verify_tally(altered, mix, root)
                description = "Verificatore: controlla il risultato alterato."
            else:
                action = lambda: environment.commission.tally(
                    mix, root, environment.trustee_ids[:1], environment.verifier,
                    entries=environment.collector.entries,
                )
                expected = ThresholdError
                description = "Commissione: verifica il quorum con un solo trustee."
        print(description)
        try:
            action()
        except expected as exc:
            print(f"Rifiuto atteso: {exc}")
            return True
        raise AssertionError("Il controllo ha accettato lo scenario che doveva rifiutare")

    def scenarios(self) -> None:
        if self._environment() is None:
            return
        print("\nScenari sulla consultazione corrente")
        for index, (_, title) in enumerate(SCENARIOS, 1):
            print(f"{index}. {title}")
        choice = input("Scenario [0 per tornare]: ").strip()
        if choice == "0":
            return
        if choice not in {str(index) for index in range(1, len(SCENARIOS) + 1)}:
            print("Opzione non valida.")
            return
        name = SCENARIOS[int(choice) - 1][0]
        student_id = None
        if name in {"wrong_password", "second_vote", "tampered_request", "tampered_receipt", "tampered_proof"}:
            student_id = input("Identificativo [invio per il primo disponibile]: ").strip() or None
        self.run_scenario(name, student_id)

    def run(self) -> None:
        actions = {
            "1": self.setup, "2": self.vote, "3": self.show_board, "4": self.recover,
            "5": self.finalize, "6": self.verify_receipt, "7": self.mix, "8": self.tally,
            "9": self.audit, "10": self.scenarios, "11": lambda: run_demo(6),
        }
        while True:
            print(
                "\nPrototipo APS\n1. Inizializza\n2. Autentica e vota\n3. Mostra bacheca\n"
                "4. Recupera registrazione e ricevuta\n5. Chiudi e pubblica la radice Merkle\n"
                "6. Verifica una ricevuta\n7. Esegui Mix\n8. Esegui scrutinio\n9. Audit\n"
                "10. Scenari sulla consultazione corrente\n11. Demo automatica separata\n0. Esci"
            )
            choice = input("Scelta: ").strip()
            if choice == "0":
                return
            try:
                actions.get(choice, lambda: print("Opzione non valida."))()
            except (ProtocolError, ValueError) as exc:
                print(f"Operazione rifiutata: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prototipo APS con messaggi JSON")
    parser.add_argument("--demo", action="store_true", help="esegue la demo automatica")
    parser.add_argument("--voters", type=int, default=6, help="elettori della demo")
    args = parser.parse_args()
    if args.demo:
        if args.voters < 0:
            parser.error("Il numero di elettori deve essere non negativo")
        run_demo(args.voters)
    else:
        try:
            TerminalApplication().run()
        except (EOFError, KeyboardInterrupt):
            print("\nChiusura del programma.")


if __name__ == "__main__":
    main()
