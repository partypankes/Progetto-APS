"""Tempi delle fasi e dimensioni JSON su consultazioni indipendenti.

Le misure *_mean sono medie per elettore nella singola consultazione.
Le altre misure riguardano l'intera consultazione. Conteggi di controllo,
dimensioni, riepiloghi e scrittura dei risultati sono fuori dai timer.
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend

from crypto_utils import serialized_size
from election import ElectionEnvironment


def measure(operation: Callable[[], Any]) -> tuple[Any, float]:
    start = time.perf_counter_ns()
    result = operation()
    return result, (time.perf_counter_ns() - start) / 1_000_000


def benchmark_scenario(voter_count: int) -> dict[str, dict[str, float]]:
    if type(voter_count) is not int or voter_count < 1:
        raise ValueError("Il benchmark richiede almeno un elettore")
    accounts = {
        f"bench-{index:04d}": f"password-prova-{index:04d}"
        for index in range(voter_count)
    }
    # Chiavi delle autorità, manifesto, quote Shamir e preparazione account.
    environment, setup = measure(lambda: ElectionEnvironment(accounts))
    credentials, requests, receipts = [], [], []
    client_creation, authentication, preparation, collection, receipt_verification = [], [], [], [], []

    for index, (student_id, password) in enumerate(accounts.items()):
        # Verifica del manifesto e generazione della chiave temporanea RSA.
        voter, elapsed = measure(environment.new_voter)
        client_creation.append(elapsed)
        credential, elapsed = measure(
            lambda: voter.authenticate(environment.idp, student_id, password)
        )
        credentials.append(credential)
        authentication.append(elapsed)
        request, elapsed = measure(lambda: voter.prepare_cast(index % 2))
        requests.append(request)
        preparation.append(elapsed)
        receipt, elapsed = measure(lambda: environment.collector.cast(request))
        receipts.append(receipt)
        collection.append(elapsed)
        _, elapsed = measure(
            lambda: environment.verifier.verify_receipt_for_request(receipt, request)
        )
        receipt_verification.append(elapsed)

    final_root, root_time = measure(
        lambda: environment.finalize_board(at_time=environment.manifest.body.closes_at)
    )
    entries = environment.collector.entries
    proofs, proof_generation, individual = [], [], []
    for request, receipt in zip(requests, receipts, strict=True):
        index = receipt.body.index
        proof, elapsed = measure(lambda: environment.collector.proof(index))
        proofs.append(proof)
        proof_generation.append(elapsed)
        _, elapsed = measure(
            lambda: environment.verifier.verify_individual(
                receipt, request, entries[index], final_root, proof,
            )
        )
        individual.append(elapsed)

    mix_result, mix_time = measure(environment.mix_ballots)
    # Ricostruzione della chiave, scrutinio e controlli dei due trustee firmatari.
    tally_result, tally_time = measure(environment.tally_votes)
    _, audit_time = measure(
        lambda: environment.verifier.audit(
            entries=entries, final_root=final_root,
            mix_result=mix_result, tally_result=tally_result,
        )
    )
    tally = tally_result.body
    if (
        tally.yes != voter_count // 2 or tally.no != (voter_count + 1) // 2
        or tally.valid_count != voter_count
        or tally.invalid_outer != 0 or tally.invalid_inner != 0
    ):
        raise RuntimeError("Il risultato del benchmark non coincide con i voti inviati")

    timings = {
        "environment_setup": setup,
        "voter_client_creation_mean": statistics.mean(client_creation),
        "authentication_mean": statistics.mean(authentication),
        "ballot_preparation_mean": statistics.mean(preparation),
        "collector_validation_mean": statistics.mean(collection),
        "receipt_verification_mean": statistics.mean(receipt_verification),
        "final_merkle_root": root_time,
        "merkle_proof_generation_mean": statistics.mean(proof_generation),
        "individual_inclusion_mean": statistics.mean(individual),
        "mix_total": mix_time,
        "tally_total": tally_time,
        "universal_audit_total": audit_time,
    }
    sizes = {
        "manifest": serialized_size(environment.manifest),
        "credential_mean": statistics.mean(map(serialized_size, credentials)),
        "cast_request_mean": statistics.mean(map(serialized_size, requests)),
        "board_entry_mean": statistics.mean(map(serialized_size, entries)),
        "receipt_mean": statistics.mean(map(serialized_size, receipts)),
        "final_root": serialized_size(final_root),
        "merkle_proof_mean": statistics.mean(map(serialized_size, proofs)),
        "mix_record_total": serialized_size(mix_result),
        "mix_list_total": serialized_size(mix_result.inner_envelopes),
        "tally_result": serialized_size(tally_result),
        "public_board_total": serialized_size(entries),
    }
    return {"timings_ms": timings, "sizes_bytes": sizes}


def write_csv(voter_counts: list[int], output: Path, runs: int = 5) -> Path:
    if (
        not voter_counts or any(type(count) is not int or count < 1 for count in voter_counts)
        or type(runs) is not int or runs < 2
    ):
        raise ValueError("Servono carichi positivi e almeno due esecuzioni per carico")
    if len(voter_counts) != len(set(voter_counts)):
        raise ValueError("I carichi non devono ripetersi")
    output.parent.mkdir(parents=True, exist_ok=True)
    summary_path = output.with_name(output.stem + "_summary.csv")
    environment_path = output.with_name(output.stem + "_environment.json")
    environment_path.write_text(json.dumps({
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
        "voters": voter_counts,
        "runs_per_load": runs,
        "timer": "time.perf_counter_ns, elapsed milliseconds",
        "summary": "Mean and sample standard deviation across independent runs",
        "per_voter_metrics": "*_mean: within-run mean, then aggregated across runs",
        "setup_includes": "Authority keys, manifest, secret shares and account setup",
        "client_creation_includes": "Manifest verification and temporary RSA key generation",
        "tally_includes": "Key reconstruction, tally and checks by two signing trustees",
        "size_encoding": "Deterministic UTF-8 JSON; Merkle proof includes index, tree_size, path",
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    summaries = []
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["voters", "run", "metric", "unit", "value"])
        for voter_count in voter_counts:
            observations: dict[tuple[str, str], list[float]] = {}
            for run in range(1, runs + 1):
                result = benchmark_scenario(voter_count)
                for group, unit in (("timings_ms", "ms"), ("sizes_bytes", "bytes")):
                    for metric, value in result[group].items():
                        writer.writerow([voter_count, run, metric, unit, f"{value:.6f}"])
                        observations.setdefault((metric, unit), []).append(value)
                stream.flush()
                print(f"n={voter_count}, esecuzione {run}/{runs}: completata", flush=True)
            for (metric, unit), values in observations.items():
                summaries.append([
                    voter_count, runs, metric, unit,
                    f"{statistics.mean(values):.6f}", f"{statistics.stdev(values):.6f}",
                ])
    with summary_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["voters", "runs", "metric", "unit", "mean", "stddev"])
        writer.writerows(summaries)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark APS con messaggi JSON")
    parser.add_argument("--voters", default="10,50,100", help="Carichi separati da virgole")
    parser.add_argument("--runs", type=int, default=5, help="Esecuzioni per carico (almeno 2)")
    parser.add_argument("--output", default="results/benchmark.csv", help="CSV delle singole esecuzioni")
    args = parser.parse_args()
    try:
        counts = [int(value.strip()) for value in args.voters.split(",")]
        path = write_csv(counts, Path(args.output), args.runs)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"Risultati: {path.resolve()}")
    print(f"Riepilogo: {path.with_name(path.stem + '_summary.csv').resolve()}")
    print(f"Ambiente: {path.with_name(path.stem + '_environment.json').resolve()}")


if __name__ == "__main__":
    main()
