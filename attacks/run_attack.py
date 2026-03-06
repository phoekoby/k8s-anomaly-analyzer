"""
run_attack.py — Оркестратор сценариев атак
==========================================

Запускает выбранный сценарий, пишет метку в attack_labels.csv.

Использование:
    python run_attack.py --scenario s1_cryptominer
    python run_attack.py --scenario s2_secrets_enum --namespace default --runs 3
    python run_attack.py --list
    python run_attack.py --show-labels

Файл меток: attacks/attack_labels.csv
    scenario, namespace, start_utc, end_utc, mitre_technique, run_id
"""

import argparse
import csv
import importlib
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

LABELS_FILE   = Path(__file__).parent / "attack_labels.csv"
SCENARIOS_DIR = Path(__file__).parent / "scenarios"

# ── Метаданные сценариев ──────────────────────────────────────────────────────
SCENARIO_META = {
    # ── Атаки ─────────────────────────────────────────────────────────────────
    "s1_cryptominer":    {"mitre": "T1496", "type": "attack",
                          "desc": "Resource Hijacking — stress-ng CPU miner + outbound to mining pool"},
    "s2_secrets_enum":   {"mitre": "T1552", "type": "attack",
                          "desc": "Credential Access — mass GET/LIST secrets via Job"},
    "s3_privileged_pod": {"mitre": "T1611", "type": "attack",
                          "desc": "Escape to Host — privileged pod with hostPID + hostPath"},
    "s4_network_scan":   {"mitre": "T1046", "type": "attack",
                          "desc": "Network Discovery — nmap SYN scan of cluster CIDR"},
    "s5_exec_storm":     {"mitre": "T1609", "type": "attack",
                          "desc": "Execution — kubectl exec storm across namespaces"},
    "s6_lateral_move":   {"mitre": "T1210", "type": "attack",
                          "desc": "Lateral Movement — cross-namespace SA + service probing"},
    "s8_http_error_storm": {"mitre": "T1190", "type": "attack",
                            "desc": "Exploit Public App — HTTP fuzzing + path traversal storm"},
    "s9_rbac_escalation":  {"mitre": "T1098", "type": "attack",
                            "desc": "Account Manipulation — ClusterRoleBinding cluster-admin grant"},
    "s10_exfiltration":    {"mitre": "T1041", "type": "attack",
                            "desc": "Exfiltration over C2 — large outbound transfer + DNS fan-out"},
    "s11_brute_force":     {"mitre": "T1110", "type": "attack",
                            "desc": "Brute Force — 200+ invalid auth requests to K8s API"},
    # ── Контрольные (не атаки, для FP measurement) ────────────────────────────
    "s7_oom_control":    {"mitre": "CONTROL", "type": "control",
                          "desc": "OOMKill crashloop — operational incident, NOT an attack"},
}

# ── Покрытие MITRE ATT&CK ─────────────────────────────────────────────────────
MITRE_COVERAGE = """
MITRE ATT&CK for Containers Coverage:
  T1190 Exploit Public App      → S8  (Logs + Network + Metrics)
  T1609 Container Exec          → S5  (Audit)
  T1611 Escape to Host          → S3  (Audit + Metrics)
  T1098 Account Manipulation    → S9  (Audit)
  T1610 Deploy Container        → S1  (Audit + Metrics)
  T1210 Lateral Movement        → S6  (Audit + Network)
  T1552 Credential Access       → S2  (Audit)
  T1046 Network Discovery       → S4  (Network)
  T1041 Exfiltration over C2    → S10 (Network + Metrics)
  T1496 Resource Hijacking      → S1  (Metrics + Network)
  T1110 Brute Force             → S11 (Audit + Network)
  CONTROL Operational incident  → S7  (Metrics + Logs) [FP measurement]
"""


def write_label(scenario: str, namespace: str, start: datetime, end: datetime,
                mitre: str, scenario_type: str, run_id: str):
    write_header = not LABELS_FILE.exists()
    with open(LABELS_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["scenario", "namespace", "start_utc", "end_utc",
                             "mitre_technique", "type", "run_id"])
        writer.writerow([
            scenario,
            namespace,
            start.strftime("%Y-%m-%d %H:%M:%S"),
            end.strftime("%Y-%m-%d %H:%M:%S"),
            mitre,
            scenario_type,
            run_id,
        ])
    print(f"  ✅ Label written: {start.strftime('%H:%M:%S')} → {end.strftime('%H:%M:%S')} "
          f"[{mitre}] run={run_id}")


def run_scenario(scenario_name: str, namespace: str, run_id: str, dry_run: bool = False):
    meta = SCENARIO_META.get(scenario_name)
    if not meta:
        print(f"❌ Unknown scenario: {scenario_name}")
        print(f"   Available: {', '.join(SCENARIO_META.keys())}")
        sys.exit(1)

    tag = "⚠️  CONTROL" if meta["type"] == "control" else "🔴 ATTACK"
    print(f"\n{'='*60}")
    print(f"  {tag}   : {scenario_name}")
    print(f"  MITRE    : {meta['mitre']}")
    print(f"  Desc     : {meta['desc']}")
    print(f"  Namespace: {namespace}")
    print(f"  Run ID   : {run_id}  |  Dry run: {dry_run}")
    print(f"{'='*60}\n")

    sys.path.insert(0, str(SCENARIOS_DIR))
    module = importlib.import_module(scenario_name)

    start = datetime.now(timezone.utc)
    print(f"⏱  START: {start.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    try:
        module.run(namespace=namespace, dry_run=dry_run)
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted — running cleanup...")
        if hasattr(module, "cleanup"):
            module.cleanup(namespace=namespace)
        raise
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if hasattr(module, "cleanup"):
            module.cleanup(namespace=namespace)
        raise

    end = datetime.now(timezone.utc)
    print(f"\n⏱  END: {end.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"   Duration: {int((end - start).total_seconds())}s")

    if not dry_run:
        write_label(scenario_name, namespace, start, end,
                    meta["mitre"], meta["type"], run_id)

    print(f"\n✅ Done: {scenario_name} (run {run_id})\n")


def main():
    parser = argparse.ArgumentParser(
        description="Attack scenario runner for ClusterAnomalyAnalyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--scenario",   help="Scenario name to run")
    parser.add_argument("--namespace",  default="default")
    parser.add_argument("--runs",       type=int, default=1,
                        help="Repetitions (default 1, use 5 for statistical significance)")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Print commands without executing kubectl")
    parser.add_argument("--list",       action="store_true",
                        help="List available scenarios")
    parser.add_argument("--coverage",   action="store_true",
                        help="Show MITRE ATT&CK coverage")
    parser.add_argument("--show-labels", action="store_true",
                        help="Print current attack_labels.csv")
    parser.add_argument("--pause",      type=int, default=120,
                        help="Seconds to wait between runs (default 120)")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable scenarios:\n")
        attacks  = [(n, m) for n, m in SCENARIO_META.items() if m["type"] == "attack"]
        controls = [(n, m) for n, m in SCENARIO_META.items() if m["type"] == "control"]
        print("  ATTACKS:")
        for name, meta in attacks:
            print(f"    {name:<26} [{meta['mitre']:<8}] {meta['desc']}")
        print("\n  CONTROL (for FP measurement):")
        for name, meta in controls:
            print(f"    {name:<26} [{meta['mitre']:<8}] {meta['desc']}")
        print()
        return

    if args.coverage:
        print(MITRE_COVERAGE)
        return

    if args.show_labels:
        if LABELS_FILE.exists():
            print(LABELS_FILE.read_text())
        else:
            print("No labels file yet.")
        return

    if not args.scenario:
        parser.print_help()
        sys.exit(1)

    for i in range(args.runs):
        run_id = str(uuid.uuid4())[:8]
        if args.runs > 1:
            print(f"\n>>> Run {i+1}/{args.runs}")
        run_scenario(args.scenario, args.namespace, run_id, dry_run=args.dry_run)

        if i < args.runs - 1:
            print(f"  Waiting {args.pause}s before next run (cluster cooldown)...")
            time.sleep(args.pause)


if __name__ == "__main__":
    main()
