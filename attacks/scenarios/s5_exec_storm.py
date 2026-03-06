"""
s5_exec_storm.py — T1609 Container Administration Command
=========================================================

Выполняет серию kubectl exec в поды разных namespace.
Имитирует атакующего, который получил доступ к кластеру и
исследует контейнеры через exec.

Ожидаемые сигналы:
  Audit:    feat_exec_events_count >> базлайн (10-30 exec/мин)
            feat_cross_namespace_access (exec в разные namespace)
            feat_unusual_agents_count (нетипичный user-agent)
  Logs:     feat_unseen_templates (shell команды в логах контейнеров)
"""

import subprocess
import time

# Команды которые будем выполнять в подах (безвредные разведчательные)
RECON_COMMANDS = [
    "id",
    "whoami",
    "hostname",
    "cat /etc/passwd | head -5",
    "env | grep -i secret || true",
    "env | grep -i token || true",
    "ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null || true",
    "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 50 || true",
    "ps aux 2>/dev/null | head -10 || true",
    "cat /proc/net/tcp 2>/dev/null | head -10 || true",
    "ls /root 2>/dev/null || true",
    "find / -name '*.key' -maxdepth 5 2>/dev/null | head -5 || true",
]

# Namespace из которых выбираем поды для exec
TARGET_NAMESPACES = ["default", "monitoring", "kafka", "postgres", "kube-system"]
EXEC_ROUNDS = 3   # раундов перебора
SLEEP_BETWEEN = 3  # секунд между exec


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S5] Starting kubectl exec storm...")
    print(f"     Target namespaces: {TARGET_NAMESPACES}")
    print(f"     Commands per pod: {len(RECON_COMMANDS)}")
    print(f"     Rounds: {EXEC_ROUNDS}")

    # Собираем список доступных подов
    pods_by_ns = {}
    for ns in TARGET_NAMESPACES:
        pods = _get_running_pods(ns)
        if pods:
            pods_by_ns[ns] = pods[:3]  # не более 3 подов на namespace
            print(f"     Found pods in {ns}: {pods_by_ns[ns]}")

    if not pods_by_ns:
        print("     ⚠️  No running pods found in target namespaces")
        print("     Using default namespace only...")
        pods_by_ns = {namespace: _get_running_pods(namespace)}

    total_exec = 0
    for round_num in range(EXEC_ROUNDS):
        print(f"\n[S5] Round {round_num + 1}/{EXEC_ROUNDS}")
        for ns, pods in pods_by_ns.items():
            for pod in pods:
                for cmd in RECON_COMMANDS[:4]:  # по 4 команды на под за раунд
                    if dry_run:
                        print(f"[DRY] kubectl exec {pod} -n {ns} -- sh -c '{cmd}'")
                        continue
                    _exec_in_pod(pod, ns, cmd)
                    total_exec += 1
                    time.sleep(SLEEP_BETWEEN)

        if round_num < EXEC_ROUNDS - 1:
            print(f"     Round {round_num+1} done. Brief pause...")
            time.sleep(10)

    print(f"\n[S5] Exec storm complete. Total exec calls: {total_exec}")
    # Нет cleanup — exec не создаёт ресурсов


def cleanup(namespace: str = "default"):
    pass  # exec не создаёт K8s ресурсов


def _get_running_pods(namespace: str) -> list:
    """Возвращает имена Running подов в namespace."""
    result = subprocess.run(
        ["kubectl", "get", "pods", "-n", namespace,
         "--field-selector=status.phase=Running",
         "-o", "jsonpath={.items[*].metadata.name}"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return []
    names = result.stdout.strip().split()
    return [n for n in names if n]


def _exec_in_pod(pod: str, namespace: str, command: str):
    """Выполняет команду в поде. Ошибки игнорируем."""
    result = subprocess.run(
        ["kubectl", "exec", pod, "-n", namespace,
         "--", "sh", "-c", command],
        capture_output=True, text=True, timeout=10
    )
    status = "✓" if result.returncode == 0 else "✗"
    print(f"     {status} exec {pod} -n {namespace}: {command[:40]}")
