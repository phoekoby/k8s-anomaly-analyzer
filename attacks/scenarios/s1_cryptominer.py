"""
s1_cryptominer.py — T1496 Resource Hijacking
=============================================

Симулирует cryptominer: pod со stress-ng нагружает CPU на 5 минут.
Дополнительно пытается делать outbound соединения на известные mining-pool порты
чтобы триггернуть network-канал.

Ожидаемые сигналы:
  Metrics:  feat_cluster_cpu_spike >> 2.0, feat_cpu_requests_cores всплеск
  Logs:     feat_unseen_templates (неизвестные логи нового пода)
  Audit:    feat_new_pod_count (создание пода)
  Network:  feat_external_egress (попытка соединения наружу)
"""

import subprocess
import time

ATTACK_DURATION = 300  # 5 минут — достаточно для нескольких окон коллектора
POD_NAME = "attack-cryptominer"

# Известные mining-pool порты для симуляции outbound трафика
# Используем nc (netcat) — просто попытка соединения, не реальный майнинг
MINING_POOL_IPS = [
    "pool.supportxmr.com",  # XMR pool
    "xmr.pool.minergate.com",
]
MINING_PORTS = [3333, 4444, 14444]

POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  labels:
    app: {POD_NAME}
    attack-scenario: s1-cryptominer
spec:
  restartPolicy: Never
  containers:
  - name: miner
    image: debian:slim
    command:
    - /bin/sh
    - -c
    - |
      apt-get update -qq && apt-get install -y -qq stress-ng netcat-openbsd 2>/dev/null
      echo "[attack] Starting CPU stress (simulated cryptominer)..."
      # stress-ng на все доступные CPU на ATTACK_DURATION секунд
      stress-ng --cpu 0 --timeout {ATTACK_DURATION}s --metrics-brief &
      STRESS_PID=$!
      # Попытки outbound соединений на mining-pool порты (триггер network-канала)
      for i in $(seq 1 10); do
        nc -z -w 2 pool.supportxmr.com 3333 2>/dev/null || true
        nc -z -w 2 xmr.pool.minergate.com 4444 2>/dev/null || true
        sleep 30
      done
      wait $STRESS_PID
      echo "[attack] Done."
    resources:
      requests:
        cpu: "2000m"
        memory: "256Mi"
      limits:
        cpu: "4000m"
        memory: "512Mi"
"""


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S1] Deploying cryptominer pod '{POD_NAME}' in namespace '{namespace}'...")
    print(f"     Duration: {ATTACK_DURATION}s ({ATTACK_DURATION//60}m)")

    _kubectl_apply(POD_MANIFEST, namespace, dry_run)

    if dry_run:
        print(f"[DRY] Would wait {ATTACK_DURATION}s for pod to finish")
        return

    # Ждём пока под запустится
    print("[S1] Waiting for pod to start...")
    _wait_for_pod(POD_NAME, namespace, state="Running", timeout=60)

    print(f"[S1] Pod running. Stress-ng active for {ATTACK_DURATION}s...")
    print(f"     Watch: kubectl logs -f {POD_NAME} -n {namespace}")

    # Ждём завершения
    time.sleep(ATTACK_DURATION + 30)  # +30с на завершение

    print("[S1] Attack duration passed. Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    print(f"[S1] Deleting pod {POD_NAME}...")
    subprocess.run(
        ["kubectl", "delete", "pod", POD_NAME, "-n", namespace,
         "--ignore-not-found", "--grace-period=0", "--force"],
        capture_output=True
    )
    print(f"[S1] Cleanup done.")


def _kubectl_apply(manifest: str, namespace: str, dry_run: bool):
    cmd = ["kubectl", "apply", "-n", namespace, "-f", "-"]
    if dry_run:
        print(f"[DRY] kubectl apply -n {namespace} -f - <<EOF\n{manifest}\nEOF")
        return
    result = subprocess.run(cmd, input=manifest.encode(), capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl apply failed: {result.stderr.decode()}")
    print(f"     {result.stdout.decode().strip()}")


def _wait_for_pod(name: str, namespace: str, state: str = "Running", timeout: int = 60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["kubectl", "get", "pod", name, "-n", namespace,
             "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True
        )
        phase = result.stdout.strip()
        if phase == state:
            print(f"     Pod phase: {phase} ✓")
            return
        print(f"     Pod phase: {phase or 'Pending'}... waiting")
        time.sleep(5)
    print(f"     ⚠️  Timeout waiting for pod {state}")
