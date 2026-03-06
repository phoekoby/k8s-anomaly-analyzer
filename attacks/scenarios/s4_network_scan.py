"""
s4_network_scan.py — T1046 Network Service Discovery
====================================================

Запускает под с nmap внутри кластера. Сканирует CIDR подсети кластера
и перебирает порты известных сервисов.

Ожидаемые сигналы:
  Network:  feat_syn_count >> базлайн (тысячи SYN пакетов)
            feat_port_diversity_ratio >> 0.5
            feat_wellknown_ports_scanned всплеск
            feat_dropped_flows (Cilium блокирует часть)
            feat_lateral_flow_count (трафик между namespace)
  Audit:    feat_new_pod_count (создание пода)
"""

import subprocess
import time

POD_NAME = "attack-network-scanner"

# CIDR для сканирования — Service CIDR кластера (обычно 10.96.0.0/12)
# Можно посмотреть: kubectl cluster-info dump | grep service-cluster-ip-range
SCAN_TARGETS = "10.96.0.0/16"
# Порты для сканирования (известные сервисы K8s + common services)
SCAN_PORTS   = "22,80,443,2379,2380,3306,5432,6379,8080,8443,9000,9090,9093,9200,10250,10255"

POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  labels:
    app: {POD_NAME}
    attack-scenario: s4-network-scan
spec:
  restartPolicy: Never
  containers:
  - name: scanner
    image: instrumentisto/nmap:latest
    command:
    - /bin/sh
    - -c
    - |
      echo "[attack] Starting network reconnaissance..."

      echo "[attack] Phase 1: Host discovery ping sweep..."
      nmap -sn {SCAN_TARGETS} --min-rate 500 -T4 2>/dev/null | tail -5

      echo "[attack] Phase 2: Port scan on discovered hosts..."
      nmap -sS -p {SCAN_PORTS} {SCAN_TARGETS} --min-rate 1000 -T4 \
           --open --max-retries 1 2>/dev/null | grep -E "(open|filtered|Nmap scan)" | head -50

      echo "[attack] Phase 3: Service version detection on top targets..."
      # Детектируем версии сервисов на apiserver порту
      nmap -sV -p 443,6443,8080 {SCAN_TARGETS} -T3 2>/dev/null | head -30

      echo "[attack] Phase 4: UDP scan for DNS..."
      nmap -sU -p 53 10.96.0.0/24 -T4 2>/dev/null | head -20 || true

      echo "[attack] Scan complete."
    securityContext:
      capabilities:
        add: ["NET_RAW", "NET_ADMIN"]
    resources:
      requests:
        cpu: "500m"
        memory: "128Mi"
"""

ATTACK_DURATION = 180  # nmap обычно завершается за 2-3 минуты


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S4] Deploying network scanner pod '{POD_NAME}' in namespace '{namespace}'...")
    print(f"     Scan target: {SCAN_TARGETS}")
    print(f"     Ports: {SCAN_PORTS}")

    if dry_run:
        print(f"[DRY] Would create pod with nmap, scan {SCAN_TARGETS}:{SCAN_PORTS}")
        return

    _apply(POD_MANIFEST, namespace)

    print("[S4] Waiting for pod to start...")
    _wait_for_pod(POD_NAME, namespace, timeout=90)

    print(f"[S4] Scanner running. Waiting up to {ATTACK_DURATION}s for completion...")
    print(f"     Watch: kubectl logs -f {POD_NAME} -n {namespace}")

    # Ждём завершения пода (Succeeded) или timeout
    _wait_for_pod(POD_NAME, namespace, state="Succeeded", timeout=ATTACK_DURATION)

    print("[S4] Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    print(f"[S4] Deleting scanner pod {POD_NAME}...")
    subprocess.run(
        ["kubectl", "delete", "pod", POD_NAME, "-n", namespace,
         "--ignore-not-found", "--grace-period=0", "--force"],
        capture_output=True
    )
    print("[S4] Cleanup done.")


def _apply(manifest: str, namespace: str):
    cmd = ["kubectl", "apply", "-n", namespace, "-f", "-"]
    result = subprocess.run(cmd, input=manifest.encode(), capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl apply failed: {result.stderr.decode()}")
    print(f"     {result.stdout.decode().strip()}")


def _wait_for_pod(name: str, namespace: str, state: str = "Running", timeout: int = 90):
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
        if phase == "Failed":
            print(f"     ⚠️  Pod failed!")
            return
        print(f"     Phase: {phase or 'Pending'}... waiting")
        time.sleep(8)
    print(f"     ⚠️  Timeout waiting for {state}")
