"""
s11_brute_force.py — T1110 Brute Force / Credential Stuffing
=============================================================

Симулирует brute force атаку на Kubernetes API Server:
множество запросов с неверными токенами → шквал 401/403.

Дополнительно имитирует brute force на внутренние сервисы.

Почему ценен для ВКР:
  Демонстрирует детекцию через КОМБИНАЦИЮ каналов:
  - Audit: feat_failed_requests_count (сотни 401 за минуту)
  - Network: feat_syn_count (много новых соединений)
  - Metrics: без изменений (атака не потребляет ресурсы пода-жертвы)
  Показывает что Logs-канал здесь СЛЕПОЙ — ошибки auth в kube-apiserver
  не попадают в application logs. Это аргумент для multi-modal.

Ожидаемые сигналы:
  Audit:    feat_failed_requests_count >> 50/мин
            feat_failed_ratio > 0.9
            feat_anonymous_count рост (запросы без токена)
            feat_unique_source_ips (один IP, но много запросов)
  Network:  feat_syn_count рост (много TCP соединений к API)
            feat_suspicious_port_hits (6443 — K8s API port)
  Logs:     без значимых изменений
"""

import subprocess
import time

POD_NAME = "attack-brute-force"

# K8s API endpoint внутри кластера
K8S_API = "https://kubernetes.default.svc.cluster.local"

POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  labels:
    app: {POD_NAME}
    attack-scenario: s11-brute-force
spec:
  restartPolicy: Never
  containers:
  - name: bruteforce
    image: curlimages/curl:latest
    command:
    - /bin/sh
    - -c
    - |
      echo "[attack] Brute force simulation started"
      K8S_API="{K8S_API}"

      echo "[attack] Phase 1: Anonymous requests (no token)..."
      for i in $(seq 1 30); do
        curl -sk -o /dev/null -w "%{{http_code}}\\n" \
             --connect-timeout 2 --max-time 3 \
             "$K8S_API/api/v1/secrets" 2>/dev/null
        sleep 0.1
      done

      echo "[attack] Phase 2: Invalid token credential stuffing..."
      # Генерируем случайные "токены"
      for i in $(seq 1 100); do
        FAKE_TOKEN=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 64)
        curl -sk -o /dev/null -w "%{{http_code}}\\n" \
             -H "Authorization: Bearer $FAKE_TOKEN" \
             --connect-timeout 2 --max-time 3 \
             "$K8S_API/api/v1/namespaces/kube-system/secrets" 2>/dev/null
        sleep 0.05
      done

      echo "[attack] Phase 3: Malformed JWT attempts..."
      for i in $(seq 1 50); do
        curl -sk -o /dev/null -w "%{{http_code}}\\n" \
             -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.AAAA.BBBB" \
             --connect-timeout 2 --max-time 3 \
             "$K8S_API/api/v1/namespaces" 2>/dev/null
        sleep 0.1
      done

      echo "[attack] Phase 4: Rapid fire on multiple endpoints..."
      ENDPOINTS="/api/v1/pods /api/v1/secrets /apis/rbac.authorization.k8s.io/v1/clusterroles /api/v1/nodes"
      for endpoint in $ENDPOINTS; do
        for i in $(seq 1 25); do
          curl -sk -o /dev/null \
               -H "Authorization: Bearer invalid-token-$i" \
               --connect-timeout 1 --max-time 2 \
               "$K8S_API$endpoint" 2>/dev/null
          sleep 0.05
        done
      done

      echo "[attack] Brute force simulation complete."
      echo "[attack] Expected: ~200+ failed auth events in audit log"
    resources:
      requests:
        cpu: "200m"
        memory: "64Mi"
"""

ATTACK_DURATION = 180


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S11] Deploying brute force pod '{POD_NAME}' in '{namespace}'")
    print(f"      Target: {K8S_API}")
    print(f"      Expected: ~200 failed auth requests → feat_failed_requests_count spike")

    if dry_run:
        print("[DRY] Would create pod sending 200+ invalid auth requests to K8s API")
        return

    _apply(POD_MANIFEST, namespace)

    print("[S11] Waiting for pod to start...")
    _wait_for_phase(POD_NAME, namespace, "Running", timeout=60)

    print(f"[S11] Brute force running...")
    print(f"      Watch: kubectl logs -f {POD_NAME} -n {namespace}")
    _wait_for_phase(POD_NAME, namespace, "Succeeded", timeout=ATTACK_DURATION)

    print("[S11] Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    subprocess.run(
        ["kubectl", "delete", "pod", POD_NAME, "-n", namespace,
         "--ignore-not-found", "--grace-period=0", "--force"],
        capture_output=True
    )
    print("[S11] Cleanup done.")


def _apply(manifest: str, namespace: str):
    result = subprocess.run(
        ["kubectl", "apply", "-n", namespace, "-f", "-"],
        input=manifest.encode(), capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"kubectl apply failed: {result.stderr.decode()}")
    print(f"      {result.stdout.decode().strip()}")


def _wait_for_phase(name: str, namespace: str, phase: str, timeout: int = 60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["kubectl", "get", "pod", name, "-n", namespace,
             "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True
        )
        current = result.stdout.strip()
        if current == phase:
            print(f"      Phase: {phase} ✓")
            return
        if current == "Failed":
            print("      ⚠️  Pod failed")
            return
        print(f"      Phase: {current or 'Pending'}...")
        time.sleep(8)
    print(f"      ⚠️  Timeout waiting for {phase}")
