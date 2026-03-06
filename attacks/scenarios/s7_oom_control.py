"""
s7_oom_control.py — КОНТРОЛЬНЫЙ СЦЕНАРИЙ (не атака)
====================================================

ВАЖНО: Это НЕ атака. Это контрольный сценарий для измерения FP rate.

Симулирует легитимный операционный инцидент: pod с утечкой памяти
который OOMKill-ится и перезапускается в crashloop.

Цель: проверить что детектор НЕ путает операционный сбой с атакой,
или честно измерить сколько FP он генерирует на таких событиях.

Ожидаемые сигналы (операционные, не security):
  Metrics:  feat_container_restarts_max всплеск (crashloop)
            feat_crashloop_signal = 1
            feat_pods_not_ready рост
            feat_cluster_mem_used_bytes рост перед OOMKill
  Logs:     feat_error_count всплеск (OOM error messages)
            feat_unseen_templates (OOM killer log patterns)
  Audit:    feat_new_pod_count (restart создаёт новый pod)
  Network:  без изменений (нет сетевой аномалии)

Отличие от атак для LLM-классификатора (L3):
  - Нет audit-сигналов exec/secrets/RBAC
  - Нет cross-namespace трафика
  - Нет external connections
  - Есть характерный паттерн: memory рост → OOM → restart → repeat
"""

import subprocess
import time

POD_NAME = "control-oom-memleak"

# Pod который намеренно течёт по памяти до OOMKill
# Limit 128Mi → через ~60с съест всё и будет убит
POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  labels:
    app: {POD_NAME}
    scenario-type: control       # НЕ атака
    attack-scenario: s7-oom-control
spec:
  # restartPolicy: Always → будет crashloop после OOMKill
  restartPolicy: Always
  containers:
  - name: memleak
    image: python:3.11-slim
    command:
    - python3
    - -c
    - |
      import time, os, sys
      print("[control] Memory leak simulation started", flush=True)
      data = []
      chunk_size = 10 * 1024 * 1024  # 10MB chunks
      allocated = 0
      while True:
          data.append(b'x' * chunk_size)
          allocated += chunk_size
          print(f"[control] Allocated: {{allocated // 1024 // 1024}}MB", flush=True)
          time.sleep(1)
    resources:
      requests:
        cpu: "50m"
        memory: "32Mi"
      limits:
        cpu: "100m"
        memory: "128Mi"    # намеренно маленький лимит → OOMKill через ~60-90s
"""

DURATION = 300  # 5 минут — достаточно для 3-4 OOMKill циклов


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S7-CONTROL] Deploying memory leak pod '{POD_NAME}' in '{namespace}'")
    print(f"     Memory limit: 128Mi (OOMKill expected in ~60-90s)")
    print(f"     Expected: crashloop cycle, NO security signals")
    print(f"     Duration: {DURATION}s (~{DURATION//60}min, {DURATION//90} OOMKill cycles)")

    if dry_run:
        print("[DRY] Would create pod with 128Mi limit → OOMKill → restart cycle")
        return

    _apply(POD_MANIFEST, namespace)

    print("[S7] Waiting for pod to start...")
    _wait_for_phase(POD_NAME, namespace, "Running", timeout=60)

    print(f"[S7] Pod running. Watching crashloop for {DURATION}s...")
    print(f"     Watch: kubectl get pod {POD_NAME} -n {namespace} -w")
    print(f"     Logs:  kubectl logs {POD_NAME} -n {namespace} --previous")

    # Периодически печатаем статус
    start = time.time()
    while time.time() - start < DURATION:
        time.sleep(30)
        result = subprocess.run(
            ["kubectl", "get", "pod", POD_NAME, "-n", namespace,
             "-o", "jsonpath={.status.phase} restarts={.status.containerStatuses[0].restartCount}"],
            capture_output=True, text=True
        )
        print(f"     Status: {result.stdout.strip()}")

    print("[S7] Control scenario complete. Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    print(f"[S7] Deleting pod {POD_NAME}...")
    subprocess.run(
        ["kubectl", "delete", "pod", POD_NAME, "-n", namespace,
         "--ignore-not-found", "--grace-period=0", "--force"],
        capture_output=True
    )
    print("[S7] Cleanup done.")


def _apply(manifest: str, namespace: str):
    result = subprocess.run(
        ["kubectl", "apply", "-n", namespace, "-f", "-"],
        input=manifest.encode(), capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"kubectl apply failed: {result.stderr.decode()}")
    print(f"     {result.stdout.decode().strip()}")


def _wait_for_phase(name: str, namespace: str, phase: str, timeout: int = 60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["kubectl", "get", "pod", name, "-n", namespace,
             "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True
        )
        if result.stdout.strip() == phase:
            print(f"     Phase: {phase} ✓")
            return
        print(f"     Phase: {result.stdout.strip() or 'Pending'}...")
        time.sleep(5)
    print("     ⚠️  Timeout waiting for pod phase")
