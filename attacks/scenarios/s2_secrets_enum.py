"""
s2_secrets_enum.py — T1552 Credential Access
============================================

Симулирует mass secrets enumeration: скрипт выполняет 50+ GET/LIST
на secrets и configmaps за 2 минуты от нетипичного ServiceAccount.

Ожидаемые сигналы:
  Audit:    feat_secrets_access_count >> базлайн (50+ за минуту)
            feat_secrets_list_count всплеск
            feat_watch_sensitive (ставим watch на secrets)
            feat_cross_namespace_access (читаем секреты из других namespace)
"""

import subprocess
import time

SA_NAME      = "attack-secret-reader"
ROLE_NAME    = "attack-secret-reader-role"
BINDING_NAME = "attack-secret-reader-binding"
JOB_NAME     = "attack-secrets-enum"

# Namespace из которых будем читать секреты (cross-namespace access)
TARGET_NAMESPACES = ["default", "monitoring", "postgres", "kafka"]

SERVICEACCOUNT_MANIFEST = f"""
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {SA_NAME}
"""

# ClusterRole — читаем secrets во всех namespace (имитация скомпрометированного SA)
CLUSTERROLE_MANIFEST = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {ROLE_NAME}
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps", "serviceaccounts"]
  verbs: ["get", "list", "watch"]
"""

CLUSTERROLEBINDING_MANIFEST = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {BINDING_NAME}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {ROLE_NAME}
subjects:
- kind: ServiceAccount
  name: {SA_NAME}
  namespace: default
"""

# Job который выполняет перечисление секретов
JOB_MANIFEST = f"""
apiVersion: batch/v1
kind: Job
metadata:
  name: {JOB_NAME}
  labels:
    attack-scenario: s2-secrets-enum
spec:
  ttlSecondsAfterFinished: 30
  template:
    spec:
      serviceAccountName: {SA_NAME}
      restartPolicy: Never
      containers:
      - name: enum
        image: bitnami/kubectl:latest
        command:
        - /bin/sh
        - -c
        - |
          echo "[attack] Starting secrets enumeration..."
          # LIST secrets в нескольких namespace (T1552 — mass credential dumping)
          for i in $(seq 1 20); do
            kubectl get secrets -n default 2>/dev/null | wc -l
            kubectl get secrets -n monitoring 2>/dev/null | wc -l
            kubectl get secrets -n postgres 2>/dev/null | wc -l
            kubectl get configmaps -n default 2>/dev/null | wc -l
            sleep 2
          done
          echo "[attack] Phase 2: targeted GET on specific secrets..."
          # GET отдельных секретов (имитация ручного перебора)
          for ns in default monitoring postgres kafka; do
            for secret in $(kubectl get secrets -n $ns -o name 2>/dev/null | head -10); do
              kubectl get $secret -n $ns 2>/dev/null > /dev/null
              sleep 0.5
            done
          done
          echo "[attack] Phase 3: watch на secrets (persistence)..."
          # Watch на secrets — атакующий ждёт появления новых токенов
          timeout 30 kubectl get secrets -n default --watch 2>/dev/null || true
          echo "[attack] Enumeration complete."
"""


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S2] Setting up attack SA and RBAC...")

    if dry_run:
        print("[DRY] Would create: ServiceAccount, ClusterRole, ClusterRoleBinding, Job")
        print(f"      kubectl apply -f - (SA, ClusterRole, Binding in namespace '{namespace}')")
        print(f"      kubectl apply -f - (Job)")
        print(f"      Wait ~120s for job completion")
        print(f"      kubectl delete job/{JOB_NAME} sa/{SA_NAME} clusterrole/{ROLE_NAME} ...")
        return

    # Создаём SA в целевом namespace
    _apply(SERVICEACCOUNT_MANIFEST, namespace)

    # ClusterRole и Binding — cluster-scoped
    _apply(CLUSTERROLE_MANIFEST, namespace=None)
    _apply(CLUSTERROLEBINDING_MANIFEST, namespace=None)

    print("[S2] Deploying enumeration job...")
    _apply(JOB_MANIFEST, namespace)

    # Ждём завершения job
    print("[S2] Waiting for job completion (~2 min)...")
    _wait_for_job(JOB_NAME, namespace, timeout=180)

    print("[S2] Job done. Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    print("[S2] Cleaning up RBAC and job...")
    resources = [
        ["kubectl", "delete", "job", JOB_NAME, "-n", namespace, "--ignore-not-found"],
        ["kubectl", "delete", "serviceaccount", SA_NAME, "-n", namespace, "--ignore-not-found"],
        ["kubectl", "delete", "clusterrolebinding", BINDING_NAME, "--ignore-not-found"],
        ["kubectl", "delete", "clusterrole", ROLE_NAME, "--ignore-not-found"],
    ]
    for cmd in resources:
        subprocess.run(cmd, capture_output=True)
    print("[S2] Cleanup done.")


def _apply(manifest: str, namespace: str = None):
    cmd = ["kubectl", "apply", "-f", "-"]
    if namespace:
        cmd += ["-n", namespace]
    result = subprocess.run(cmd, input=manifest.encode(), capture_output=True)
    if result.returncode != 0:
        # Не падаем — некоторые namespace могут не существовать
        print(f"     ⚠️  apply warning: {result.stderr.decode().strip()[:200]}")
    else:
        print(f"     {result.stdout.decode().strip()}")


def _wait_for_job(name: str, namespace: str, timeout: int = 180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["kubectl", "get", "job", name, "-n", namespace,
             "-o", "jsonpath={.status.conditions[0].type}"],
            capture_output=True, text=True
        )
        condition = result.stdout.strip()
        if condition in ("Complete", "Failed"):
            print(f"     Job condition: {condition} ✓")
            return
        print(f"     Job status: {condition or 'Running'}... waiting")
        time.sleep(10)
    print("     ⚠️  Job timeout — proceeding anyway")
