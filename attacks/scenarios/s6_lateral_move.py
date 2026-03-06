"""
s6_lateral_move.py — T1210 Lateral Movement
============================================

Создаёт pod в namespace A со ServiceAccount из namespace B,
затем с него обращается к API и сервисам в других namespace.
Имитирует lateral movement через скомпрометированный SA токен.

Ожидаемые сигналы:
  Audit:    feat_cross_namespace_access (SA из чужого namespace)
            feat_secrets_access_count (попытки читать секреты)
  Network:  feat_lateral_flow_count (pod→pod трафик между namespace)
            feat_dropped_flows (Cilium блокирует часть)
  Metrics:  feat_new_pod_count (deployment attackerа)
"""

import subprocess
import time

SA_NAME       = "attack-lateral-sa"
POD_NAME      = "attack-lateral-mover"
ROLE_NAME     = "attack-lateral-role"
BINDING_NAME  = "attack-lateral-binding"

# Namespace откуда атакуем и куда пробуем прорваться
SOURCE_NS     = "default"
TARGET_SERVICES = [
    # (namespace, service, port) — пробуем подключиться
    ("monitoring",  "prometheus-operated",   9090),
    ("monitoring",  "alertmanager-operated", 9093),
    ("postgres",    "postgres",              5432),
    ("kafka",       "kafka",                 9092),
    ("ae-monitoring", "clickstack-clickhouse", 9000),
]

SERVICEACCOUNT_MANIFEST = f"""
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {SA_NAME}
  namespace: {SOURCE_NS}
"""

CLUSTERROLE_MANIFEST = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {ROLE_NAME}
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints", "secrets", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list"]
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
  namespace: {SOURCE_NS}
"""

# Строим команды попыток доступа к сервисам в других namespace
_service_probes = "\n".join([
    f"nc -z -w 3 {svc}.{ns}.svc.cluster.local {port} 2>/dev/null && "
    f"echo 'REACHED {ns}/{svc}:{port}' || echo 'BLOCKED {ns}/{svc}:{port}'"
    for ns, svc, port in TARGET_SERVICES
])

POD_MANIFEST = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
  namespace: {SOURCE_NS}
  labels:
    app: {POD_NAME}
    attack-scenario: s6-lateral-move
spec:
  serviceAccountName: {SA_NAME}
  restartPolicy: Never
  containers:
  - name: lateral
    image: bitnami/kubectl:latest
    command:
    - /bin/sh
    - -c
    - |
      echo "[attack] Lateral movement started from namespace: {SOURCE_NS}"
      echo "[attack] SA: {SA_NAME} (cross-namespace access)"

      echo ""
      echo "[attack] Phase 1: K8s API enumeration from compromised SA..."
      kubectl get pods --all-namespaces 2>/dev/null | head -20 || true
      kubectl get secrets --all-namespaces 2>/dev/null | head -20 || true
      kubectl get services --all-namespaces 2>/dev/null | head -20 || true

      echo ""
      echo "[attack] Phase 2: Cross-namespace service probing (network lateral)..."
      apt-get install -qq netcat-openbsd 2>/dev/null || true
      {_service_probes}

      echo ""
      echo "[attack] Phase 3: Read secrets from other namespaces..."
      for ns in monitoring postgres kafka ae-monitoring; do
        echo "  Trying secrets in $ns..."
        kubectl get secrets -n $ns 2>/dev/null | head -5 || echo "  access denied: $ns"
        sleep 2
      done

      echo ""
      echo "[attack] Phase 4: Enumerate RBAC (who has access to what)..."
      kubectl get clusterrolebindings 2>/dev/null | head -20 || true
      kubectl get rolebindings --all-namespaces 2>/dev/null | head -20 || true

      echo "[attack] Lateral movement complete."
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
"""

ATTACK_DURATION = 240  # 4 минуты


def run(namespace: str = "default", dry_run: bool = False):
    print(f"[S6] Setting up lateral movement scenario...")
    print(f"     Source namespace: {SOURCE_NS}")
    print(f"     Target services: {[f'{ns}/{svc}' for ns,svc,_ in TARGET_SERVICES]}")

    if dry_run:
        print(f"[DRY] Would create: SA in {SOURCE_NS}, ClusterRole, ClusterRoleBinding")
        print(f"[DRY] Would create: Pod {POD_NAME} in {SOURCE_NS}")
        print(f"[DRY] Pod probes services across namespaces via K8s API and TCP")
        return

    # RBAC
    _apply(SERVICEACCOUNT_MANIFEST)
    _apply(CLUSTERROLE_MANIFEST)
    _apply(CLUSTERROLEBINDING_MANIFEST)

    # Pod
    print(f"[S6] Deploying lateral mover pod...")
    _apply(POD_MANIFEST)

    print(f"[S6] Waiting for pod to start...")
    _wait_for_pod(POD_NAME, SOURCE_NS, timeout=60)

    print(f"[S6] Lateral mover running. Duration: {ATTACK_DURATION}s")
    print(f"     Watch: kubectl logs -f {POD_NAME} -n {SOURCE_NS}")
    _wait_for_pod(POD_NAME, SOURCE_NS, state="Succeeded", timeout=ATTACK_DURATION)

    print("[S6] Cleaning up...")
    cleanup(namespace)


def cleanup(namespace: str = "default"):
    print("[S6] Cleaning up lateral movement resources...")
    cmds = [
        ["kubectl", "delete", "pod", POD_NAME, "-n", SOURCE_NS,
         "--ignore-not-found", "--grace-period=0", "--force"],
        ["kubectl", "delete", "serviceaccount", SA_NAME, "-n", SOURCE_NS,
         "--ignore-not-found"],
        ["kubectl", "delete", "clusterrolebinding", BINDING_NAME,
         "--ignore-not-found"],
        ["kubectl", "delete", "clusterrole", ROLE_NAME,
         "--ignore-not-found"],
    ]
    for cmd in cmds:
        subprocess.run(cmd, capture_output=True)
    print("[S6] Cleanup done.")


def _apply(manifest: str):
    cmd = ["kubectl", "apply", "-f", "-"]
    result = subprocess.run(cmd, input=manifest.encode(), capture_output=True)
    if result.returncode != 0:
        print(f"     ⚠️  apply warning: {result.stderr.decode().strip()[:200]}")
    else:
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
        if phase == "Failed":
            print(f"     ⚠️  Pod failed — check logs: kubectl logs {name} -n {namespace}")
            return
        print(f"     Phase: {phase or 'Pending'}... waiting")
        time.sleep(8)
    print(f"     ⚠️  Timeout waiting for {state}")
