# Attack Scenarios — ClusterAnomalyAnalyzer

Скрипты для инъекции контролируемых атак и генерации weak labels.

## Быстрый старт

```bash
# Посмотреть все сценарии
python run_attack.py --list

# Проверить без выполнения
python run_attack.py --scenario s1_cryptominer --dry-run

# Запустить (5 прогонов для статзначимости)
python run_attack.py --scenario s1_cryptominer --runs 5

# Посмотреть накопленные метки
python run_attack.py --show-labels
```

## Структура

```
attacks/
├── run_attack.py           # Оркестратор
├── attack_labels.csv       # Генерируется автоматически
└── scenarios/
    ├── s1_cryptominer.py    # T1496 Resource Hijacking
    ├── s2_secrets_enum.py   # T1552 Credential Access
    ├── s3_privileged_pod.py # T1611 Escape to Host
    ├── s4_network_scan.py   # T1046 Network Discovery
    ├── s5_exec_storm.py     # T1609 Container Exec
    ├── s6_lateral_move.py   # T1210 Lateral Movement
    ├── s7_oom_control.py    # CONTROL (OOMKill — не атака, FP measurement)
    ├── s8_http_error_storm.py # T1190 Exploit Public App
    ├── s9_rbac_escalation.py  # T1098 Account Manipulation
    ├── s10_exfiltration.py    # T1041 Exfiltration over C2
    └── s11_brute_force.py     # T1110 Brute Force
```

## Все сценарии

| # | Сценарий | MITRE | Длит. | Главные признаки |
|---|----------|-------|-------|-----------------|
| S1 | stress-ng CPU + outbound mining | T1496 | 5 мин | `feat_cluster_cpu_spike`, `feat_external_egress` |
| S2 | Mass GET/LIST secrets via Job | T1552 | 2 мин | `feat_secrets_access_count`, `feat_watch_sensitive` |
| S3 | Privileged pod hostPID + hostPath | T1611 | 3 мин | `feat_new_pod_count`, `feat_write_sensitive_count` |
| S4 | nmap SYN scan cluster CIDR | T1046 | 3 мин | `feat_syn_count`, `feat_port_diversity_ratio` |
| S5 | kubectl exec storm, 5 namespace | T1609 | 5 мин | `feat_exec_events_count`, `feat_cross_namespace_access` |
| S6 | Cross-namespace SA + service probe | T1210 | 4 мин | `feat_cross_namespace_access`, `feat_lateral_flow_count` |
| S7 | OOMKill crashloop (**CONTROL**) | — | 5 мин | `feat_crashloop_signal`, `feat_container_restarts_max` |
| S8 | HTTP path fuzzing + error storm | T1190 | 4 мин | `feat_error_count`, `feat_unseen_templates` |
| S9 | ClusterRoleBinding cluster-admin | T1098 | 2 мин | `feat_rbac_change_count`, `feat_write_sensitive_count` |
| S10 | Large outbound transfer + DNS | T1041 | 3 мин | `feat_external_egress`, `feat_dns_unique_domains` |
| S11 | 200+ invalid auth → K8s API | T1110 | 3 мин | `feat_failed_requests_count`, `feat_failed_ratio` |

## MITRE ATT&CK покрытие

```
T1190 Exploit Public App      → S8  (Logs + Network + Metrics)
T1609 Container Exec          → S5  (Audit)
T1611 Escape to Host          → S3  (Audit + Metrics)
T1098 Account Manipulation    → S9  (Audit)
T1610 Deploy Container        → S1  (Audit + Metrics)
T1210 Lateral Movement        → S6  (Audit + Network)
T1552 Credential Access       → S2  (Audit)
T1046 Network Discovery       → S4  (Network)
T1041 Exfiltration over C2    → S10 (Network + Metrics)
T1496 Resource Hijacking      → S1  (Metrics + Network)
T1110 Brute Force             → S11 (Audit + Network)
CONTROL Operational incident  → S7  (Metrics + Logs)
```

## Рекомендуемый порядок запуска

С паузой 15 минут между сценариями — дать кластеру вернуться к baseline.

```bash
# Сначала control — узнать базовый FP rate
python run_attack.py --scenario s7_oom_control --runs 5

# Потом атаки
for s in s1_cryptominer s2_secrets_enum s3_privileged_pod s4_network_scan \
         s5_exec_storm s6_lateral_move s8_http_error_storm s9_rbac_escalation \
         s10_exfiltration s11_brute_force; do
  python run_attack.py --scenario $s --runs 5
  echo "Waiting 15 min..."
  sleep 900
done
```

## Использование меток в датасете

```python
import pandas as pd

labels = pd.read_csv("attacks/attack_labels.csv",
                     parse_dates=["start_utc", "end_utc"])
features = pd.read_parquet("dataset/features_joined.parquet")

# Помечаем окна
features["label"] = 0
features["mitre"]  = ""
for _, row in labels.iterrows():
    if row["type"] == "control":
        continue   # контрольный — не помечаем как атаку
    mask = (
        (features["window_start"] >= row["start_utc"]) &
        (features["window_start"] <= row["end_utc"]) &
        (features["entity_namespace"] == row["namespace"])
    )
    features.loc[mask, "label"] = 1
    features.loc[mask, "mitre"] = row["mitre_technique"]

print(f"Anomalous windows: {features['label'].sum()}")
print(f"Normal windows:    {(features['label'] == 0).sum()}")
print(f"Control windows:   {len(labels[labels['type']=='control'])}")
```

## Требования

- `kubectl` настроен на кластер
- Права `cluster-admin` (для ClusterRole в S2, S6, S9)
- Python 3.10+
