"""
metric_parser.py  (v2 — namespace-level)
-----------------------------------------
Читает метрики из otel_metrics_gauge/sum (ClickHouse).

С появлением k8s_cluster receiver у нас теперь ДВА уровня метрик:

  [1] k8s.* метрики  — NAMESPACE-level (основной источник)
      entity = k8s.namespace.name → прямой join с audit/log/network
      Источник: k8sclusterreceiver (новый deployment-коллектор)

  [2] system.* метрики — NODE-level (вспомогательный)
      entity = node hostname → агрегируется в cluster-level вектор
      Источник: hostmetrics receiver (daemonset-коллектор)

Финальный датасет:
  entity_namespace × window_start → ~30 признаков

Признаки (k8s.* namespace-level):
  Workload health:
    feat_container_restarts      — сумма рестартов контейнеров (T1190 exploit aftermath)
    feat_container_restarts_max  — максимум рестартов одного контейнера (crashloop)
    feat_pods_not_ready          — поды не в Ready состоянии
    feat_pods_pending            — поды в Pending (staging атаки, T1496)
    feat_pods_failed             — поды в Failed
    feat_pods_running            — поды в Running (базлайн)
    feat_pods_total              — всего подов в namespace
  Deployment stability:
    feat_deployment_deficit      — sum(desired - available) по деплойментам
    feat_replicaset_deficit      — sum(desired - available) по replicaset-ам
    feat_statefulset_deficit     — sum(desired - available) по statefulset-ам
    feat_daemonset_deficit       — sum(desired - ready) по daemonset-ам
  Resource requests/limits:
    feat_cpu_requests_cores      — суммарный CPU request (всплеск = cryptominer, T1496)
    feat_mem_requests_bytes      — суммарный Memory request
    feat_cpu_limits_cores        — суммарный CPU limit
    feat_mem_limits_bytes        — суммарный Memory limit
  Jobs (attack staging):
    feat_job_failed_pods         — проваленные job-поды
    feat_job_active_pods         — активные job-поды
  Derived security signals:
    feat_crashloop_signal        — restarts_max >= 5 (binary: идёт crashloop)
    feat_pending_ratio           — pending / total (аномально высокий = staging)
    feat_failed_ratio            — failed / total
    feat_workload_instability    — (deploy_deficit + rs_deficit) / total_pods
    feat_resource_pressure       — cpu_requests / cpu_limits (близко к 1 = перегрузка)

Признаки (system.* cluster-level, агрегат по нодам):
    feat_cluster_cpu_load_avg    — средний load average по кластеру
    feat_cluster_cpu_spike       — load_1m / load_15m (внезапный всплеск, T1496)
    feat_cluster_mem_used_bytes  — использование памяти кластера
    feat_cluster_net_bytes_out   — исходящий трафик кластера (T1041)
    feat_cluster_disk_write      — запись на диск (T1611)

MITRE ATT&CK покрытие:
  T1190 Exploit Public-Facing App : feat_container_restarts, feat_crashloop_signal
  T1496 Resource Hijacking        : feat_pods_pending, feat_cpu_requests_cores, feat_cluster_cpu_spike
  T1611 Escape to Host            : feat_cluster_disk_write
  T1041 Exfiltration over C2      : feat_cluster_net_bytes_out
  T1610 Deploy Container          : feat_pods_total рост, feat_deployment_deficit

Запуск:
    python metric_parser.py --hours 2 --host localhost --out dataset/metric_features.parquet
    python metric_parser.py --hours 24 --host localhost --out dataset/metric_features.parquet
    python metric_parser.py --hours 2 --namespace kafka --out dataset/metric_features.parquet
"""

import argparse
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

CLICKHOUSE_PORT = 9000
CLICKHOUSE_DB   = "default"
CLICKHOUSE_USER = "otelcollector"
CLICKHOUSE_PASS = "lXg}45T{F.4UelH-?4o}"

# Namespace-level k8s.* метрики
K8S_GAUGE_METRICS = [
    "k8s.container.restarts",
    "k8s.container.ready",
    "k8s.pod.phase",
    "k8s.deployment.available",
    "k8s.deployment.desired",
    "k8s.replicaset.available",
    "k8s.replicaset.desired",
    "k8s.statefulset.ready_pods",
    "k8s.statefulset.desired_pods",
    "k8s.namespace.phase",
    "k8s.container.cpu_request",
    "k8s.container.memory_request",
    "k8s.container.cpu_limit",
    "k8s.container.memory_limit",
    "k8s.job.failed_pods",
    "k8s.job.active_pods",
    "k8s.job.successful_pods",
    "k8s.daemonset.ready_nodes",
    "k8s.daemonset.desired_scheduled_nodes",
]

# Node-level system.* метрики (cluster aggregate)
SYSTEM_GAUGE_METRICS = [
    "system.cpu.load_average.1m",
    "system.cpu.load_average.15m",
]

SYSTEM_SUM_METRICS = [
    "system.memory.usage",
    "system.network.io",
    "system.disk.io",
]


def get_client(host: str) -> Client:
    return Client(host=host, port=CLICKHOUSE_PORT, database=CLICKHOUSE_DB,
                  user=CLICKHOUSE_USER, password=CLICKHOUSE_PASS,
                  connect_timeout=30, send_receive_timeout=300)


# ── Запрос k8s.* метрик (namespace-level) ────────────────────────────────────

def fetch_k8s_metrics(client: Client, start: datetime, end: datetime,
                      ns_filter: str = None) -> pd.DataFrame:
    """
    Читаем все k8s.* метрики с namespace в ResourceAttributes.
    AVG за минуту — gauge обновляется несколько раз.
    """
    names_sql = ", ".join(f"'{m}'" for m in K8S_GAUGE_METRICS)
    ns_clause  = f"AND ResourceAttributes['k8s.namespace.name'] = '{ns_filter}'" if ns_filter else ""

    query = f"""
        SELECT
            toStartOfMinute(TimeUnix)                          AS window_start,
            ResourceAttributes['k8s.namespace.name']           AS namespace,
            MetricName,
            Attributes['k8s.pod.phase']                        AS pod_phase,
            avg(Value)                                         AS value_avg,
            max(Value)                                         AS value_max,
            sum(Value)                                         AS value_sum,
            count()                                            AS value_count
        FROM otel_metrics_gauge
        WHERE TimeUnix >= %(start)s
          AND TimeUnix <  %(end)s
          AND MetricName IN ({names_sql})
          AND ResourceAttributes['k8s.namespace.name'] != ''
          {ns_clause}
        GROUP BY window_start, namespace, MetricName, pod_phase
        ORDER BY window_start, namespace, MetricName
    """
    data, cols = client.execute(query, {"start": start, "end": end}, with_column_types=True)
    col_names  = [c[0] for c in cols]
    df = pd.DataFrame(data, columns=col_names)
    log.info(f"k8s metrics: {len(df)} rows, "
             f"{df['namespace'].nunique() if not df.empty else 0} namespaces")
    return df


# ── Запрос system.* метрик (node-level, cluster aggregate) ───────────────────

def fetch_system_metrics(client: Client, start: datetime, end: datetime) -> pd.DataFrame:
    """
    Читаем system.* метрики и агрегируем по кластеру (avg/sum по нодам).
    Эти метрики идут без namespace — привязываем к каждому window_start.
    """
    gauge_sql = ", ".join(f"'{m}'" for m in SYSTEM_GAUGE_METRICS)
    q_gauge = f"""
        SELECT
            toStartOfMinute(TimeUnix) AS window_start,
            MetricName,
            avg(Value)                AS value_avg
        FROM otel_metrics_gauge
        WHERE TimeUnix >= %(start)s
          AND TimeUnix <  %(end)s
          AND MetricName IN ({gauge_sql})
        GROUP BY window_start, MetricName
        ORDER BY window_start, MetricName
    """
    g_data, g_cols = client.execute(q_gauge, {"start": start, "end": end}, with_column_types=True)
    df_gauge = pd.DataFrame(g_data, columns=[c[0] for c in g_cols])

    sum_sql = ", ".join(f"'{m}'" for m in SYSTEM_SUM_METRICS)
    q_sum = f"""
        SELECT
            toStartOfMinute(TimeUnix) AS window_start,
            MetricName,
            Attributes['direction']   AS direction,
            Attributes['state']       AS state,
            avg(Value)                AS value_cluster_avg
        FROM otel_metrics_sum
        WHERE TimeUnix >= %(start)s
          AND TimeUnix <  %(end)s
          AND MetricName IN ({sum_sql})
        GROUP BY window_start, MetricName, direction, state
        ORDER BY window_start, MetricName
    """
    s_data, s_cols = client.execute(q_sum, {"start": start, "end": end}, with_column_types=True)
    df_sum = pd.DataFrame(s_data, columns=[c[0] for c in s_cols])

    records = defaultdict(dict)

    for _, row in df_gauge.iterrows():
        ws = str(row["window_start"])
        if row["MetricName"] == "system.cpu.load_average.1m":
            records[ws]["_load_1m"] = row["value_avg"]
        elif row["MetricName"] == "system.cpu.load_average.15m":
            records[ws]["_load_15m"] = row["value_avg"]

    for _, row in df_sum.iterrows():
        ws = str(row["window_start"])
        m, d, s = row["MetricName"], row["direction"], row["state"]
        v = row["value_cluster_avg"]
        if m == "system.memory.usage" and s == "used":
            records[ws]["_mem_used"] = v
        elif m == "system.network.io" and d == "transmit":
            records[ws]["_net_out"] = v
        elif m == "system.disk.io" and d == "write":
            records[ws]["_disk_write"] = v

    rows = []
    for ws, r in records.items():
        l1  = r.get("_load_1m",  0)
        l15 = r.get("_load_15m", 1)
        rows.append({
            "window_start":                ws,
            "feat_cluster_cpu_load_avg":   round(l1, 4),
            "feat_cluster_cpu_spike":      round(l1 / l15, 4) if l15 > 0 else 0.0,
            "feat_cluster_mem_used_bytes": r.get("_mem_used",   0),
            "feat_cluster_net_bytes_out":  r.get("_net_out",    0),
            "feat_cluster_disk_write":     r.get("_disk_write", 0),
        })

    df = pd.DataFrame(rows) if rows else pd.DataFrame()
    log.info(f"System (cluster-level): {len(df)} windows")
    return df


# ── Построение namespace-level признаков ─────────────────────────────────────

def compute_restart_deltas(df: pd.DataFrame) -> pd.DataFrame:
    """
    k8s.container.restarts — монотонный счётчик (растёт с момента запуска пода).
    Нам нужна ДЕЛЬТА за минуту: restarts[t] - restarts[t-1].

    Без этого в нормальном кластере где поды жили неделю
    feat_container_restarts = миллионы (бесполезно для детекции).

    С дельтой: 0 в норме, всплеск > 0 = активный crashloop прямо сейчас.
    """
    if df.empty:
        return df

    restart_mask = df["MetricName"] == "k8s.container.restarts"
    df_restarts  = df[restart_mask].copy()
    df_other     = df[~restart_mask].copy()

    if df_restarts.empty:
        return df

    # Группируем по namespace + pod (чтобы diff был по одному pod-у)
    # ResourceAttributes содержат k8s.pod.name — используем namespace как прокси
    df_restarts = df_restarts.sort_values(["namespace", "window_start"])
    df_restarts["value_sum_delta"] = (
        df_restarts.groupby("namespace")["value_sum"]
        .diff()
        .clip(lower=0)  # counter reset → 0, не отрицательное
        .fillna(0)
    )
    df_restarts["value_max_delta"] = (
        df_restarts.groupby("namespace")["value_max"]
        .diff()
        .clip(lower=0)
        .fillna(0)
    )
    # Заменяем value_sum/max на дельты
    df_restarts["value_sum"] = df_restarts["value_sum_delta"]
    df_restarts["value_max"] = df_restarts["value_max_delta"]
    df_restarts = df_restarts.drop(columns=["value_sum_delta", "value_max_delta"])

    return pd.concat([df_other, df_restarts], ignore_index=True)


def build_k8s_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Pivot k8s.* метрик → один вектор признаков на (namespace × window_start).
    """
    if df.empty:
        return pd.DataFrame()

    # Преобразуем монотонный счётчик рестартов в дельту за минуту
    df = compute_restart_deltas(df)

    records = defaultdict(lambda: defaultdict(float))

    for _, row in df.iterrows():
        key    = (str(row["window_start"]), row["namespace"])
        metric = row["MetricName"]
        phase  = row.get("pod_phase", "") or ""
        vsum   = float(row["value_sum"])
        vmax   = float(row["value_max"])
        vcnt   = int(row["value_count"])

        r = records[key]

        if metric == "k8s.container.restarts":
            r["feat_container_restarts"]     += vsum
            r["feat_container_restarts_max"]  = max(r["feat_container_restarts_max"], vmax)

        elif metric == "k8s.container.ready":
            # value = 1 если ready, 0 если нет → not_ready = кол-во записей с value=0
            r["feat_pods_not_ready"] += max(0, vcnt - vsum)

        elif metric == "k8s.pod.phase":
            phase_lower = phase.lower()
            if "running" in phase_lower:
                r["feat_pods_running"]   += vcnt
            elif "pending" in phase_lower:
                r["feat_pods_pending"]   += vcnt
            elif "failed" in phase_lower:
                r["feat_pods_failed"]    += vcnt
            elif "succeeded" in phase_lower:
                r["feat_pods_succeeded"] += vcnt
            r["feat_pods_total"] += vcnt

        elif metric == "k8s.deployment.desired":
            r["_deploy_desired"]   += vsum
        elif metric == "k8s.deployment.available":
            r["_deploy_available"] += vsum

        elif metric == "k8s.replicaset.desired":
            r["_rs_desired"]   += vsum
        elif metric == "k8s.replicaset.available":
            r["_rs_available"] += vsum

        elif metric == "k8s.statefulset.desired_pods":
            r["_ss_desired"] += vsum
        elif metric == "k8s.statefulset.ready_pods":
            r["_ss_ready"]   += vsum

        elif metric == "k8s.container.cpu_request":
            r["feat_cpu_requests_cores"] += vsum
        elif metric == "k8s.container.memory_request":
            r["feat_mem_requests_bytes"] += vsum
        elif metric == "k8s.container.cpu_limit":
            r["feat_cpu_limits_cores"]   += vsum
        elif metric == "k8s.container.memory_limit":
            r["feat_mem_limits_bytes"]   += vsum

        elif metric == "k8s.job.failed_pods":
            r["feat_job_failed_pods"]     += vsum
        elif metric == "k8s.job.active_pods":
            r["feat_job_active_pods"]     += vsum
        elif metric == "k8s.job.successful_pods":
            r["feat_job_successful_pods"] += vsum

        elif metric == "k8s.daemonset.desired_scheduled_nodes":
            r["_ds_desired"] += vsum
        elif metric == "k8s.daemonset.ready_nodes":
            r["_ds_ready"]   += vsum

    rows = []
    for (ws, ns), r in records.items():
        # Deficit: сколько подов НЕ поднялось
        r["feat_deployment_deficit"]  = max(0, r.get("_deploy_desired", 0)  - r.get("_deploy_available", 0))
        r["feat_replicaset_deficit"]  = max(0, r.get("_rs_desired", 0)      - r.get("_rs_available", 0))
        r["feat_statefulset_deficit"] = max(0, r.get("_ss_desired", 0)      - r.get("_ss_ready", 0))
        r["feat_daemonset_deficit"]   = max(0, r.get("_ds_desired", 0)      - r.get("_ds_ready", 0))

        # Derived security signals
        total_pods = r.get("feat_pods_total", 1) or 1
        r["feat_crashloop_signal"]     = 1.0 if r.get("feat_container_restarts_max", 0) >= 5 else 0.0
        r["feat_pending_ratio"]        = round(r.get("feat_pods_pending", 0) / total_pods, 4)
        r["feat_failed_ratio"]         = round(r.get("feat_pods_failed",  0) / total_pods, 4)
        r["feat_workload_instability"] = round(
            (r.get("feat_deployment_deficit", 0) + r.get("feat_replicaset_deficit", 0)) / total_pods, 4
        )
        cpu_req = r.get("feat_cpu_requests_cores", 0)
        cpu_lim = r.get("feat_cpu_limits_cores",   1) or 1
        r["feat_resource_pressure"]    = round(cpu_req / cpu_lim, 4)

        # Убираем служебные поля
        clean = {k: v for k, v in r.items() if not k.startswith("_")}
        rows.append({"window_start": ws, "entity_namespace": ns, **clean})

    result = pd.DataFrame(rows)
    if not result.empty:
        result = result.sort_values(["window_start", "entity_namespace"]).reset_index(drop=True)
        feat_cols = [c for c in result.columns if c.startswith("feat_")]
        result[feat_cols] = result[feat_cols].fillna(0.0)

    return result


# ── Join k8s + system метрик ──────────────────────────────────────────────────

def join_with_system(df_k8s: pd.DataFrame, df_sys: pd.DataFrame) -> pd.DataFrame:
    """
    Добавляем cluster-level system.* признаки к каждой namespace-строке.
    Cluster CPU spike виден во всех namespace одновременно — это корректно.
    """
    if df_sys.empty or df_k8s.empty:
        return df_k8s
    df_merged = df_k8s.merge(df_sys, on="window_start", how="left")
    sys_cols  = [c for c in df_sys.columns if c.startswith("feat_")]
    df_merged[sys_cols] = df_merged[sys_cols].fillna(0.0)
    return df_merged


# ── Батчинг ───────────────────────────────────────────────────────────────────

def fetch_batched(client: Client, start: datetime, end: datetime,
                  ns_filter: str = None, batch_minutes: int = 60):
    k8s_parts = []
    sys_parts  = []
    batch_start = start

    log.info(f"Fetching {start.strftime('%H:%M')} → {end.strftime('%H:%M')} "
             f"in {batch_minutes}-min batches...")

    while batch_start < end:
        batch_end = min(batch_start + timedelta(minutes=batch_minutes), end)
        log.info(f"  {batch_start.strftime('%H:%M')} → {batch_end.strftime('%H:%M')}")

        try:
            k = fetch_k8s_metrics(client, batch_start, batch_end, ns_filter)
            if not k.empty:
                k8s_parts.append(k)
        except Exception as e:
            log.warning(f"  k8s metrics error: {e}")

        try:
            s = fetch_system_metrics(client, batch_start, batch_end)
            if not s.empty:
                sys_parts.append(s)
        except Exception as e:
            log.warning(f"  system metrics error: {e}")

        batch_start = batch_end

    df_k8s = pd.concat(k8s_parts, ignore_index=True) if k8s_parts else pd.DataFrame()
    df_sys  = pd.concat(sys_parts, ignore_index=True) if sys_parts  else pd.DataFrame()

    if not df_sys.empty:
        df_sys = df_sys.groupby("window_start").mean(numeric_only=True).reset_index()

    log.info(f"Total: {len(df_k8s)} k8s rows, {len(df_sys)} system windows")
    return df_k8s, df_sys


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Metric anomaly features — namespace-level (v2)")
    p.add_argument("--hours",     type=int,   default=24)
    p.add_argument("--from",      dest="from_dt")
    p.add_argument("--to",        dest="to_dt")
    p.add_argument("--out",       default="dataset/metric_features.parquet")
    p.add_argument("--host",      default="localhost")
    p.add_argument("--batch",     type=int,   default=60)
    p.add_argument("--namespace", default=None, help="Фильтр по namespace (для отладки)")
    args = p.parse_args()

    now = datetime.now(timezone.utc)
    if args.from_dt:
        start = datetime.fromisoformat(args.from_dt).replace(tzinfo=timezone.utc)
        end   = datetime.fromisoformat(args.to_dt).replace(tzinfo=timezone.utc) if args.to_dt else now
    else:
        end   = now
        start = end - timedelta(hours=args.hours)

    log.info(f"Period: {start} → {end}")
    client = get_client(args.host)

    df_k8s_raw, df_sys = fetch_batched(client, start, end,
                                        ns_filter=args.namespace,
                                        batch_minutes=args.batch)

    if df_k8s_raw.empty:
        log.warning("No k8s metrics found. Проверь что cluster-otel-collector запущен.")
        return

    df_k8s = build_k8s_features(df_k8s_raw)
    if df_k8s.empty:
        log.warning("No features built"); return

    df = join_with_system(df_k8s, df_sys)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)
    log.info(f"Saved {len(df)} rows → {args.out}")

    # ── Статистика ─────────────────────────────────────────────────────────────
    feat_cols = [c for c in df.columns if c.startswith("feat_")]

    print(f"\n=== СТАТИСТИКА ===")
    print(f"Строк (namespace × window): {len(df)}")
    print(f"Namespace: {df['entity_namespace'].nunique()} → {sorted(df['entity_namespace'].unique())}")
    print(f"Период:    {df['window_start'].min()} → {df['window_start'].max()}")
    print(f"Признаков: {len(feat_cols)}")

    print(f"\nСредние значения:")
    print(df[feat_cols].mean().round(4).to_string())

    print(f"\n── Security сигналы ──")
    for col, label, threshold in [
        ("feat_crashloop_signal",    "Crashloop (restarts_max >= 5)", 0),
        ("feat_pods_pending",        "Pods pending > 0",              0),
        ("feat_deployment_deficit",  "Deployment deficit > 0",        0),
        ("feat_cluster_cpu_spike",   "Cluster CPU spike > 2.0",       2.0),
        ("feat_job_failed_pods",     "Job failed pods > 0",           0),
    ]:
        if col in df.columns:
            n = len(df[df[col] > threshold])
            print(f"  {label}: {n} окон ({round(n/len(df)*100,1)}%)")

    print(f"\nТоп namespace по container_restarts (суммарно):")
    if "feat_container_restarts" in df.columns:
        print(df.groupby("entity_namespace")["feat_container_restarts"]
                .sum().sort_values(ascending=False).head(10).to_string())

    print(f"\n=== JOIN ===")
    print(f"Ключ объединения с audit/log/network датасетами:")
    print(f"  (entity_namespace, window_start)")
    print(f"Cluster-level признаки (feat_cluster_*) одинаковы для всех namespace в окне.")


if __name__ == "__main__":
    main()