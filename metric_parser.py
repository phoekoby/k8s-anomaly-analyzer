"""
metric_parser.py
----------------
Читает системные метрики из otel_metrics_gauge и otel_metrics_sum (ClickHouse),
извлекает security-релевантные признаки на уровне node × Δt=1min.

ВАЖНО про entity:
  Метрики system.* — node-level (от otel-collector / node_exporter).
  Entity здесь = hostname ноды, а не kubernetes namespace.
  При join с audit/log/network датасетами используй cluster-level агрегацию
  (среднее/сумма по нодам) или сопоставляй по временному окну.

  Если нужен namespace-level → добавь kube-state-metrics в Prometheus
  (kube_pod_container_cpu_usage_seconds_total{namespace=...} и т.д.)

Доступные метрики (из реального кластера):
  GAUGE:  system.cpu.load_average.1m/5m/15m
  SUM:    system.cpu.time, system.memory.usage,
          system.network.io/errors/packets/dropped/connections,
          system.disk.io/operations/io_time

Признаки (20 штук):
  CPU:      feat_cpu_load_avg_1m, feat_cpu_load_avg_5m, feat_cpu_load_avg_15m
            feat_cpu_load_spike (load_1m / load_15m — внезапный всплеск)
            feat_cpu_time_rate (Δcpu_time/Δt — % utilization через counter rate)
  Memory:   feat_mem_bytes_used, feat_mem_bytes_free, feat_mem_utilization
  Network:  feat_net_bytes_in, feat_net_bytes_out
            feat_net_errors_in, feat_net_errors_out
            feat_net_dropped_in, feat_net_dropped_out
            feat_net_connections_total
  Disk:     feat_disk_io_bytes_read, feat_disk_io_bytes_write
            feat_disk_operations_rate
  Derived:  feat_load_per_connection (load / connections — аномальный паттерн cryptominer)
            feat_net_error_ratio (errors / total_packets)

MITRE ATT&CK покрытие:
  T1496 Resource Hijacking (cryptomining): feat_cpu_load_spike, feat_cpu_time_rate
  T1041 Exfiltration over C2:              feat_net_bytes_out аномалия
  T1611 Escape to Host:                    feat_disk_io_bytes_write всплеск
  T1110 Brute Force:                       feat_net_connections_total всплеск

Запуск:
    python metric_parser.py --hours 2 --host localhost --out dataset/metric_features.parquet
    python metric_parser.py --hours 2 --host localhost --out dataset/metric_features.parquet --node worker-1
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

# ── Метрики которые нас интересуют ────────────────────────────────────────────

GAUGE_METRICS = [
    "system.cpu.load_average.1m",
    "system.cpu.load_average.5m",
    "system.cpu.load_average.15m",
]

SUM_METRICS = [
    "system.cpu.time",
    "system.memory.usage",
    "system.network.io",
    "system.network.errors",
    "system.network.packets",
    "system.network.dropped",
    "system.network.connections",
    "system.disk.io",
    "system.disk.operations",
    "system.disk.io_time",
]


def get_client(host: str) -> Client:
    return Client(host=host, port=CLICKHOUSE_PORT, database=CLICKHOUSE_DB,
                  user=CLICKHOUSE_USER, password=CLICKHOUSE_PASS,
                  connect_timeout=30, send_receive_timeout=300)


# ── Запросы ───────────────────────────────────────────────────────────────────

def fetch_gauge(client: Client, start: datetime, end: datetime,
                node_filter: str = None) -> pd.DataFrame:
    """
    Читаем gauge метрики (load average).
    Берём AVG за каждую минуту — gauge может обновляться несколько раз в минуту.
    """
    names_sql = ", ".join(f"'{m}'" for m in GAUGE_METRICS)
    node_clause = f"AND ResourceAttributes['host.name'] = '{node_filter}'" if node_filter else ""

    query = f"""
        SELECT
            toStartOfMinute(TimeUnix)                       AS window_start,
            ResourceAttributes['host.name']                 AS node,
            MetricName,
            avg(Value)                                      AS value_avg
        FROM otel_metrics_gauge
        WHERE TimeUnix >= %(start)s
          AND TimeUnix <  %(end)s
          AND MetricName IN ({names_sql})
          {node_clause}
        GROUP BY window_start, node, MetricName
        ORDER BY window_start, node, MetricName
    """
    data, cols = client.execute(query, {"start": start, "end": end}, with_column_types=True)
    col_names = [c[0] for c in cols]
    df = pd.DataFrame(data, columns=col_names)
    log.info(f"Gauge: {len(df)} rows ({df['node'].nunique() if not df.empty else 0} nodes)")
    return df


def fetch_sum(client: Client, start: datetime, end: datetime,
              node_filter: str = None) -> pd.DataFrame:
    """
    Читаем sum/counter метрики.
    sum метрики — монотонные счётчики (system.cpu.time, bytes_in/out и т.д.)
    Берём MAX за минуту — на конец окна, потом считаем дельту между окнами.

    Attributes содержат direction (receive/transmit) и state (user/system/idle).
    """
    names_sql = ", ".join(f"'{m}'" for m in SUM_METRICS)
    node_clause = f"AND ResourceAttributes['host.name'] = '{node_filter}'" if node_filter else ""

    query = f"""
        SELECT
            toStartOfMinute(TimeUnix)                       AS window_start,
            ResourceAttributes['host.name']                 AS node,
            MetricName,
            Attributes['direction']                         AS direction,
            Attributes['state']                             AS state,
            Attributes['device']                            AS device,
            max(Value)                                      AS value_max
        FROM otel_metrics_sum
        WHERE TimeUnix >= %(start)s
          AND TimeUnix <  %(end)s
          AND MetricName IN ({names_sql})
          {node_clause}
        GROUP BY window_start, node, MetricName, direction, state, device
        ORDER BY window_start, node, MetricName, direction, state, device
    """
    data, cols = client.execute(query, {"start": start, "end": end}, with_column_types=True)
    col_names = [c[0] for c in cols]
    df = pd.DataFrame(data, columns=col_names)
    log.info(f"Sum: {len(df)} rows")
    return df


# ── Вычисление rate из counter ────────────────────────────────────────────────

def compute_rates(df_sum: pd.DataFrame) -> dict:
    """
    Для монотонных счётчиков вычисляем delta между соседними окнами.
    Возвращает {(node, window_start, metric, direction, state, device): rate_per_min}

    Delta = value[t] - value[t-1]
    Если delta < 0 — счётчик сбросился (перезапуск), берём само значение.
    """
    if df_sum.empty:
        return {}

    rates = {}
    # Группируем по node + metric + labels чтобы diff считался в правильном порядке
    group_cols = ["node", "MetricName", "direction", "state", "device"]
    for keys, grp in df_sum.groupby(group_cols, sort=True):
        grp = grp.sort_values("window_start")
        values  = grp["value_max"].values
        windows = grp["window_start"].values
        for i in range(1, len(grp)):
            delta = values[i] - values[i-1]
            if delta < 0:
                delta = values[i]  # counter reset
            key = (keys[0], windows[i]) + keys[1:]  # (node, window_start, metric, dir, state, dev)
            rates[key] = delta
    return rates


# ── Сборка признаков ──────────────────────────────────────────────────────────

def build_features(df_gauge: pd.DataFrame, df_sum: pd.DataFrame) -> pd.DataFrame:
    """
    Pivot + агрегация → один вектор признаков на (node × window_start).
    """
    if df_gauge.empty and df_sum.empty:
        return pd.DataFrame()

    records = defaultdict(dict)

    # ── Gauge: load average ───────────────────────────────────────────────────
    for _, row in df_gauge.iterrows():
        key = (row["node"], row["window_start"])
        name = row["MetricName"]
        val  = row["value_avg"]

        if name == "system.cpu.load_average.1m":
            records[key]["feat_cpu_load_avg_1m"] = val
        elif name == "system.cpu.load_average.5m":
            records[key]["feat_cpu_load_avg_5m"] = val
        elif name == "system.cpu.load_average.15m":
            records[key]["feat_cpu_load_avg_15m"] = val

    # ── Sum: вычисляем дельты ─────────────────────────────────────────────────
    rates = compute_rates(df_sum)

    # Агрегируем дельты по (node, window_start, metric) суммируя по device/direction/state
    metric_agg = defaultdict(lambda: defaultdict(float))
    for (node, window, metric, direction, state, device), delta in rates.items():
        metric_agg[(node, window)][(metric, direction, state)] += delta

    for (node, window), m in metric_agg.items():
        key = (node, window)

        # CPU time (суммируем все states кроме idle)
        cpu_active = sum(v for (metric, dir_, state), v in m.items()
                         if metric == "system.cpu.time" and state not in ("idle", "wait"))
        cpu_idle   = sum(v for (metric, dir_, state), v in m.items()
                         if metric == "system.cpu.time" and state == "idle")
        cpu_total  = cpu_active + cpu_idle
        records[key]["feat_cpu_time_rate"]    = round(cpu_active, 4)
        records[key]["feat_cpu_utilization"]  = round(cpu_active / cpu_total, 4) if cpu_total > 0 else 0.0

        # Memory: gauge даёт абсолютное значение, sum даёт delta от state
        # system.memory.usage{state="used"} — это gauge-like в sum
        mem_used = sum(v for (metric, dir_, state), v in m.items()
                       if metric == "system.memory.usage" and state == "used")
        mem_free = sum(v for (metric, dir_, state), v in m.items()
                       if metric == "system.memory.usage" and state == "free")
        records[key]["feat_mem_delta_used"] = round(mem_used, 0)
        records[key]["feat_mem_delta_free"] = round(mem_free, 0)

        # Network I/O
        net_in  = sum(v for (metric, dir_, state), v in m.items()
                      if metric == "system.network.io" and dir_ == "receive")
        net_out = sum(v for (metric, dir_, state), v in m.items()
                      if metric == "system.network.io" and dir_ == "transmit")
        records[key]["feat_net_bytes_in"]  = round(net_in, 0)
        records[key]["feat_net_bytes_out"] = round(net_out, 0)

        # Network errors
        err_in  = sum(v for (metric, dir_, state), v in m.items()
                      if metric == "system.network.errors" and dir_ == "receive")
        err_out = sum(v for (metric, dir_, state), v in m.items()
                      if metric == "system.network.errors" and dir_ == "transmit")
        records[key]["feat_net_errors_in"]  = round(err_in, 0)
        records[key]["feat_net_errors_out"] = round(err_out, 0)

        # Network packets (для расчёта error ratio)
        pkt_in  = sum(v for (metric, dir_, state), v in m.items()
                      if metric == "system.network.packets" and dir_ == "receive")
        pkt_out = sum(v for (metric, dir_, state), v in m.items()
                      if metric == "system.network.packets" and dir_ == "transmit")
        records[key]["feat_net_packets_in"]  = round(pkt_in, 0)
        records[key]["feat_net_packets_out"] = round(pkt_out, 0)

        # Network dropped
        drop_in  = sum(v for (metric, dir_, state), v in m.items()
                       if metric == "system.network.dropped" and dir_ == "receive")
        drop_out = sum(v for (metric, dir_, state), v in m.items()
                       if metric == "system.network.dropped" and dir_ == "transmit")
        records[key]["feat_net_dropped_in"]  = round(drop_in, 0)
        records[key]["feat_net_dropped_out"] = round(drop_out, 0)

        # Network connections (текущее, не delta — это gauge-like counter)
        net_conn = sum(v for (metric, dir_, state), v in m.items()
                       if metric == "system.network.connections")
        records[key]["feat_net_connections"] = round(net_conn, 0)

        # Disk I/O
        disk_read  = sum(v for (metric, dir_, state), v in m.items()
                         if metric == "system.disk.io" and dir_ == "read")
        disk_write = sum(v for (metric, dir_, state), v in m.items()
                         if metric == "system.disk.io" and dir_ == "write")
        records[key]["feat_disk_bytes_read"]  = round(disk_read, 0)
        records[key]["feat_disk_bytes_write"] = round(disk_write, 0)

        disk_ops = sum(v for (metric, dir_, state), v in m.items()
                       if metric == "system.disk.operations")
        records[key]["feat_disk_operations"]  = round(disk_ops, 0)

    # ── Производные признаки ──────────────────────────────────────────────────
    rows = []
    for (node, window), feats in records.items():
        # CPU spike: load_1m >> load_15m → внезапная нагрузка (cryptominer)
        l1  = feats.get("feat_cpu_load_avg_1m",  0)
        l15 = feats.get("feat_cpu_load_avg_15m", 0)
        feats["feat_cpu_load_spike"] = round(l1 / l15, 4) if l15 > 0 else 0.0

        # Net error ratio: ошибки / пакеты
        pkt_total = feats.get("feat_net_packets_in", 0) + feats.get("feat_net_packets_out", 0)
        err_total = feats.get("feat_net_errors_in", 0)  + feats.get("feat_net_errors_out", 0)
        feats["feat_net_error_ratio"] = round(err_total / pkt_total, 6) if pkt_total > 0 else 0.0

        # Exfiltration signal: outbound >> inbound (аномальная асимметрия)
        bytes_in  = feats.get("feat_net_bytes_in", 0)
        bytes_out = feats.get("feat_net_bytes_out", 0)
        total_io  = bytes_in + bytes_out
        feats["feat_net_out_ratio"] = round(bytes_out / total_io, 4) if total_io > 0 else 0.0

        rows.append({
            "window_start": window.isoformat() if hasattr(window, "isoformat") else str(window),
            "entity_node":  node,
            **feats
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["window_start", "entity_node"]).reset_index(drop=True)
        # Заполняем пропуски нулями
        feat_cols = [c for c in df.columns if c.startswith("feat_")]
        df[feat_cols] = df[feat_cols].fillna(0.0)

    return df


# ── Fetch + батчинг ───────────────────────────────────────────────────────────

def fetch_all(client: Client, start: datetime, end: datetime,
              node_filter: str = None, batch_minutes: int = 60) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Загружаем gauge и sum батчами по batch_minutes."""
    gauge_parts = []
    sum_parts   = []
    batch_start = start

    log.info(f"Fetching metrics {start.strftime('%H:%M')} → {end.strftime('%H:%M')} "
             f"in {batch_minutes}-min batches...")

    while batch_start < end:
        batch_end = min(batch_start + timedelta(minutes=batch_minutes), end)
        log.info(f"  {batch_start.strftime('%H:%M')} → {batch_end.strftime('%H:%M')}")
        try:
            g = fetch_gauge(client, batch_start, batch_end, node_filter)
            if not g.empty:
                gauge_parts.append(g)
        except Exception as e:
            log.warning(f"  Gauge batch error: {e}")
        try:
            s = fetch_sum(client, batch_start, batch_end, node_filter)
            if not s.empty:
                sum_parts.append(s)
        except Exception as e:
            log.warning(f"  Sum batch error: {e}")
        batch_start = batch_end

    df_gauge = pd.concat(gauge_parts, ignore_index=True) if gauge_parts else pd.DataFrame()
    df_sum   = pd.concat(sum_parts,   ignore_index=True) if sum_parts   else pd.DataFrame()
    log.info(f"Total: {len(df_gauge)} gauge rows, {len(df_sum)} sum rows")
    return df_gauge, df_sum


# ── Основная функция ──────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Metric anomaly features from otel_metrics_*")
    p.add_argument("--hours",  type=int,   default=24)
    p.add_argument("--from",   dest="from_dt")
    p.add_argument("--to",     dest="to_dt")
    p.add_argument("--out",    default="dataset/metric_features.parquet")
    p.add_argument("--host",   default="localhost")
    p.add_argument("--batch",  type=int,   default=60,
                   help="Размер батча в минутах (по умолчанию 60)")
    p.add_argument("--node",   default=None,
                   help="Фильтр по ноде (hostname) для отладки")
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

    df_gauge, df_sum = fetch_all(client, start, end,
                                 node_filter=args.node,
                                 batch_minutes=args.batch)

    if df_gauge.empty and df_sum.empty:
        log.warning("No metrics found"); return

    df = build_features(df_gauge, df_sum)
    if df.empty:
        log.warning("No features built"); return

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)
    log.info(f"Saved {len(df)} rows → {args.out}")

    # ── Статистика ────────────────────────────────────────────────────────────
    feat_cols = [c for c in df.columns if c.startswith("feat_")]

    print(f"\n=== СТАТИСТИКА ===")
    print(f"Строк (node × window): {len(df)}")
    print(f"Нод:                   {df['entity_node'].nunique()} → {list(df['entity_node'].unique())}")
    print(f"Период:                {df['window_start'].min()} → {df['window_start'].max()}")
    print(f"Всего признаков:       {len(feat_cols)}")

    print(f"\nСредние значения признаков:")
    print(df[feat_cols].mean().round(4).to_string())

    print(f"\nОкна с cpu_load_spike > 2.0 (внезапный CPU всплеск): "
          f"{len(df[df.get('feat_cpu_load_spike', pd.Series(dtype=float)) > 2.0])}")
    print(f"Окна с net_out_ratio > 0.8 (аномальный outbound): "
          f"{len(df[df.get('feat_net_out_ratio', pd.Series(dtype=float)) > 0.8])}")

    print(f"\nПо нодам:")
    print(df.groupby("entity_node")[feat_cols].mean().round(2).to_string())

    print(f"\n=== ЗАМЕЧАНИЕ ПО ENTITY ===")
    print(f"Текущий entity: node (hostname). Метрики system.* — node-level.")
    print(f"Для namespace-level метрик добавь kube-state-metrics в Prometheus:")
    print(f"  kube_pod_container_cpu_usage_seconds_total{{namespace=...}}")
    print(f"  kube_pod_container_restarts_total{{namespace=...}}")
    print(f"При join с audit/log/network: агрегируй по window_start (sum/avg по нодам)")


if __name__ == "__main__":
    main()
