"""
collector.py — тонкая обёртка над парсерами.
Импортирует готовые функции, не дублирует логику.

/app/
    collector.py
    parsers/
        __init__.py
        audit_parser.py
        network_parser.py
        log_parser.py
        metric_parser.py
"""

import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone

import pandas as pd
from clickhouse_driver import Client

from parsers import audit_parser
from parsers import network_parser
from parsers import log_parser
from parsers import metric_parser

# ── Конфиг ───────────────────────────────────────────────────────────────────
CH_HOST   = os.getenv("CLICKHOUSE_HOST", "clickstack-clickhouse.ae-monitoring.svc.cluster.local")
CH_PORT   = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CH_DB     = os.getenv("CLICKHOUSE_DB", "default")
CH_USER   = os.getenv("CLICKHOUSE_USER", "otelcollector")
CH_PASS   = os.getenv("CLICKHOUSE_PASSWORD", "")
INTERVAL  = int(os.getenv("COLLECT_INTERVAL", "60"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("collector")
logging.getLogger("drain3.template_miner").setLevel(logging.WARNING)
logging.getLogger("clickhouse_driver").setLevel(logging.WARNING)


def get_client() -> Client:
    return Client(
        host=CH_HOST, port=CH_PORT, database=CH_DB,
        user=CH_USER, password=CH_PASS,
        connect_timeout=10, send_receive_timeout=55,
    )


def insert_df(client: Client, table: str, df: pd.DataFrame) -> int:
    """
    Вставка DataFrame в ClickHouse.
    Убирает служебные колонки (_*, tmpl_*).
    Конвертирует строковые timestamp → datetime (log_parser возвращает isoformat).
    """
    if df is None or df.empty:
        return 0

    df = df.copy()

    # Убираем служебные колонки
    drop_cols = [c for c in df.columns if c.startswith("_") or c.startswith("tmpl_")]
    df = df.drop(columns=drop_cols, errors="ignore")

    # window_start может быть строкой ISO (log_parser) или datetime — нормализуем
    if "window_start" in df.columns:
        df["window_start"] = pd.to_datetime(df["window_start"], utc=True).dt.tz_localize(None)

    cols = list(df.columns)
    rows = df.values.tolist()
    client.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES", rows)
    return len(rows)


def main():
    log.info("=" * 60)
    log.info("ClusterAnomalyAnalyzer — Feature Collector")
    log.info(f"ClickHouse: {CH_HOST}:{CH_PORT}/{CH_DB}")
    log.info(f"Interval:   {INTERVAL}s")
    log.info("=" * 60)

    running = {"active": True}
    def handle_signal(sig, frame):
        log.info("Shutdown signal received...")
        running["active"] = False
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Состояние между итерациями
    log_ns_data   = {}  # Drain3-майнеры — накапливаются, не сбрасывать!
    log_topn_map  = {}

    iteration = 0

    while running["active"]:
        iteration += 1
        now   = datetime.now(timezone.utc)
        end   = now.replace(second=0, microsecond=0)
        start = end - timedelta(minutes=1)

        log.info(f"[#{iteration:05d}] {start.strftime('%H:%M')} -> {end.strftime('%H:%M')}")

        try:
            client = get_client()

            # ── Audit ─────────────────────────────────────────────────────────
            try:
                rows = audit_parser.fetch_raw_events(client, start, end)
                df   = audit_parser.build_windows(rows)
                n    = insert_df(client, "features_audit", df)
                log.info(f"  audit:   {n} rows")
            except Exception as e:
                log.warning(f"  audit error: {e}")

            # ── Network ───────────────────────────────────────────────────────
            try:
                rows = network_parser.fetch_events(client, start, end, batch_minutes=1)
                df   = network_parser.build_windows(rows)
                n    = insert_df(client, "features_network", df)
                log.info(f"  network: {n} rows")
            except Exception as e:
                log.warning(f"  network error: {e}")

            # ── Logs (stateful Drain3) ────────────────────────────────────────
            try:
                rows = log_parser.fetch_events(client, start, end, batch_minutes=1)
                if rows:
                    new_ns = log_parser.build_templates(rows)
                    for ns, data in new_ns.items():
                        if ns not in log_ns_data:
                            log_ns_data[ns] = data
                    log_topn_map = log_parser.get_topn_templates(log_ns_data, top_n=50)
                    df = log_parser.build_windows(rows, log_ns_data, log_topn_map)
                    n  = insert_df(client, "features_logs", df)
                    log.info(f"  logs:    {n} rows (trained ns: {len(log_ns_data)})")
                else:
                    log.info("  logs:    0 rows")
            except Exception as e:
                log.warning(f"  logs error: {e}")

            # ── Metrics ───────────────────────────────────────────────────────
            # metric_parser v2: namespace-level, entity_namespace → join с остальными
            # API: fetch_batched(client, start, end) → (df_k8s, df_sys)
            #      build_k8s_features(df_k8s)        → DataFrame
            #      join_with_system(df_k8s, df_sys)  → финальный DataFrame
            try:
                df_k8s_raw, df_sys = metric_parser.fetch_batched(
                    client, start, end, batch_minutes=1
                )
                if not df_k8s_raw.empty:
                    df_k8s = metric_parser.build_k8s_features(df_k8s_raw)
                    df     = metric_parser.join_with_system(df_k8s, df_sys)
                    n      = insert_df(client, "features_metrics", df)
                    log.info(f"  metrics: {n} rows")
                else:
                    log.info("  metrics: 0 rows")
            except Exception as e:
                log.warning(f"  metrics error: {e}")

        except Exception as e:
            log.error(f"Iteration error: {e}", exc_info=True)

        # Статистика каждый час
        if iteration % 60 == 0:
            try:
                client = get_client()
                parts = []
                for tbl in ["features_audit", "features_logs",
                            "features_metrics", "features_network"]:
                    cnt = client.execute(f"SELECT count() FROM {tbl}")[0][0]
                    parts.append(f"{tbl.replace('features_', '')}: {cnt}")
                log.info("DB totals — " + " | ".join(parts))
            except Exception as e:
                log.warning(f"Stats error: {e}")

        next_tick = end + timedelta(minutes=1)
        sleep_s   = max(1, (next_tick - datetime.now(timezone.utc)).total_seconds())
        if running["active"]:
            time.sleep(sleep_s)

    log.info("Collector stopped.")


if __name__ == "__main__":
    main()