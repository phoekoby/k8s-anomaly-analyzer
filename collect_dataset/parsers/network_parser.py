"""
network_parser.py
-----------------
Читает Cilium/Hubble flow события из cilium_netflow_raw (ClickHouse),
извлекает 11 security-признаков на каждое окно (entity × Δt=1min).

Ключевые решения:
  1. JSONExtract в SQL — не читаем Body целиком (Memory limit exceeded)
  2. Батчи по 10 минут — контроль нагрузки на ClickHouse
  3. feat_port_diversity_ratio вместо nonstd ports count — более дискриминативный
  4. feat_wellknown_ports_scanned — port scan идёт по портам 1-1024

Использование:
    python network_parser.py --hours 2 --out dataset/network_features.parquet
    python network_parser.py --from "2026-02-23 00:00:00" --to "2026-02-24 00:00:00"
"""

import argparse
import logging
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
TABLE           = "cilium_netflow_raw"

INTERNAL_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.28.", "192.168."
)

SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 5555, 8888, 9999, 6666, 1337, 31337}


def is_external_ip(ip: str) -> bool:
    return bool(ip) and not any(ip.startswith(p) for p in INTERNAL_PREFIXES)


def get_client(host: str) -> Client:
    return Client(host=host, port=CLICKHOUSE_PORT, database=CLICKHOUSE_DB,
                  user=CLICKHOUSE_USER, password=CLICKHOUSE_PASS,
                  connect_timeout=30, send_receive_timeout=300)


def fetch_events(client: Client, start: datetime, end: datetime,
                 batch_minutes: int = 10) -> list[dict]:
    """
    Извлекаем только нужные поля через JSONExtract в ClickHouse SQL.

    Почему не SELECT Body:
      Body содержит KubeVirt node labels (~200KB на строку).
      За 10 минут это ~350K строк — Memory limit exceeded (9.31 GiB).
      JSONExtract читает только запрошенные поля из сжатого хранилища.
    """
    all_rows = []
    batch_start = start
    log.info(f"Fetching {start.strftime('%H:%M')} → {end.strftime('%H:%M')} "
             f"in {batch_minutes}-min batches...")

    while batch_start < end:
        batch_end = min(batch_start + timedelta(minutes=batch_minutes), end)
        query = """
            SELECT
                Timestamp,
                JSONExtractString(Body, 'flow', 'verdict')                        AS verdict,
                JSONExtractString(Body, 'flow', 'IP', 'source')                   AS src_ip,
                JSONExtractString(Body, 'flow', 'IP', 'destination')              AS dst_ip,
                JSONExtractUInt(Body, 'flow', 'l4', 'TCP', 'source_port')         AS tcp_src,
                JSONExtractUInt(Body, 'flow', 'l4', 'TCP', 'destination_port')    AS tcp_dst,
                JSONExtractUInt(Body, 'flow', 'l4', 'UDP', 'source_port')         AS udp_src,
                JSONExtractUInt(Body, 'flow', 'l4', 'UDP', 'destination_port')    AS udp_dst,
                JSONExtractBool(Body, 'flow', 'l4', 'TCP', 'flags', 'SYN')        AS syn,
                JSONExtractBool(Body, 'flow', 'l4', 'TCP', 'flags', 'ACK')        AS ack,
                multiIf(
                    JSONHas(Body, 'flow', 'l4', 'TCP'),    'TCP',
                    JSONHas(Body, 'flow', 'l4', 'UDP'),    'UDP',
                    JSONHas(Body, 'flow', 'l4', 'ICMPv4'), 'ICMP',
                    JSONHas(Body, 'flow', 'l4', 'ICMPv6'), 'ICMP',
                    'UNKNOWN'
                )                                                                  AS protocol,
                JSONExtractString(Body, 'flow', 'source',      'namespace')       AS src_ns,
                JSONExtractString(Body, 'flow', 'destination', 'namespace')       AS dst_ns,
                JSONExtractString(Body, 'flow', 'source',      'pod_name')        AS src_pod,
                JSONExtractString(Body, 'flow', 'destination', 'pod_name')        AS dst_pod,
                JSONExtractString(Body, 'flow', 'traffic_direction')              AS direction,
                JSONExtractString(Body, 'flow', 'Type')                           AS flow_type,
                positionCaseInsensitive(
                    JSONExtractRaw(Body, 'flow', 'source', 'labels'), 'reserved:world'
                ) > 0                                                              AS src_world,
                positionCaseInsensitive(
                    JSONExtractRaw(Body, 'flow', 'destination', 'labels'), 'reserved:world'
                ) > 0                                                              AS dst_world
            FROM cilium_netflow_raw
            WHERE Timestamp >= %(start)s AND Timestamp < %(end)s
        """
        try:
            data, cols = client.execute(query, {"start": batch_start, "end": batch_end},
                                        with_column_types=True)
            col_names = [c[0] for c in cols]
            for row in data:
                all_rows.append(dict(zip(col_names, row)))
            log.info(f"  {batch_start.strftime('%H:%M')}→{batch_end.strftime('%H:%M')}: "
                     f"{len(data)} rows (total: {len(all_rows)})")
        except Exception as e:
            log.warning(f"  Batch {batch_start.strftime('%H:%M')} error: {e}")
        batch_start = batch_end

    log.info(f"Total: {len(all_rows)} flow records")
    return all_rows


def extract_features(events: list[dict], window_start: datetime,
                     entity: str) -> dict | None:
    """
    11 security-признаков для одного окна (entity_namespace × 1min).

    Почему feat_port_diversity_ratio вместо unique_nonstd_ports:
      Абсолютное число нестандартных портов ~99 в каждом окне (Longhorn,
      эфемерные порты TCP replies) — признак неинформативен.
      Ratio = unique_ports / total_flows нормализует по объёму:
        Нормальный трафик: 1000 flows на 5 портов  → ratio = 0.005
        Port scan:         1000 flows на 1000 портов → ratio = 1.0
    """
    n = len(events)
    if n == 0:
        return None

    dropped = syn = dns = suspicious = icmp = ext_in = ext_out = 0
    unique_src = set()
    unique_dst = set()
    unique_dst_ports = set()
    ext_dst_ips = set()
    lateral        = 0   # pod→pod между разными namespace (T1210)
    dns_domains    = set()  # уникальные DNS домены (T1048 DNS Tunneling)

    for ev in events:
        verdict  = ev.get("verdict", "")
        src_ip   = ev.get("src_ip", "") or ""
        dst_ip   = ev.get("dst_ip", "") or ""
        proto    = ev.get("protocol", "")
        src_port = ev.get("tcp_src") or ev.get("udp_src") or 0
        dst_port = ev.get("tcp_dst") or ev.get("udp_dst") or 0

        src_world = bool(ev.get("src_world")) or is_external_ip(src_ip)
        dst_world = bool(ev.get("dst_world")) or is_external_ip(dst_ip)
        is_syn    = (proto == "TCP"
                     and bool(ev.get("syn"))
                     and not bool(ev.get("ack")))

        unique_src.add(src_ip)
        unique_dst.add(dst_ip)
        if dst_port > 0:
            unique_dst_ports.add(dst_port)

        if verdict == "DROPPED":                 dropped   += 1
        if src_world and not dst_world:          ext_in    += 1
        if dst_world and not src_world:
            ext_out += 1
            ext_dst_ips.add(dst_ip)
        if dst_port == 53 or src_port == 53:     dns       += 1
        if is_syn:                               syn       += 1
        if dst_port in SUSPICIOUS_PORTS:         suspicious += 1
        if proto == "ICMP":                      icmp      += 1
        
        src_ns = ev.get("src_ns", "") or ""
        dst_ns = ev.get("dst_ns", "") or ""

        # T1210 Lateral Movement: внутренний cross-namespace трафик
        # src и dst — оба известных namespace, но разные
        if (src_ns and dst_ns
                and src_ns != dst_ns
                and src_ns not in ("unknown", "")
                and dst_ns not in ("unknown", "")
                and not ev.get("src_world")
                and not ev.get("dst_world")):
            lateral += 1

        # T1048 DNS Tunneling: аномально много уникальных доменов
        # Нормально: один namespace делает запросы к 5-10 доменам
        # Tunneling: сотни уникальных субдоменов за минуту
        dns_query = ev.get("dns_query", "") or ""
        if dns_query:
            # Нормализуем до базового домена (убираем субдомены)
            parts = dns_query.rstrip(".").split(".")
            base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else dns_query
            dns_domains.add(base_domain)

    port_diversity    = round(len(unique_dst_ports) / n, 4) if n > 0 else 0.0
    wellknown_scanned = len({p for p in unique_dst_ports if 0 < p < 1024})

    return {
        "window_start":               window_start.isoformat(),
        "entity_namespace":           entity,

        # NetworkPolicy violations (Lateral Movement, T1046)
        "feat_dropped_flows":         dropped,
        "feat_dropped_ratio":         round(dropped / n, 4),

        # External traffic (T1041 Exfiltration, Initial Access)
        "feat_external_ingress":      ext_in,
        "feat_external_egress":       ext_out,
        "feat_unique_external_dst":   len(ext_dst_ips),

        # Network Discovery (T1046)
        "feat_dns_query_count":       dns,
        "feat_syn_count":             syn,

        # Port scanning indicators
        "feat_port_diversity_ratio":  port_diversity,
        "feat_wellknown_ports_scanned": wellknown_scanned,

        # Backdoor / C2
        "feat_suspicious_port_hits":  suspicious,

        # ICMP sweep
        "feat_icmp_count":            icmp,

        # Общий объём
        "feat_total_flows":           n,

        # Debug (не входят в модель)
        "_unique_src_ips":            len(unique_src),
        "_unique_dst_ips":            len(unique_dst),
        "_unique_dst_ports":          len(unique_dst_ports),

        "feat_lateral_flow_count":    lateral,

        # T1048 DNS Tunneling
        "feat_dns_unique_domains":    len(dns_domains),
    }


def build_windows(rows: list[dict]) -> pd.DataFrame:
    groups: dict[tuple, list] = {}
    for ev in rows:
        ts = ev["Timestamp"]
        dt = ts if isinstance(ts, datetime) else datetime.utcnow().replace(tzinfo=timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_floor = dt.replace(second=0, microsecond=0)
        entity   = ev.get("dst_ns") or ev.get("src_ns") or "unknown"
        groups.setdefault((entity, dt_floor), []).append(ev)

    records = [
        feat for (ns, ws), evs in groups.items()
        if (feat := extract_features(evs, ws, ns))
    ]
    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values(["window_start", "entity_namespace"]).reset_index(drop=True)
    log.info(f"Built {len(df)} feature rows from {len(groups)} windows")
    return df


def main():
    p = argparse.ArgumentParser(description="Extract Cilium netflow security features")
    p.add_argument("--hours", type=int, default=2)
    p.add_argument("--from",  dest="from_dt")
    p.add_argument("--to",    dest="to_dt")
    p.add_argument("--out",   default="dataset/network_features.parquet")
    p.add_argument("--host",  default="localhost")
    p.add_argument("--batch", type=int, default=10,
                   help="Размер батча в минутах (default: 10)")
    args = p.parse_args()

    now = datetime.now(timezone.utc)
    if args.from_dt:
        start = datetime.fromisoformat(args.from_dt).replace(tzinfo=timezone.utc)
        end   = (datetime.fromisoformat(args.to_dt).replace(tzinfo=timezone.utc)
                 if args.to_dt else now)
    else:
        end   = now
        start = end - timedelta(hours=args.hours)

    log.info(f"Period: {start} → {end}")
    client = get_client(args.host)
    rows   = fetch_events(client, start, end, batch_minutes=args.batch)
    if not rows:
        log.warning("No events found"); return

    df = build_windows(rows)
    if df.empty:
        log.warning("Empty DataFrame"); return

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)
    log.info(f"Saved {len(df)} rows → {args.out}")

    feat_cols = [c for c in df.columns if c.startswith("feat_")]
    print("\n=== СТАТИСТИКА ===")
    print(f"Строк (entity × window): {len(df)}")
    print(f"Уникальных namespace:    {df['entity_namespace'].nunique()}")
    print(f"Период:                  {df['window_start'].min()} → {df['window_start'].max()}")

    print("\nТоп-5 namespace по объёму трафика:")
    print(df.groupby("entity_namespace")["feat_total_flows"]
            .sum().sort_values(ascending=False).head().to_string())

    print("\nСредние значения признаков:")
    print(df[feat_cols].mean().round(4).to_string())

    dropped = df[df["feat_dropped_flows"] > 0]
    print(f"\nОкна с DROPPED flows: {len(dropped)}")
    if not dropped.empty:
        print(dropped[["window_start", "entity_namespace",
                        "feat_dropped_flows"]].head(5).to_string(index=False))

    scanning = df[df["feat_port_diversity_ratio"] > 0.1]
    print(f"\nОкна с высоким port diversity ratio (>0.1): {len(scanning)}")
    if not scanning.empty:
        print(scanning[["window_start", "entity_namespace",
                         "feat_port_diversity_ratio",
                         "feat_syn_count"]].head(5).to_string(index=False))


if __name__ == "__main__":
    main()