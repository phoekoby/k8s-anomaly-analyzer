"""
audit_parser.py
---------------
Читает события из k8s_audit_logs (ClickHouse), парсит Body JSON,
извлекает 15 security-признаков на каждое окно (entity × Δt=1min).

Результат сохраняется в Parquet файл для обучения модели.

Использование:
    python audit_parser.py --hours 24 --out dataset/audit_features.parquet
    python audit_parser.py --from "2026-02-23 00:00:00" --to "2026-02-24 00:00:00"
"""

import argparse
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from clickhouse_driver import Client

# ── Логирование ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ── Настройки подключения ─────────────────────────────────────────────────────
CLICKHOUSE_HOST = "clickstack-clickhouse.ae-monitoring.svc.cluster.local"
CLICKHOUSE_PORT = 9000
CLICKHOUSE_DB   = "default"
CLICKHOUSE_USER = "otelcollector"
CLICKHOUSE_PASS = "lXg}45T{F.4UelH-?4o}"

TABLE = "k8s_audit_logs"
WINDOW_MINUTES = 1  # размер окна агрегации

# ── Security-релевантные константы ────────────────────────────────────────────

# Ресурсы связанные с credential access (T1552)
SENSITIVE_RESOURCES = {"secrets", "serviceaccounts/token", "configmaps"}

# Ресурсы exec/attach (T1609 Execution)
EXEC_RESOURCES = {"pods/exec", "pods/attach", "pods/portforward"}

# RBAC ресурсы (Privilege Escalation)
RBAC_RESOURCES = {"roles", "rolebindings", "clusterroles", "clusterrolebindings"}

# Verbs которые изменяют состояние (не read-only)
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}

# Стандартные системные user agents (не подозрительные)
SYSTEM_AGENTS = {
    "kube-scheduler", "kube-controller-manager",
    "kubectl", "kubelet", "kube-proxy"
}


# ── Подключение к ClickHouse ──────────────────────────────────────────────────

def get_client(args: argparse.Namespace) -> Client:
    return Client(
        host=args.host,
        port=args.port,
        database=args.database,
        user=args.user,
        password=args.password,
        settings={"use_numpy": False}
    )


# ── Загрузка сырых событий ────────────────────────────────────────────────────

def fetch_raw_events(client: Client, start: datetime, end: datetime) -> list[dict]:
    """
    Читаем строки из k8s_audit_logs за указанный период.
    Body содержит полный JSON audit event.
    """
    query = f"""
        SELECT
            Timestamp,
            Body
        FROM {TABLE}
        WHERE Timestamp >= %(start)s
          AND Timestamp <  %(end)s
          AND Body != ''
        ORDER BY Timestamp
    """
    log.info(f"Fetching events from {start} to {end}...")
    rows = client.execute(query, {"start": start, "end": end})
    log.info(f"Fetched {len(rows)} raw rows")
    return rows


# ── Парсинг одного события ────────────────────────────────────────────────────

def parse_event(body: str) -> dict | None:
    """
    Парсим JSON из поля Body.
    Возвращаем плоский dict с нужными полями или None если не парсится.
    """
    try:
        e = json.loads(body)
    except json.JSONDecodeError:
        return None

    # Базовые поля
    verb       = e.get("verb", "")
    stage      = e.get("stage", "")
    level      = e.get("level", "")

    # Пропускаем незавершённые запросы
    if stage != "ResponseComplete":
        return None

    # User
    user       = e.get("user", {})
    username   = user.get("username", "unknown")
    groups     = user.get("groups", [])
    user_agent = e.get("userAgent", "")

    # ObjectRef
    obj        = e.get("objectRef", {})
    resource   = obj.get("resource", "")
    subresource = obj.get("subresource", "")
    namespace  = obj.get("namespace", "") or "cluster-scoped"
    name       = obj.get("name", "")

    # Полный ресурс с subresource (например pods/exec)
    full_resource = f"{resource}/{subresource}" if subresource else resource

    # Response
    resp       = e.get("responseStatus", {})
    resp_code  = resp.get("code", 0)

    # Source
    source_ips = e.get("sourceIPs", [])
    source_ip  = source_ips[0] if source_ips else ""

    # Timestamp
    ts_str     = e.get("requestReceivedTimestamp", e.get("stageTimestamp", ""))

    # Annotations
    annotations = e.get("annotations", {})
    authz_decision = annotations.get("authorization.k8s.io/decision", "")

    return {
        "timestamp_str": ts_str,
        "verb": verb,
        "username": username,
        "groups": groups,
        "user_agent": user_agent,
        "resource": resource,
        "full_resource": full_resource,
        "namespace": namespace,
        "object_name": name,
        "resp_code": resp_code,
        "source_ip": source_ip,
        "authz_decision": authz_decision,
        "level": level,
    }


# ── Извлечение признаков из окна ──────────────────────────────────────────────

def extract_features(window_events: list[dict], window_start: datetime, entity: str) -> dict:
    """
    По списку событий одного окна (entity × 1min) извлекаем 15 security-признаков.

    entity = namespace (основная единица агрегации)
    """
    n = len(window_events)
    if n == 0:
        return None

    # Счётчики
    exec_count          = 0  # pods/exec, pods/attach, pods/portforward
    secrets_count       = 0  # обращения к secrets и токенам
    secrets_list_count  = 0  # именно list secrets (mass dumping)
    failed_count        = 0  # HTTP >= 400
    anonymous_count     = 0  # system:anonymous
    rbac_change_count   = 0  # write operations на RBAC ресурсах
    token_request_count = 0  # serviceaccounts/token
    portforward_count   = 0  # pods/portforward отдельно
    write_sensitive     = 0  # write verbs на чувствительных ресурсах
    denied_count        = 0  # authz decision = deny
    cross_ns_count  = 0   # запросы из чужого namespace (T1210 Lateral Movement)
    watch_count     = 0   # verb=watch на sensitive ресурсах (T1552 persistence)
    new_pod_count   = 0   # verb=create, resource=pods (T1610 Deploy Container)

    unique_users        = set()
    unique_source_ips   = set()
    unusual_agents      = set()
    verbs_seen          = set()
    resources_seen      = set()

    for ev in window_events:
        verb          = ev["verb"]
        resource      = ev["resource"]
        full_resource = ev["full_resource"]
        username      = ev["username"]
        resp_code     = ev["resp_code"]
        user_agent    = ev["user_agent"]
        source_ip     = ev["source_ip"]
        authz         = ev["authz_decision"]

        unique_users.add(username)
        unique_source_ips.add(source_ip)
        verbs_seen.add(verb)
        resources_seen.add(full_resource)

        # T1609 — Execution
        if full_resource in EXEC_RESOURCES:
            exec_count += 1
        if full_resource == "pods/portforward":
            portforward_count += 1

        # T1552 — Credential Access
        if resource in {"secrets", "configmaps"}:
            secrets_count += 1
            if verb == "list":
                secrets_list_count += 1
        if full_resource == "serviceaccounts/token":
            token_request_count += 1
            secrets_count += 1

        # Privilege Escalation — RBAC changes
        if resource in RBAC_RESOURCES and verb in WRITE_VERBS:
            rbac_change_count += 1

        # Write на чувствительных ресурсах
        if resource in SENSITIVE_RESOURCES and verb in WRITE_VERBS:
            write_sensitive += 1

        # Ошибки доступа
        if resp_code >= 400:
            failed_count += 1
        if resp_code == 403:
            denied_count += 1

        # Анонимные запросы
        if username == "system:anonymous":
            anonymous_count += 1

        # Нестандартные user agents
        ua_lower = user_agent.lower()
        is_system = any(s in ua_lower for s in SYSTEM_AGENTS)
        is_kubectl = "kubectl" in ua_lower
        is_kube    = "kube" in ua_lower
        if not is_system and not is_kubectl and not is_kube and user_agent:
            unusual_agents.add(user_agent)

        if username.startswith("system:serviceaccount:"):
            parts = username.split(":")
            if len(parts) >= 4 and parts[2] != entity and parts[2] != "":
                cross_ns_count += 1

        # T1552 persistence: watch на sensitive ресурсах
        # Атакующий ставит watch чтобы получать изменения без повторных GET
        if verb == "watch" and resource in SENSITIVE_RESOURCES:
            watch_count += 1

        # T1610 — Deploy Container: создание новых подов
        if verb == "create" and resource == "pods":
            new_pod_count += 1

    # Производные признаки
    secrets_list_ratio = (
        secrets_list_count / secrets_count if secrets_count > 0 else 0.0
    )
    failed_ratio = failed_count / n if n > 0 else 0.0

    return {
        # Идентификаторы окна
        "window_start":           window_start.isoformat(),
        "entity_namespace":       entity,

        # ── 15 SECURITY ПРИЗНАКОВ ──────────────────────────────────────────

        # T1609 Execution
        "feat_exec_events_count":       exec_count,
        "feat_portforward_count":       portforward_count,

        # T1552 Credential Access
        "feat_secrets_access_count":    secrets_count,
        "feat_secrets_list_count":      secrets_list_count,
        "feat_secrets_list_ratio":      round(secrets_list_ratio, 4),
        "feat_token_request_count":     token_request_count,

        # Privilege Escalation
        "feat_rbac_change_count":       rbac_change_count,
        "feat_write_sensitive_count":   write_sensitive,

        # Ошибки и отказы
        "feat_failed_requests_count":   failed_count,
        "feat_denied_count":            denied_count,
        "feat_failed_ratio":            round(failed_ratio, 4),

        # Анонимный доступ
        "feat_anonymous_count":         anonymous_count,

        # Энтропия активности
        "feat_unique_users_count":      len(unique_users),
        "feat_unique_source_ips":       len(unique_source_ips),
        "feat_unusual_agents_count":    len(unusual_agents),

        # Общий объём
        "feat_total_events":            n,

        # Для отладки и EDA (не входят в модель напрямую)
        "_unique_users_list":   list(unique_users)[:10],
        "_verbs_seen":          list(verbs_seen),
        "_resources_seen":      list(resources_seen)[:10],

        "feat_cross_namespace_access": cross_ns_count,

        # T1552 Watch persistence
        "feat_watch_sensitive":        watch_count,

        # T1610 Deploy Container
        "feat_new_pod_count":          new_pod_count,
    }


# ── Оконная агрегация ─────────────────────────────────────────────────────────

def build_windows(rows: list, window_minutes: int = 1) -> pd.DataFrame:
    """
    Группируем события по (namespace, 1-минутное окно) и извлекаем признаки.
    """
    # Парсим все события
    parsed = []
    for ts, body in rows:
        ev = parse_event(body)
        if ev is None:
            continue

        # Определяем timestamp
        try:
            if ev["timestamp_str"]:
                dt = datetime.fromisoformat(
                    ev["timestamp_str"].replace("Z", "+00:00")
                )
            else:
                dt = ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts))
        except Exception:
            dt = ts if isinstance(ts, datetime) else datetime.utcnow()

        # Округляем до минуты
        dt_floor = dt.replace(second=0, microsecond=0)
        ev["_dt"]     = dt
        ev["_window"] = dt_floor
        parsed.append(ev)

    if not parsed:
        log.warning("No valid events after parsing")
        return pd.DataFrame()

    log.info(f"Parsed {len(parsed)} valid events")

    # Группируем по (namespace × window)
    groups: dict[tuple, list] = {}
    for ev in parsed:
        key = (ev["namespace"], ev["_window"])
        groups.setdefault(key, []).append(ev)

    # Извлекаем признаки для каждой группы
    records = []
    for (namespace, window_start), events in groups.items():
        features = extract_features(events, window_start, namespace)
        if features:
            records.append(features)

    df = pd.DataFrame(records)

    # Сортируем
    if not df.empty:
        df = df.sort_values(["window_start", "entity_namespace"]).reset_index(drop=True)

    log.info(f"Built {len(df)} feature rows from {len(groups)} windows")
    return df


# ── Основная функция ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Extract audit log security features")
    parser.add_argument("--hours",  type=int, default=24,
                        help="Сколько часов назад читать (default: 24)")
    parser.add_argument("--from",   dest="from_dt", default=None,
                        help="Начало периода: '2026-02-23 00:00:00'")
    parser.add_argument("--to",     dest="to_dt",   default=None,
                        help="Конец периода: '2026-02-24 00:00:00'")
    parser.add_argument("--out",    default="dataset/audit_features.parquet",
                        help="Путь к выходному Parquet файлу")
    parser.add_argument("--host",   default=CLICKHOUSE_HOST,
                        help="ClickHouse host")
    parser.add_argument("--port",   default=CLICKHOUSE_PORT,
                        help="ClickHouse port")
    parser.add_argument("--database", default=CLICKHOUSE_DB,
                        help="ClickHouse database")
    parser.add_argument("--user",   default=CLICKHOUSE_USER,
                        help="ClickHouse user")
    parser.add_argument("--password", default=CLICKHOUSE_PASS,
                        help="ClickHouse password")
    args = parser.parse_args()

    # Временной диапазон
    now = datetime.now(timezone.utc)
    if args.from_dt:
        start = datetime.fromisoformat(args.from_dt).replace(tzinfo=timezone.utc)
        end   = datetime.fromisoformat(args.to_dt).replace(tzinfo=timezone.utc) if args.to_dt else now
    else:
        end   = now
        start = end - timedelta(hours=args.hours)

    log.info(f"Period: {start} → {end}")

    # Подключение
    client = get_client(args)

    # Загрузка сырых событий
    rows = fetch_raw_events(client, start, end)
    if not rows:
        log.warning("No events found for the specified period")
        return

    # Оконная агрегация и извлечение признаков
    df = build_windows(rows, window_minutes=WINDOW_MINUTES)
    if df.empty:
        log.warning("Empty DataFrame after feature extraction")
        return

    # Сохранение
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)
    log.info(f"Saved {len(df)} rows → {out_path}")

    # Краткая статистика
    print("\n=== СТАТИСТИКА ===")
    print(f"Всего строк (entity × window): {len(df)}")
    print(f"Уникальных namespace:          {df['entity_namespace'].nunique()}")
    print(f"Период:                        {df['window_start'].min()} → {df['window_start'].max()}")
    print(f"\nТоп-5 namespace по количеству окон:")
    print(df['entity_namespace'].value_counts().head())
    print(f"\nСредние значения признаков:")
    feat_cols = [c for c in df.columns if c.startswith("feat_")]
    print(df[feat_cols].mean().round(3).to_string())


if __name__ == "__main__":
    main()
