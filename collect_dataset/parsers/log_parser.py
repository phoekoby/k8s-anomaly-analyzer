"""
log_parser.py
-------------
Читает логи приложений из otel_cluster_logs (ClickHouse),
извлекает признаки на основе шаблонов Drain3 (entity × Δt=1min).

Подход: Template Mining вместо ручного парсинга
  - Drain3 автоматически кластеризует строки логов в шаблоны
    "User <*> logged in from <*>", "Failed password for <*>" и т.д.
  - Признаки окна = вектор частот Top-N шаблонов
  - Главный аномальный сигнал = новые шаблоны (unseen templates)
    которых не было в baseline — необычное поведение сервиса

Преимущества перед ручным парсингом:
  - Работает на любом формате (kafka, nginx, spring, postgres, falco...)
  - Не требует обновления при смене версии сервиса
  - Unsupervised: модель сама учит что нормально
  - Соответствует SOTA: DeepLog, LogAnomaly, LogBERT

Использование:
    # Шаг 1: обучить шаблоны на baseline (первый запуск)
    python log_parser.py --hours 24 --out dataset/log_features.parquet

    # Шаг 2: последующие запуски переиспользуют обученные шаблоны
    python log_parser.py --hours 24 --out dataset/log_features.parquet --templates templates.json
"""

import argparse
import json
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from clickhouse_driver import Client
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# Drain3 спамит "Starting Drain3 template miner" при каждом TemplateMiner()
# Заглушаем его внутренний логгер
logging.getLogger("drain3.template_miner").setLevel(logging.WARNING)

CLICKHOUSE_PORT = 9000
CLICKHOUSE_DB   = "default"
CLICKHOUSE_USER = "otelcollector"
CLICKHOUSE_PASS = "lXg}45T{F.4UelH-?4o}"

# Сколько Top-N шаблонов включать в вектор признаков
TOP_N_TEMPLATES = 200  # покрываем длинный хвост шаблонов

# Минимум строк в шаблоне чтобы попасть в Top-N (фильтр шума)
MIN_TEMPLATE_COUNT = 5

# Falco namespace — каждая строка уже security event, не шаблонизируем
FALCO_NAMESPACE = "falco"

# Паттерны для нормализации перед Drain3
# Заменяем высококардинальные значения на токены — Drain3 работает лучше
# Убираем ANSI escape коды ДО Drain3 — иначе цветные логи Bitnami
# создают отдельные шаблоны для одинаковых сообщений
RE_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]|\\u001b\[[0-9;]*[mGKHF]')

NORMALIZERS = [
    # IP адреса
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b'), '<IP>'),
    # UUID
    (re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
                re.IGNORECASE), '<UUID>'),
    # Kubernetes pod names (содержат хэш)
    (re.compile(r'\b([a-z][a-z0-9-]+)-[a-z0-9]{5,10}-[a-z0-9]{5}\b'), r'\1-<POD>'),
    # Временные метки внутри строки
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'),
     '<TS>'),
    # Hex значения
    (re.compile(r'\b0x[0-9a-fA-F]+\b'), '<HEX>'),
    # Пути к файлам с хэшами в имени
    (re.compile(r'/[a-zA-Z0-9/_.-]+/[a-f0-9]{32,}'), '<HASH_PATH>'),
    # Kafka/Java: OffsetAndEpoch списки — огромные уникальные строки
    # Без этого каждый список offset'ов становится отдельным шаблоном
    (re.compile(r'OffsetAndEpoch\(offset=\d+,\s*epoch=\d+\)'), '<OFFSET_EPOCH>'),
    # Kafka snapshot IDs: Set(OffsetAndEpoch(...), ...)
    (re.compile(r'Set\(<OFFSET_EPOCH>(?:,\s*<OFFSET_EPOCH>)*\)'), 'Set(<OFFSETS>)'),
    # Java stack trace frames: "at com.example.Class.method(File.java:123)"
    (re.compile(r'at [a-zA-Z][a-zA-Z0-9_.]+\([A-Za-z0-9_.]+:\d+\)'), 'at <FRAME>'),
    # Java class paths в логах (длинные пути через точку)
    (re.compile(r'\b[a-z][a-z0-9]+(?:\.[a-z][a-z0-9]+){3,}\b'), '<CLASS>'),
]

# Severity keywords для дополнительного сигнала
SEV_ERROR = re.compile(r'\b(ERROR|FATAL|CRITICAL|EXCEPTION|PANIC)\b', re.IGNORECASE)
SEV_WARN  = re.compile(r'\b(WARN|WARNING)\b', re.IGNORECASE)

# Falco severity
FALCO_CRITICAL = re.compile(r'\b(Emergency|Alert|Critical|Error|Warning)\b', re.IGNORECASE)


def get_client(host: str) -> Client:
    return Client(host=host, port=CLICKHOUSE_PORT, database=CLICKHOUSE_DB,
                  user=CLICKHOUSE_USER, password=CLICKHOUSE_PASS,
                  connect_timeout=30, send_receive_timeout=300)


def make_drain3() -> TemplateMiner:
    """
    Создаём Drain3 с настройками под kubernetes логи.
    sim_th=0.4 — низкий порог схожести, чтобы разные форматы
    (nginx, java, json-normalized) не смешивались в один шаблон.
    """
    cfg = TemplateMinerConfig()
    cfg.drain_sim_th      = 0.5   # порог схожести — 0.5 оптимально для k8s логов
                                   # 0.4 слишком низкий: похожие строки не сливались
    cfg.drain_depth       = 4     # глубина дерева Drain
    cfg.drain_max_children = 100  # макс ветвей на узел
    cfg.parametrize_numeric_tokens = True  # числа → <*>
    return TemplateMiner(config=cfg)


def normalize(line: str) -> str:
    """Нормализация строки перед подачей в Drain3.
    Порядок важен: сначала убираем ANSI, потом остальные паттерны.
    """
    # 1. Убираем ANSI escape коды (Bitnami цветные логи)
    line = RE_ANSI.sub('', line)
    # 2. Остальные нормализации
    for pattern, replacement in NORMALIZERS:
        line = pattern.sub(replacement, line)
    return line.strip()


# ── Загрузка событий ──────────────────────────────────────────────────────────

def fetch_events(client: Client, start: datetime, end: datetime,
                 batch_minutes: int = 30) -> list[dict]:
    all_rows = []
    batch_start = start
    log.info(f"Fetching {start.strftime('%H:%M')} → {end.strftime('%H:%M')} "
             f"in {batch_minutes}-min batches...")

    while batch_start < end:
        batch_end = min(batch_start + timedelta(minutes=batch_minutes), end)
        query = """
            SELECT
                Timestamp,
                Body,
                ResourceAttributes['k8s.namespace.name'] AS namespace,
                ResourceAttributes['service.name']        AS service
            FROM otel_cluster_logs
            WHERE Timestamp >= %(start)s
              AND Timestamp <  %(end)s
              AND Body != ''
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

    log.info(f"Total: {len(all_rows)} log records")
    return all_rows


# ── Шаг 1: Обучение шаблонов ─────────────────────────────────────────────────

def build_templates(rows: list[dict], namespace_filter: str = None) -> dict:
    """
    Прогоняем все строки через Drain3 и строим словарь шаблонов.
    Возвращает:
      {
        namespace: {
          miner: TemplateMiner,
          template_counts: Counter({template_id: count}),
          all_template_ids: set
        }
      }
    """
    # Группируем по namespace — у каждого свой miner
    # чтобы шаблоны не смешивались между kafka и nginx
    miners: dict[str, TemplateMiner] = {}
    template_counts: dict[str, Counter] = {}

    log.info("Building Drain3 templates per namespace...")
    for ev in rows:
        ns = ev.get("namespace") or "unknown"
        if namespace_filter and ns != namespace_filter:
            continue
        if ns == FALCO_NAMESPACE:
            continue  # Falco считаем отдельно

        body = ev.get("Body", "").strip()
        if not body:
            continue

        if ns not in miners:
            miners[ns] = make_drain3()
            template_counts[ns] = Counter()

        normalized = normalize(body)
        result = miners[ns].add_log_message(normalized)
        if result and result.get("cluster_id"):
            template_counts[ns][result["cluster_id"]] += 1

    # Логируем итог
    for ns, counter in template_counts.items():
        log.info(f"  {ns}: {len(counter)} unique templates, "
                 f"{sum(counter.values())} total lines")

    return {
        ns: {
            "miner": miners[ns],
            "template_counts": template_counts[ns],
        }
        for ns in miners
    }


# ── Шаг 2: Определение Top-N шаблонов для каждого namespace ──────────────────

def get_topn_templates(ns_data: dict, top_n: int = TOP_N_TEMPLATES) -> dict[str, list]:
    """
    Возвращает {namespace: [template_id_1, ..., template_id_N]}
    Это будут колонки в итоговом DataFrame.
    """
    result = {}
    for ns, data in ns_data.items():
        all_counts  = data["template_counts"]
        total_lines = sum(all_counts.values())
        top = [
            tid for tid, cnt in all_counts.most_common()
            if cnt >= MIN_TEMPLATE_COUNT
        ][:top_n]
        covered = sum(all_counts[tid] for tid in top)
        coverage = round(covered / total_lines * 100, 1) if total_lines > 0 else 0
        result[ns] = top
        log.info(f"  {ns}: top-{len(top)} templates, coverage {coverage}% of lines")
    return result


# ── Шаг 3: Извлечение признаков из окна ──────────────────────────────────────

def extract_features(events: list[dict], window_start: datetime, entity: str,
                     miner: TemplateMiner, topn_ids: list[int]) -> dict | None:
    n = len(events)
    if n == 0:
        return None

    # Счётчики шаблонов в этом окне
    window_counts  = Counter()
    unseen_count   = 0   # шаблоны не из Top-N — ключевой аномальный сигнал
    error_count    = 0
    warn_count     = 0
    falco_alerts   = 0
    falco_critical_count = 0

    topn_set = set(topn_ids)  # вычисляем один раз вне цикла

    for ev in events:
        body = ev.get("Body", "").strip()
        if not body:
            continue

        ns = ev.get("namespace", "")

        # Falco обрабатываем отдельно
        if ns == FALCO_NAMESPACE:
            falco_alerts += 1
            if FALCO_CRITICAL.search(body):
                falco_critical_count += 1
            continue

        # Severity сигналы (быстрее чем Drain3 для счётчиков)
        if SEV_ERROR.search(body):  error_count += 1
        if SEV_WARN.search(body):   warn_count  += 1

        # Drain3 матчинг — match() не изменяет miner, только проверяет
        normalized = normalize(body)
        cluster = miner.match(normalized)

        if cluster is not None:
            tid = cluster.cluster_id
            if tid in topn_set:
                window_counts[tid] += 1
            # else: известный но редкий шаблон — норма, не считаем как аномалию
        else:
            unseen_count += 1  # полностью новый шаблон которого нет в miner — аномалия

    # Вектор Top-N шаблонов (topn_set определён до цикла — см. выше)
    template_vector = {
        f"tmpl_{tid}": window_counts.get(tid, 0)
        for tid in topn_ids
    }

    # Нормализованный счётчик unseen
    unseen_ratio = round(unseen_count / n, 4) if n > 0 else 0.0

    return {
        "window_start":     window_start.isoformat(),
        "entity_namespace": entity,

        # ── SECURITY ПРИЗНАКИ ──────────────────────────────────────────────

        # Главный сигнал аномалии — новые/редкие шаблоны
        "feat_unseen_templates":       unseen_count,
        "feat_unseen_ratio":           unseen_ratio,

        # Severity signals
        "feat_error_count":            error_count,
        "feat_error_ratio":            round(error_count / n, 4),
        "feat_warn_count":             warn_count,

        # Falco alerts (прямые security события)
        "feat_falco_alerts":           falco_alerts,
        "feat_falco_critical":         falco_critical_count,

        # Общий объём
        "feat_total_log_lines":        n,

        # Вектор Top-N шаблонов (разреженный, но информативный)
        **template_vector,
    }


# ── Шаг 4: Оконная агрегация ──────────────────────────────────────────────────

def build_windows(rows: list[dict], ns_data: dict,
                  topn_map: dict[str, list]) -> pd.DataFrame:
    # Группируем события по (namespace × 1-минутное окно)
    groups: dict[tuple, list] = {}
    for ev in rows:
        ts = ev["Timestamp"]
        dt = ts if isinstance(ts, datetime) else datetime.utcnow().replace(tzinfo=timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_floor = dt.replace(second=0, microsecond=0)
        entity   = ev.get("namespace") or "unknown"
        groups.setdefault((entity, dt_floor), []).append(ev)

    # Один пустой miner для namespace без шаблонов (falco, unknown)
    # Создаём один раз — не на каждое окно
    empty_miner = make_drain3()

    records = []
    for (ns, ws), events in groups.items():
        if ns not in ns_data:
            feat = extract_features(events, ws, ns, empty_miner, [])
        else:
            feat = extract_features(events, ws, ns,
                                    ns_data[ns]["miner"],
                                    topn_map.get(ns, []))
        if feat:
            records.append(feat)

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values(["window_start", "entity_namespace"]).reset_index(drop=True)
        # Заполняем NaN нулями (разные namespace имеют разные шаблоны)
        tmpl_cols = [c for c in df.columns if c.startswith("tmpl_")]
        df[tmpl_cols] = df[tmpl_cols].fillna(0).astype(int)

    log.info(f"Built {len(df)} feature rows from {len(groups)} windows")
    return df


# ── Сохранение шаблонов ───────────────────────────────────────────────────────

def save_templates(ns_data: dict, topn_map: dict, path: str):
    """Сохраняем словарь шаблонов для повторного использования."""
    export = {}
    for ns, data in ns_data.items():
        miner = data["miner"]
        export[ns] = {
            "templates": {
                str(c.cluster_id): c.get_template()
                for c in miner.drain.id_to_cluster.values()
            },
            "topn_ids": topn_map.get(ns, []),
            "counts": {str(k): v for k, v in data["template_counts"].items()}
        }
    with open(path, "w") as f:
        json.dump(export, f, indent=2, ensure_ascii=False)
    log.info(f"Saved templates → {path}")


def print_top_templates(ns_data: dict, topn_map: dict, n: int = 5):
    """Вывод топ шаблонов для интерпретации."""
    print("\n=== TOP ШАБЛОНЫ ПО NAMESPACE ===")
    for ns, top_ids in topn_map.items():
        miner  = ns_data[ns]["miner"]
        counts = ns_data[ns]["template_counts"]
        print(f"\n{ns}:")
        for tid in top_ids[:n]:
            cluster = miner.drain.id_to_cluster.get(tid)
            tmpl = cluster.get_template() if cluster else "?"
            print(f"  [{tid}] ({counts[tid]:>6}x) {tmpl[:100]}")


# ── Основная функция ──────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Log anomaly detection via Drain3 template mining")
    p.add_argument("--hours",      type=int, default=24)
    p.add_argument("--from",       dest="from_dt")
    p.add_argument("--to",         dest="to_dt")
    p.add_argument("--out",        default="dataset/log_features.parquet")
    p.add_argument("--host",       default="localhost")
    p.add_argument("--batch",      type=int, default=30)
    p.add_argument("--top-n",      type=int, default=TOP_N_TEMPLATES,
                   help="Сколько top шаблонов включать в вектор признаков")
    p.add_argument("--save-templates", default="dataset/log_templates.json",
                   help="Куда сохранить словарь шаблонов")
    p.add_argument("--namespace",  default=None,
                   help="Обработать только один namespace (для отладки)")
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

    # Загружаем события
    rows = fetch_events(client, start, end, batch_minutes=args.batch)
    if not rows:
        log.warning("No events found"); return

    # Строим шаблоны
    ns_data = build_templates(rows, namespace_filter=args.namespace)
    if not ns_data:
        log.warning("No templates built"); return

    # Выбираем Top-N
    topn_map = get_topn_templates(ns_data, top_n=args.top_n)

    # Строим окна с признаками
    df = build_windows(rows, ns_data, topn_map)
    if df.empty:
        log.warning("Empty DataFrame"); return

    # Сохраняем
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)
    log.info(f"Saved {len(df)} rows → {args.out}")

    if args.save_templates:
        save_templates(ns_data, topn_map, args.save_templates)

    # Статистика
    feat_cols = [c for c in df.columns if c.startswith("feat_")]
    print(f"\n=== СТАТИСТИКА ===")
    print(f"Строк (entity × window): {len(df)}")
    print(f"Уникальных namespace:    {df['entity_namespace'].nunique()}")
    print(f"Период:                  {df['window_start'].min()} → {df['window_start'].max()}")
    print(f"Всего признаков:         {len(df.columns) - 2} "
          f"(из них шаблонов: {len([c for c in df.columns if c.startswith('tmpl_')])})")

    print(f"\nТоп-5 namespace по объёму логов:")
    print(df.groupby("entity_namespace")["feat_total_log_lines"]
            .sum().sort_values(ascending=False).head().to_string())

    print(f"\nСредние значения security признаков:")
    print(df[feat_cols].mean().round(4).to_string())

    print(f"\nОкна с высоким feat_unseen_ratio (>0.3): "
          f"{len(df[df['feat_unseen_ratio'] > 0.3])}")

    print(f"\nОкна с Falco alerts: "
          f"{len(df[df['feat_falco_alerts'] > 0])}")

    # Топ шаблонов
    print_top_templates(ns_data, topn_map, n=3)


if __name__ == "__main__":
    main()