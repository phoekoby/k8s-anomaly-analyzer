-- ============================================================
-- Таблицы признаков для ClusterAnomalyAnalyzer
-- Колонки строго соответствуют return-значениям парсеров
-- ============================================================

DROP TABLE IF EXISTS features_audit;
CREATE TABLE features_audit
(
    window_start                DateTime,
    entity_namespace            String,
    feat_exec_events_count      Float32,
    feat_portforward_count      Float32,
    feat_secrets_access_count   Float32,
    feat_secrets_list_count     Float32,
    feat_secrets_list_ratio     Float32,
    feat_token_request_count    Float32,
    feat_rbac_change_count      Float32,
    feat_write_sensitive_count  Float32,
    feat_failed_requests_count  Float32,
    feat_denied_count           Float32,
    feat_failed_ratio           Float32,
    feat_anonymous_count        Float32,
    feat_unique_users_count     Float32,
    feat_unique_source_ips      Float32,
    feat_unusual_agents_count   Float32,
    feat_total_events           Float32,
    collected_at                DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(collected_at)
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (window_start, entity_namespace)
TTL window_start + INTERVAL 30 DAY;

DROP TABLE IF EXISTS features_logs;
CREATE TABLE features_logs
(
    window_start                DateTime,
    entity_namespace            String,
    feat_unseen_templates       Float32,
    feat_unseen_ratio           Float32,
    feat_error_count            Float32,
    feat_error_ratio            Float32,
    feat_warn_count             Float32,
    feat_falco_alerts           Float32,
    feat_falco_critical         Float32,
    feat_total_log_lines        Float32,
    collected_at                DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(collected_at)
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (window_start, entity_namespace)
TTL window_start + INTERVAL 30 DAY;

-- network_parser.extract_features return:
--   feat_dropped_flows, feat_dropped_ratio,
--   feat_external_ingress, feat_external_egress, feat_unique_external_dst,
--   feat_dns_query_count, feat_syn_count,
--   feat_port_diversity_ratio, feat_wellknown_ports_scanned,
--   feat_suspicious_port_hits, feat_icmp_count, feat_total_flows
DROP TABLE IF EXISTS features_network;
CREATE TABLE features_network
(
    window_start                    DateTime,
    entity_namespace                String,
    feat_total_flows                Float32,
    feat_dropped_flows              Float32,
    feat_dropped_ratio              Float32,
    feat_external_ingress           Float32,
    feat_external_egress            Float32,
    feat_unique_external_dst        Float32,
    feat_dns_query_count            Float32,
    feat_syn_count                  Float32,
    feat_port_diversity_ratio       Float32,
    feat_wellknown_ports_scanned    Float32,
    feat_suspicious_port_hits       Float32,
    feat_icmp_count                 Float32,
    collected_at                    DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(collected_at)
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (window_start, entity_namespace)
TTL window_start + INTERVAL 30 DAY;

DROP TABLE IF EXISTS features_metrics;
CREATE TABLE features_metrics
(
    window_start                    DateTime,
    entity_namespace                String,
    feat_container_restarts         Float32,
    feat_container_restarts_max     Float32,
    feat_pods_not_ready             Float32,
    feat_pods_running               Float32,
    feat_pods_pending               Float32,
    feat_pods_failed                Float32,
    feat_pods_succeeded             Float32,
    feat_pods_total                 Float32,
    feat_deployment_deficit         Float32,
    feat_replicaset_deficit         Float32,
    feat_statefulset_deficit        Float32,
    feat_daemonset_deficit          Float32,
    feat_cpu_requests_cores         Float32,
    feat_mem_requests_bytes         Float32,
    feat_cpu_limits_cores           Float32,
    feat_mem_limits_bytes           Float32,
    feat_job_failed_pods            Float32,
    feat_job_active_pods            Float32,
    feat_job_successful_pods        Float32,
    feat_crashloop_signal           Float32,
    feat_pending_ratio              Float32,
    feat_failed_ratio               Float32,
    feat_workload_instability       Float32,
    feat_resource_pressure          Float32,
    feat_cluster_cpu_load_avg       Float32,
    feat_cluster_cpu_spike          Float32,
    feat_cluster_mem_used_bytes     Float32,
    feat_cluster_net_bytes_out      Float32,
    feat_cluster_disk_write         Float32,
    collected_at                    DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(collected_at)
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (window_start, entity_namespace)
TTL window_start + INTERVAL 30 DAY;

SELECT name FROM system.tables
WHERE database = currentDatabase()
  AND name LIKE 'features_%'
ORDER BY name;