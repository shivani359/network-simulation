-- Read-only examples for the educational synthetic development database.
-- Use production data only with explicit authorization and privacy review.

-- 1. Open alert queue by severity and newest event.
SELECT alert_id, timestamp, severity, risk_score, rule_id, source_ip, destination_ip, status
FROM ids_alerts
WHERE status IN ('NEW', 'INVESTIGATING')
ORDER BY
  CASE severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 4
    ELSE 5
  END,
  timestamp DESC
LIMIT 100;

-- 2. Recent repeated source/rule observations in a one-minute window.
SELECT source_ip, rule_id, COUNT(*) AS alert_count,
       MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
FROM ids_alerts
WHERE timestamp >= NOW() - INTERVAL '1 minute'
GROUP BY source_ip, rule_id
HAVING COUNT(*) > 1
ORDER BY alert_count DESC, last_seen DESC;

-- 3. Current flow classification distribution.
SELECT classification, COUNT(*) AS flow_count,
       ROUND(AVG(risk_score)::numeric, 1) AS average_risk
FROM network_flows
GROUP BY classification
ORDER BY flow_count DESC;

-- 4. Analyst disposition summary for a review period.
SELECT status, COUNT(*) AS alert_count,
       ROUND(AVG(risk_score)::numeric, 1) AS average_risk
FROM ids_alerts
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY status
ORDER BY alert_count DESC;

-- 5. Inspect active rule tuning values.
SELECT rule_id, name, severity, threshold, threshold_label, enabled
FROM detection_rules
ORDER BY rule_id;