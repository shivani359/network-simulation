import { randomUUID } from "node:crypto";
import type { NetworkFlow } from "@workspace/db";

export type Protocol = "TCP" | "UDP" | "ICMP";
export type Classification = "NORMAL" | "SUSPICIOUS" | "POTENTIAL_INTRUSION";
export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface DetectionRule {
  ruleId: string;
  name: string;
  description: string;
  severity: Severity;
  threshold: number;
  thresholdLabel: string;
  enabled: boolean;
}

export interface FlowRecord {
  flowId: string;
  timestamp: Date;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: Protocol;
  packetCount: number;
  byteCount: number;
  durationSeconds: number;
  connectionCount: number;
  failedConnectionCount: number;
  synCount: number;
  rstCount: number;
  averagePacketSize: number;
  uniqueDestinationPorts: number;
  uniqueDestinationIps: number;
  scenarioType: string;
  classification: Classification;
  riskScore: number;
  anomalyScore: number;
  ruleIds: string[];
}

export interface FlowFeatures {
  bytesPerSecond: number;
  packetsPerSecond: number;
  connectionRate: number;
  failureRatio: number;
  synRatio: number;
  uniqueDestinationPorts: number;
  uniqueDestinationIps: number;
}

export interface BaselineValue {
  mean: number;
  deviation: number;
}

export type Baseline = Record<keyof FlowFeatures, BaselineValue>;

export const NORMAL_SCENARIOS = [
  "NORMAL_WEB",
  "NORMAL_DNS",
  "NORMAL_SSH",
  "NORMAL_EMAIL",
  "NORMAL_DATABASE",
] as const;

export const SUSPICIOUS_SCENARIOS = [
  "HIGH_CONNECTION_RATE",
  "REPEATED_FAILED_CONNECTIONS",
  "MULTI_PORT_PROBING_PATTERN",
  "SYN_HEAVY_PATTERN",
  "UNUSUAL_PORT_ACTIVITY",
  "HIGH_TRAFFIC_VOLUME",
] as const;

export const DEFAULT_RULES: DetectionRule[] = [
  {
    ruleId: "IDS-001",
    name: "High connection rate",
    description: "Observed connection rate exceeded the configured synthetic baseline.",
    severity: "HIGH",
    threshold: 10,
    thresholdLabel: "connections / second",
    enabled: true,
  },
  {
    ruleId: "IDS-002",
    name: "Repeated failed connections",
    description: "Several connection attempts failed and the failure ratio is unusually high.",
    severity: "HIGH",
    threshold: 0.45,
    thresholdLabel: "failure ratio",
    enabled: true,
  },
  {
    ruleId: "IDS-003",
    name: "Destination-port diversity",
    description: "A single synthetic flow record represents activity across many destination ports.",
    severity: "MEDIUM",
    threshold: 8,
    thresholdLabel: "unique destination ports",
    enabled: true,
  },
  {
    ruleId: "IDS-004",
    name: "SYN-heavy pattern",
    description: "The SYN proportion is unusually high for the observed packet count.",
    severity: "HIGH",
    threshold: 0.8,
    thresholdLabel: "SYN / packet ratio",
    enabled: true,
  },
  {
    ruleId: "IDS-005",
    name: "Unusual service port",
    description: "The destination port is outside the small set of common training services.",
    severity: "MEDIUM",
    threshold: 1,
    thresholdLabel: "non-standard service port",
    enabled: true,
  },
  {
    ruleId: "IDS-006",
    name: "High traffic volume",
    description: "The byte volume in this synthetic flow is above the configured threshold.",
    severity: "HIGH",
    threshold: 1_500_000,
    thresholdLabel: "bytes per flow",
    enabled: true,
  },
  {
    ruleId: "IDS-007",
    name: "Statistical baseline deviation",
    description: "Flow features diverged from the baseline built from normal synthetic records.",
    severity: "MEDIUM",
    threshold: 58,
    thresholdLabel: "anomaly score",
    enabled: true,
  },
];

const RESERVED_NETWORKS = [
  { prefix: "192.0.2", start: 1 },
  { prefix: "198.51.100", start: 1 },
  { prefix: "203.0.113", start: 1 },
];

const NORMAL_SERVICE: Record<(typeof NORMAL_SCENARIOS)[number], { port: number; protocol: Protocol }> = {
  NORMAL_WEB: { port: 443, protocol: "TCP" },
  NORMAL_DNS: { port: 53, protocol: "UDP" },
  NORMAL_SSH: { port: 22, protocol: "TCP" },
  NORMAL_EMAIL: { port: 587, protocol: "TCP" },
  NORMAL_DATABASE: { port: 5432, protocol: "TCP" },
};

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIp(): string {
  const network = RESERVED_NETWORKS[randomInt(0, RESERVED_NETWORKS.length - 1)];
  return `${network.prefix}.${randomInt(network.start, 253)}`;
}

function pick<T>(items: readonly T[]): T {
  return items[randomInt(0, items.length - 1)];
}

export function generateSyntheticFlow(scenario?: string): Omit<FlowRecord, "classification" | "riskScore" | "anomalyScore" | "ruleIds"> {
  const selectedScenario =
    scenario ??
    (Math.random() < 0.72 ? pick(NORMAL_SCENARIOS) : pick(SUSPICIOUS_SCENARIOS));
  const isNormal = (NORMAL_SCENARIOS as readonly string[]).includes(selectedScenario);
  const service = isNormal
    ? NORMAL_SERVICE[selectedScenario as (typeof NORMAL_SCENARIOS)[number]]
    : { port: 443, protocol: "TCP" as Protocol };

  let packetCount = randomInt(8, 45);
  let byteCount = randomInt(3_000, 70_000);
  let durationSeconds = Number((Math.random() * 18 + 2).toFixed(2));
  let connectionCount = randomInt(1, 8);
  let failedConnectionCount = randomInt(0, 1);
  let synCount = randomInt(1, Math.max(2, Math.floor(packetCount * 0.35)));
  let rstCount = randomInt(0, 2);
  let destinationPort = service.port;
  let protocol = service.protocol;
  let uniqueDestinationPorts = 1;
  let uniqueDestinationIps = 1;

  switch (selectedScenario) {
    case "HIGH_CONNECTION_RATE":
      packetCount = randomInt(70, 180);
      connectionCount = randomInt(40, 120);
      durationSeconds = Number((Math.random() * 0.75 + 0.25).toFixed(2));
      failedConnectionCount = randomInt(3, 20);
      synCount = randomInt(Math.floor(packetCount * 0.65), packetCount);
      break;
    case "REPEATED_FAILED_CONNECTIONS":
      connectionCount = randomInt(12, 35);
      failedConnectionCount = randomInt(8, connectionCount);
      durationSeconds = Number((Math.random() * 10 + 5).toFixed(2));
      packetCount = randomInt(18, 75);
      synCount = randomInt(8, 28);
      rstCount = randomInt(5, 20);
      break;
    case "MULTI_PORT_PROBING_PATTERN":
      connectionCount = randomInt(14, 38);
      uniqueDestinationPorts = randomInt(10, 28);
      destinationPort = randomInt(1_024, 60_000);
      durationSeconds = Number((Math.random() * 12 + 1).toFixed(2));
      packetCount = randomInt(25, 100);
      failedConnectionCount = randomInt(5, 22);
      synCount = randomInt(18, Math.max(18, packetCount));
      break;
    case "SYN_HEAVY_PATTERN":
      packetCount = randomInt(70, 180);
      synCount = randomInt(Math.ceil(packetCount * 0.84), packetCount);
      connectionCount = randomInt(18, 55);
      failedConnectionCount = randomInt(3, 16);
      durationSeconds = Number((Math.random() * 4 + 0.5).toFixed(2));
      rstCount = randomInt(3, 18);
      break;
    case "UNUSUAL_PORT_ACTIVITY":
      destinationPort = pick([4444, 1337, 31337, 49152, 55000]);
      connectionCount = randomInt(8, 26);
      failedConnectionCount = randomInt(2, 10);
      break;
    case "HIGH_TRAFFIC_VOLUME":
      byteCount = randomInt(2_000_000, 12_000_000);
      packetCount = randomInt(2_000, 18_000);
      durationSeconds = Number((Math.random() * 60 + 10).toFixed(2));
      connectionCount = randomInt(2, 12);
      break;
    case "NORMAL_DNS":
      packetCount = randomInt(1, 8);
      byteCount = randomInt(80, 1_400);
      durationSeconds = Number((Math.random() * 0.8 + 0.05).toFixed(2));
      protocol = "UDP";
      break;
    case "NORMAL_SSH":
      packetCount = randomInt(18, 90);
      byteCount = randomInt(2_500, 55_000);
      durationSeconds = Number((Math.random() * 110 + 15).toFixed(2));
      connectionCount = 1;
      break;
    case "NORMAL_EMAIL":
      byteCount = randomInt(2_000, 180_000);
      durationSeconds = Number((Math.random() * 7 + 1).toFixed(2));
      break;
    case "NORMAL_DATABASE":
      byteCount = randomInt(5_000, 140_000);
      connectionCount = randomInt(1, 4);
      durationSeconds = Number((Math.random() * 3 + 0.2).toFixed(2));
      break;
  }

  return {
    flowId: randomUUID(),
    timestamp: new Date(Date.now() - randomInt(0, 3_600_000)),
    sourceIp: randomIp(),
    destinationIp: randomIp(),
    sourcePort: randomInt(32_768, 65_000),
    destinationPort,
    protocol,
    packetCount,
    byteCount,
    durationSeconds,
    connectionCount,
    failedConnectionCount,
    synCount,
    rstCount,
    averagePacketSize: Number((byteCount / Math.max(1, packetCount)).toFixed(2)),
    uniqueDestinationPorts,
    uniqueDestinationIps,
    scenarioType: selectedScenario,
  };
}

export function generateSyntheticFlows(
  count: number,
  mode: "normal" | "mixed" | "suspicious",
  scenario?: string | null,
) {
  return Array.from({ length: count }, () => {
    if (scenario) return generateSyntheticFlow(scenario);
    const selectedMode = mode === "mixed" ? (Math.random() < 0.7 ? "normal" : "suspicious") : mode;
    return generateSyntheticFlow(
      selectedMode === "normal" ? pick(NORMAL_SCENARIOS) : pick(SUSPICIOUS_SCENARIOS),
    );
  });
}

export function extractNetworkFeatures(flow: Pick<
  NetworkFlow,
  | "packetCount"
  | "byteCount"
  | "durationSeconds"
  | "connectionCount"
  | "failedConnectionCount"
  | "synCount"
  | "uniqueDestinationPorts"
  | "uniqueDestinationIps"
>): FlowFeatures {
  const duration = Math.max(0.001, Number.isFinite(flow.durationSeconds) ? flow.durationSeconds : 0);
  const connections = Math.max(0, flow.connectionCount);
  const packets = Math.max(0, flow.packetCount);
  return {
    bytesPerSecond: Math.max(0, flow.byteCount) / duration,
    packetsPerSecond: packets / duration,
    connectionRate: connections / duration,
    failureRatio: connections === 0 ? 0 : Math.min(1, flow.failedConnectionCount / connections),
    synRatio: packets === 0 ? 0 : Math.min(1, flow.synCount / packets),
    uniqueDestinationPorts: Math.max(1, flow.uniqueDestinationPorts),
    uniqueDestinationIps: Math.max(1, flow.uniqueDestinationIps),
  };
}

const DEFAULT_BASELINE: Baseline = {
  bytesPerSecond: { mean: 7_000, deviation: 18_000 },
  packetsPerSecond: { mean: 7, deviation: 11 },
  connectionRate: { mean: 1.2, deviation: 2 },
  failureRatio: { mean: 0.03, deviation: 0.12 },
  synRatio: { mean: 0.16, deviation: 0.2 },
  uniqueDestinationPorts: { mean: 1.1, deviation: 0.5 },
  uniqueDestinationIps: { mean: 1.05, deviation: 0.3 },
};

type BaselineFlow = Pick<
  NetworkFlow,
  | "packetCount"
  | "byteCount"
  | "durationSeconds"
  | "connectionCount"
  | "failedConnectionCount"
  | "synCount"
  | "uniqueDestinationPorts"
  | "uniqueDestinationIps"
>;

export function calculateBaseline(normalFlows: BaselineFlow[]): Baseline {
  if (normalFlows.length < 8) return DEFAULT_BASELINE;
  const features = normalFlows.map(extractNetworkFeatures);
  const keys = Object.keys(DEFAULT_BASELINE) as (keyof FlowFeatures)[];
  return Object.fromEntries(
    keys.map((key) => {
      const values = features.map((feature) => feature[key]);
      const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
      const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
      return [key, { mean, deviation: Math.max(Math.sqrt(variance), DEFAULT_BASELINE[key].deviation * 0.15) }];
    }),
  ) as Baseline;
}

export function calculateAnomalyScore(features: FlowFeatures, baseline: Baseline): number {
  const zScores = (Object.keys(features) as (keyof FlowFeatures)[]).map((key) => {
    const base = baseline[key];
    return Math.max(0, (features[key] - base.mean) / Math.max(base.deviation, 0.001));
  });
  const maxDeviation = Math.max(...zScores);
  const averageDeviation = zScores.reduce((sum, score) => sum + score, 0) / zScores.length;
  return Math.max(0, Math.min(100, Math.round(maxDeviation * 16 + averageDeviation * 12)));
}

export function analyzeFlow(
  flow: Omit<FlowRecord, "classification" | "riskScore" | "anomalyScore" | "ruleIds">,
  rules: DetectionRule[],
  baseline: Baseline,
): FlowRecord {
  const features = extractNetworkFeatures(flow);
  const anomalyScore = calculateAnomalyScore(features, baseline);
  const commonPorts = new Set([20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 1433, 3306, 5432, 6379, 8080, 8443]);

  const matches = rules.filter((rule) => {
    if (!rule.enabled) return false;
    switch (rule.ruleId) {
      case "IDS-001":
        return features.connectionRate >= rule.threshold;
      case "IDS-002":
        return flow.failedConnectionCount >= 5 && features.failureRatio >= rule.threshold;
      case "IDS-003":
        return features.uniqueDestinationPorts >= rule.threshold;
      case "IDS-004":
        return flow.synCount >= 12 && features.synRatio >= rule.threshold;
      case "IDS-005":
        return !commonPorts.has(flow.destinationPort);
      case "IDS-006":
        return flow.byteCount >= rule.threshold;
      case "IDS-007":
        return anomalyScore >= rule.threshold;
      default:
        return false;
    }
  });
  const severityWeight: Record<Severity, number> = {
    INFO: 12,
    LOW: 30,
    MEDIUM: 48,
    HIGH: 72,
    CRITICAL: 92,
  };
  const ruleRisk = matches.length
    ? Math.min(100, Math.max(...matches.map((rule) => severityWeight[rule.severity])) + (matches.length - 1) * 6)
    : 0;
  const riskScore = Math.round(ruleRisk * 0.7 + anomalyScore * 0.3);
  const classification: Classification =
    riskScore >= 61 ? "POTENTIAL_INTRUSION" : riskScore >= 21 ? "SUSPICIOUS" : "NORMAL";
  return {
    ...flow,
    anomalyScore,
    riskScore,
    classification,
    ruleIds: matches.map((rule) => rule.ruleId),
  };
}

export function severityForRisk(riskScore: number): Severity {
  if (riskScore >= 81) return "CRITICAL";
  if (riskScore >= 61) return "HIGH";
  if (riskScore >= 41) return "MEDIUM";
  if (riskScore >= 21) return "LOW";
  return "INFO";
}

export function correlateAlerts(
  alerts: Array<{ sourceIp: string; ruleId: string; timestamp: Date }>,
  windowSeconds = 60,
): Array<{ sourceIp: string; ruleId: string; count: number; firstSeen: Date; lastSeen: Date }> {
  const grouped = new Map<string, Date[]>();
  for (const alert of alerts) {
    const key = `${alert.sourceIp}:${alert.ruleId}`;
    const times = grouped.get(key) ?? [];
    times.push(alert.timestamp);
    grouped.set(key, times);
  }
  const groups: Array<{ sourceIp: string; ruleId: string; count: number; firstSeen: Date; lastSeen: Date }> = [];
  for (const [key, times] of grouped) {
    const [sourceIp, ruleId] = key.split(":");
    const ordered = times.sort((a, b) => a.getTime() - b.getTime());
    let start = 0;
    for (let end = 0; end < ordered.length; end += 1) {
      while (ordered[end].getTime() - ordered[start].getTime() > windowSeconds * 1000) start += 1;
      if (end - start > 0) {
        groups.push({
          sourceIp,
          ruleId,
          count: end - start + 1,
          firstSeen: ordered[start],
          lastSeen: ordered[end],
        });
      }
    }
  }
  return groups;
}