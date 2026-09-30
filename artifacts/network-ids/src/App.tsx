import { useMemo, useState } from 'react';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import {
  Activity, AlertCircle, AlertTriangle, ArrowRight,
  BarChart3, Check, CircleHelp, Database, Download, FileSearch, Gauge, GitBranch,
  ListFilter, LoaderCircle, LockKeyhole, Menu, Network, Plus, Radar,
  RefreshCw, Search, ShieldCheck, ShieldEllipsis, Sparkles, X,
} from 'lucide-react';
import {
  getGetAlertQueryKey, getGetAlertsQueryKey, getGetDashboardStatsQueryKey,
  getGetFlowsQueryKey, getGetRulesQueryKey, getGetTrafficAnalyticsQueryKey,
  useAddAlertNote, useGenerateSyntheticFlows, useGetAlert, useGetAlerts,
  useGetDashboardStats, useGetFlows, useGetRules, useGetTrafficAnalytics,
  useUpdateAlertStatus, useUpdateRule,
} from '@workspace/api-client-react';
import type { Alert, DetectionRule, Flow, SimulationInputScenario } from '@workspace/api-client-react';
import { Link, Route, Switch, useLocation, useParams } from 'wouter';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';

const queryClient = new QueryClient();

type Severity = Alert['severity'];
type Status = Alert['status'];
const fmt = (value?: number | null) => Number(value ?? 0).toLocaleString();
const dateTime = (value?: string) => value ? new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
const shortTime = (value?: string) => value ? new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
const titleCase = (value?: string) => value ? value.replaceAll('_', ' ').toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase()) : '—';

function getCorrelatedAlertCounts(alerts: readonly Alert[]): Map<string, number> {
  const groups = new Map<string, Alert[]>();
  for (const alert of alerts) {
    const key = `${alert.sourceIp}|${alert.ruleId}`;
    const group = groups.get(key) ?? [];
    group.push(alert);
    groups.set(key, group);
  }
  const counts = new Map<string, number>();
  for (const group of groups.values()) {
    const ordered = [...group].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    let start = 0;
    for (let end = 0; end < ordered.length; end += 1) {
      const endTime = new Date(ordered[end].timestamp).getTime();
      while (endTime - new Date(ordered[start].timestamp).getTime() > 60_000) start += 1;
      const clusterSize = end - start + 1;
      if (clusterSize > 1) {
        for (let index = start; index <= end; index += 1) {
          counts.set(ordered[index].alertId, clusterSize);
        }
      }
    }
  }
  return counts;
}

function SeverityChip({ severity }: { severity: Severity }) {
  return <span className={`severity-chip severity-${severity.toLowerCase()}`} data-testid={`severity-${severity.toLowerCase()}`}>{severity}</span>;
}
function StatusChip({ status }: { status: Status }) {
  return <span className={`status-chip status-${status.toLowerCase()}`} data-testid={`status-${status.toLowerCase()}`}>{titleCase(status)}</span>;
}
function ClassChip({ classification }: { classification: Flow['classification'] }) {
  return <span className={`class-chip class-${classification.toLowerCase()}`} data-testid={`classification-${classification.toLowerCase()}`}>{titleCase(classification)}</span>;
}
function PageHeading({ eyebrow, title, subtitle, children }: { eyebrow: string; title: string; subtitle: string; children?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p className="page-subtitle">{subtitle}</p></div>{children}</div>;
}
function PanelTitle({ title, hint, action }: { title: string; hint?: string; action?: React.ReactNode }) {
  return <div className="panel-head"><div><h2 className="panel-title">{title}</h2>{hint && <p className="panel-hint">{hint}</p>}</div>{action}</div>;
}
function ErrorMessage({ onRetry }: { onRetry: () => void }) {
  return <div className="error-state" data-testid="status-load-error"><AlertCircle size={18} /><span>Could not load this view. Check the connection and try again.</span><button className="btn btn-secondary" onClick={onRetry} data-testid="button-retry"><RefreshCw size={13} />Retry</button></div>;
}
function LoadingCards() {
  return <div className="stats-grid" aria-label="Loading dashboard"><div className="skeleton skeleton-card" /><div className="skeleton skeleton-card" /><div className="skeleton skeleton-card" /><div className="skeleton skeleton-card" /></div>;
}

function AppShell({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const title = location === '/' ? 'Overview' : location.startsWith('/alerts/') ? 'Alert investigation' : location.slice(1).replace(/^\w/, (c) => c.toUpperCase());
  const nav = [
    { href: '/', label: 'Overview', icon: Gauge },
    { href: '/alerts', label: 'Alert queue', icon: AlertTriangle },
    { href: '/flows', label: 'Flow records', icon: Network },
    { href: '/rules', label: 'Detection rules', icon: GitBranch },
  ];
  return <div className="shell">
    <aside className={`sidebar ${menuOpen ? 'open' : ''}`}>
      <div className="brand"><div className="brand-mark"><Radar size={20} strokeWidth={2.2} /></div><div><div className="brand-name">Signal Desk</div><div className="brand-sub">Network IDS lab</div></div></div>
      <div className="nav-label">Workspace</div>
      <nav className="nav-list" aria-label="Primary navigation">{nav.map(({ href, label, icon: Icon }) => <Link key={href} href={href} onClick={() => setMenuOpen(false)} className={`nav-link ${location === href || (href === '/alerts' && location.startsWith('/alerts/')) ? 'active' : ''}`} data-testid={`link-${label.toLowerCase().replaceAll(' ', '-')}`}><Icon size={17} /><span>{label}</span>{href === '/alerts' && <span className="nav-count">LIVE</span>}</Link>)}</nav>
      <div className="nav-label">Environment</div>
      <div className="safe-note"><ShieldCheck size={16} /><span>Training mode<br />Synthetic flow data only</span></div>
      <div className="sidebar-bottom"><div className="operator"><div className="operator-avatar">SA</div><div><strong>Student analyst</strong><small>Local SOC workspace</small></div></div></div>
    </aside>
    <div className="main-area">
      <header className="topbar">
        <button className="mobile-menu" aria-label="Open navigation" onClick={() => setMenuOpen(!menuOpen)} data-testid="button-mobile-menu">{menuOpen ? <X size={17} /> : <Menu size={17} />}</button>
        <div className="crumb"><span>Signal Desk</span><ArrowRight size={12} /><strong>{title}</strong></div>
        <div className="top-status"><span className="live-dot" />SIMULATION ENVIRONMENT</div>
      </header>
      <main className="main-content"><ErrorBoundary resetKey={location}>{children}</ErrorBoundary></main>
    </div>
  </div>;
}

function useRefreshGeneratedQueries() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
    void qc.invalidateQueries({ queryKey: getGetTrafficAnalyticsQueryKey() });
    void qc.invalidateQueries({ queryKey: getGetFlowsQueryKey() });
    void qc.invalidateQueries({ queryKey: getGetAlertsQueryKey() });
  };
}

function Overview() {
  const stats = useGetDashboardStats({ query: { queryKey: getGetDashboardStatsQueryKey(), refetchInterval: 15000 } });
  const traffic = useGetTrafficAnalytics({ query: { queryKey: getGetTrafficAnalyticsQueryKey(), refetchInterval: 20000 } });
  const alerts = useGetAlerts({ limit: 6 }, { query: { queryKey: getGetAlertsQueryKey({ limit: 6 }), refetchInterval: 12000 } });
  const refresh = useRefreshGeneratedQueries();
  const generate = useGenerateSyntheticFlows();
  const [mode, setMode] = useState<'normal' | 'mixed' | 'suspicious'>('mixed');
  const [scenario, setScenario] = useState<NonNullable<SimulationInputScenario> | ''>('');
  const [count, setCount] = useState('24');
  const [result, setResult] = useState<{ generated: number; alertsCreated: number } | null>(null);
  const [runError, setRunError] = useState('');
  const statsData = stats.data;
  const timeline = traffic.data?.timeline ?? [];
  const maxFlows = Math.max(1, ...timeline.map((bucket) => bucket.flows));
  const normal = statsData?.normalFlows ?? 0;
  const suspicious = statsData?.suspiciousFlows ?? 0;
  const allClassified = normal + suspicious;
  const normalPercent = allClassified ? Math.round(normal / allClassified * 100) : 0;
  const onGenerate = () => {
    setRunError('');
    setResult(null);
    generate.mutate({ data: { count: Math.max(1, Math.min(100, Number(count) || 1)), mode, ...(scenario ? { scenario } : {}) } }, {
      onSuccess: (data) => { setResult({ generated: data.generated, alertsCreated: data.alertsCreated }); refresh(); },
      onError: () => setRunError('Synthetic run could not be generated. Please retry.'),
    });
  };
  return <>
    <PageHeading eyebrow="SOC / training workspace" title="Operations overview" subtitle="Trace synthetic observations into explainable detections and analyst decisions.">
      <button className="btn btn-secondary" onClick={() => { void stats.refetch(); void traffic.refetch(); void alerts.refetch(); }} data-testid="button-refresh-overview"><RefreshCw size={14} />Refresh</button>
    </PageHeading>
    {result && <div className="result-banner" role="status" data-testid="status-run-success"><div><strong>Run complete.</strong> {result.generated} synthetic flow records generated; {result.alertsCreated} alerts created.</div><button className="btn btn-quiet" onClick={() => setResult(null)} data-testid="button-dismiss-run-result"><X size={14} />Dismiss</button></div>}
    {runError && <div className="result-banner" style={{ background: '#fbefed', borderColor: '#eed6d2', color: '#975248' }} role="alert" data-testid="status-run-error"><span>{runError}</span><button className="btn btn-secondary" onClick={() => setRunError('')} data-testid="button-dismiss-run-error"><X size={13} />Dismiss</button></div>}
    {stats.isLoading ? <LoadingCards /> : stats.isError ? <div className="panel"><ErrorMessage onRetry={() => { void stats.refetch(); void traffic.refetch(); }} /></div> : <>
      <section className="stats-grid" aria-label="Current simulation metrics">
        <StatCard label="Flows analyzed" value={fmt(statsData?.totalFlows)} detail="Synthetic records" icon={<Activity size={16} />} />
        <StatCard label="Open alerts" value={fmt(statsData?.openAlerts)} detail={`${fmt(statsData?.criticalAlerts)} critical triage signals`} icon={<AlertTriangle size={16} />} accent="amber" />
        <StatCard label="Mean risk signal" value={`${statsData?.averageRiskScore ?? 0}`} detail="Out of 100 · not a verdict" icon={<Gauge size={16} />} />
        <StatCard label="Flagged flows" value={fmt(statsData?.suspiciousFlows)} detail={`${fmt(statsData?.normalFlows)} classified normal`} icon={<ShieldEllipsis size={16} />} />
      </section>
      <section className="dashboard-grid">
        <div className="panel">
          <PanelTitle title="Flow activity" hint="Recent synthetic flow volume and suspicious classifications" action={<div className="chart-meta"><span><i className="legend-dot" />All flows</span><span><i className="legend-dot amber" />Flagged</span></div>} />
          {traffic.isLoading ? <div className="timeline-wrap"><div className="skeleton" style={{ height: 190 }} /></div> : traffic.isError ? <ErrorMessage onRetry={() => void traffic.refetch()} /> : timeline.length === 0 ? <div className="empty-state"><div className="empty-icon"><BarChart3 size={18} /></div><strong>No activity yet</strong><p>Generate a synthetic run to populate the timeline.</p></div> : <div className="timeline-wrap" data-testid="chart-flow-activity"><div className="timeline">{timeline.map((bucket, index) => <div className="bar-group" key={`${bucket.timestamp}-${index}`} title={`${bucket.flows} flows · ${bucket.suspicious} flagged`} data-testid={`bar-activity-${index}`}><div className="bar" style={{ height: `${Math.max(3, bucket.flows / maxFlows * 100)}%` }} /><div className="bar suspicious" style={{ height: `${Math.max(bucket.suspicious ? 3 : 0, bucket.suspicious / maxFlows * 100)}%` }} /></div>)}</div><div className="time-labels"><span>{shortTime(timeline[0]?.timestamp)}</span><span>{shortTime(timeline[Math.floor(timeline.length / 2)]?.timestamp)}</span><span>{shortTime(timeline[timeline.length - 1]?.timestamp)}</span></div></div>}
        </div>
        <div className="panel">
          <PanelTitle title="Classification mix" hint="Flow-level triage distribution" />
          <div className="mix-body"><div className="ring-layout"><div className="donut"><div className="donut-label">{allClassified ? `${normalPercent}%` : '—'}<small>NORMAL</small></div></div><div className="mix-legend"><div className="legend-row"><i className="legend-dot" />Normal<strong>{fmt(normal)}</strong></div><div className="legend-row"><i className="legend-dot amber" />Flagged<strong>{fmt(suspicious)}</strong></div><div className="legend-row"><i style={{ width: 7, height: 7, borderRadius: 20, background: '#dce8e5' }} />Unclassified<strong>{fmt(Math.max(0, (statsData?.totalFlows ?? 0) - allClassified))}</strong></div></div></div><div className="notice"><CircleHelp size={14} /><span>Risk and anomaly scores prioritize review. They are signals for triage, not proof of malicious activity.</span></div></div>
        </div>
      </section>
      <section className="action-grid">
        <div className="panel run-card">
          <div className="run-card-top"><div style={{ display: 'flex', gap: 12 }}><div className="run-mark"><Sparkles size={18} /></div><div><h2 className="run-title">Generate synthetic traffic</h2><p className="run-copy">Create safe, simulated flow records for detection practice. No packets are sent and no network is contacted.</p></div></div><span className="section-label">DATA ONLY</span></div>
          <div className="form-row">
            <div className="field"><label htmlFor="sim-mode">TRAFFIC PROFILE</label><select id="sim-mode" className="control" value={mode} onChange={(e) => { setMode(e.target.value as typeof mode); setScenario(''); }} data-testid="select-simulation-mode"><option value="normal">Normal baseline</option><option value="mixed">Mixed observations</option><option value="suspicious">Suspicious patterns</option></select></div>
            <div className="field"><label htmlFor="sim-count">RECORDS</label><select id="sim-count" className="control" value={count} onChange={(e) => setCount(e.target.value)} data-testid="select-simulation-count">{[12, 24, 48, 72, 100].map((n) => <option key={n} value={n}>{n} records</option>)}</select></div>
            <div className="field"><label htmlFor="sim-scenario">SCENARIO (OPTIONAL)</label><select id="sim-scenario" className="control" value={scenario} onChange={(e) => setScenario(e.target.value as NonNullable<SimulationInputScenario> | '')} data-testid="select-simulation-scenario"><option value="">Auto-select</option>{scenarioOptions.filter((option) => mode === 'normal' ? option.value.startsWith('NORMAL_') : mode === 'suspicious' ? !option.value.startsWith('NORMAL_') : true).map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></div>
            <button className="btn btn-primary" onClick={onGenerate} disabled={generate.isPending} data-testid="button-generate-flows">{generate.isPending ? <LoaderCircle size={15} className="spin" /> : <Plus size={15} />}{generate.isPending ? 'Generating' : 'Run simulation'}</button>
          </div>
          <div className="notice sim-footnote"><LockKeyhole size={13} /><span>Scenarios are synthetic statistical patterns, not real attack behavior.</span></div>
        </div>
        <div className="panel">
          <PanelTitle title="Latest alert signals" hint="Newest analyst triage items" action={<Link className="btn btn-secondary" href="/alerts" data-testid="link-view-alert-queue">View queue <ArrowRight size={13} /></Link>} />
          {alerts.isLoading ? <div className="recent-list">{[0, 1, 2].map((n) => <div className="skeleton skeleton-line" key={n} />)}</div> : alerts.isError ? <ErrorMessage onRetry={() => void alerts.refetch()} /> : !alerts.data?.length ? <div className="empty-state"><div className="empty-icon"><ShieldCheck size={18} /></div><strong>Queue is clear</strong><p>No alert records in the current view.</p></div> : <div className="recent-list">{alerts.data.slice(0, 5).map((alert) => <Link className="recent-row" href={`/alerts/${encodeURIComponent(alert.alertId)}`} key={alert.alertId} data-testid={`link-recent-alert-${alert.alertId}`}><div><span className="recent-name">{alert.alertType}</span><span className="recent-meta">{alert.sourceIp} → {alert.destinationIp} · {dateTime(alert.timestamp)}</span></div><div className="recent-right"><SeverityChip severity={alert.severity} /><div className="risk-number" style={{ marginTop: 6 }}>Risk {alert.riskScore}</div></div></Link>)}</div>}
        </div>
      </section>
      <div className="section-label" style={{ marginTop: 17 }}>Last dataset refresh · {dateTime(statsData?.generatedAt)}{statsData?.simulationRunning ? ' · simulation active' : ''}</div>
    </>}
  </>;
}

const scenarioOptions = [
  { value: 'NORMAL_WEB', label: 'Normal web browsing' },
  { value: 'NORMAL_DNS', label: 'Normal DNS lookups' },
  { value: 'NORMAL_SSH', label: 'Normal SSH administration' },
  { value: 'NORMAL_EMAIL', label: 'Normal email traffic' },
  { value: 'NORMAL_DATABASE', label: 'Normal database access' },
  { value: 'HIGH_CONNECTION_RATE', label: 'High connection rate pattern' },
  { value: 'REPEATED_FAILED_CONNECTIONS', label: 'Repeated failed connections' },
  { value: 'MULTI_PORT_PROBING_PATTERN', label: 'Multi-port probing pattern' },
  { value: 'SYN_HEAVY_PATTERN', label: 'SYN-heavy flow pattern' },
  { value: 'UNUSUAL_PORT_ACTIVITY', label: 'Unusual destination ports' },
  { value: 'HIGH_TRAFFIC_VOLUME', label: 'High traffic volume' },
];
function StatCard({ label, value, detail, icon, accent }: { label: string; value: string; detail: string; icon: React.ReactNode; accent?: string }) {
  return <div className="stat-card" data-testid={`metric-${label.toLowerCase().replaceAll(' ', '-')}`}><div className="stat-top"><span>{label}</span><span className="stat-icon" style={accent === 'amber' ? { color: '#bd8a33' } : undefined}>{icon}</span></div><div className="stat-value">{value}</div><div className="stat-foot">{detail}</div></div>;
}

function AlertsPage() {
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const args = { limit: 200, ...(severity ? { severity: severity as Severity } : {}), ...(status ? { status: status as Status } : {}) };
  const query = useGetAlerts(args, { query: { queryKey: getGetAlertsQueryKey(args), refetchInterval: 12000 } });
  const visible = useMemo(() => (query.data ?? []).filter((alert) => `${alert.alertId} ${alert.sourceIp} ${alert.destinationIp} ${alert.alertType} ${alert.ruleId} ${alert.description}`.toLowerCase().includes(search.toLowerCase())), [query.data, search]);
  const correlatedCounts = useMemo(() => getCorrelatedAlertCounts(query.data ?? []), [query.data]);
  const exportVisibleAsSiemJson = () => {
    const severityNumber: Record<Severity, number> = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
    const payload = {
      format: 'ecs-inspired-json',
      version: '1.0',
      exportedAt: new Date().toISOString(),
      dataSource: 'synthetic-training-simulation',
      events: visible.map((alert) => ({
        '@timestamp': alert.timestamp,
        event: {
          kind: 'alert',
          category: ['network'],
          type: ['info'],
          dataset: 'signal_desk.synthetic_ids',
          severity: severityNumber[alert.severity],
          risk_score: alert.riskScore,
        },
        rule: { id: alert.ruleId, name: alert.alertType },
        source: { ip: alert.sourceIp, port: alert.sourcePort },
        destination: { ip: alert.destinationIp, port: alert.destinationPort },
        network: { transport: alert.protocol.toLowerCase() },
        threat: { framework: 'MITRE ATT&CK', mapping_status: 'not_assigned' },
        labels: { synthetic: true, scenario: alert.scenarioType, triage_status: alert.status },
        message: alert.description,
      })),
    };
    const blobUrl = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = `signal-desk-alerts-${new Date().toISOString().replaceAll(':', '-')}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 0);
  };
  return <>
    <PageHeading eyebrow="Triage / queue" title="Alert queue" subtitle="Review explainable rule matches and record an analyst disposition.">
      <div className="section-label">{visible.length} RECORDS VISIBLE</div>
    </PageHeading>
    <div className="panel">
      <div className="toolbar">
        <div className="search-control"><Search size={15} /><input className="control" type="search" placeholder="Search IP, rule, alert type…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search alerts" data-testid="input-search-alerts" /></div>
        <select className="control" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filter by severity" data-testid="select-alert-severity"><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select>
        <select className="control" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status" data-testid="select-alert-status"><option value="">All statuses</option>{['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select>
        <button className="btn btn-secondary" onClick={() => void query.refetch()} data-testid="button-refresh-alerts"><RefreshCw size={13} />Refresh</button>
        <button className="btn btn-secondary" onClick={exportVisibleAsSiemJson} disabled={visible.length === 0} data-testid="button-export-json"><Download size={13} />Export JSON</button>
      </div>
      {correlatedCounts.size > 0 && <div className="notice" style={{ margin: '0 16px 14px' }} role="note" data-testid="notice-correlated-alerts"><CircleHelp size={14} /><span>{correlatedCounts.size} alert records are linked to another alert from the same source and rule within 60 seconds. Correlation helps prioritize review; each record still needs investigation.</span></div>}
      {query.isLoading ? <TableLoading /> : query.isError ? <ErrorMessage onRetry={() => void query.refetch()} /> : visible.length === 0 ? <div className="empty-state"><div className="empty-icon"><ListFilter size={18} /></div><strong>{search || severity || status ? 'No matching alerts' : 'No alerts to review'}</strong><p>{search || severity || status ? 'Adjust your search or filters to see more records.' : 'Generate a synthetic traffic run to create triage signals.'}</p></div> : <div className="table-wrap"><table className="data-table"><thead><tr><th>Alert / timestamp</th><th>Observation</th><th>Severity</th><th>Disposition</th><th>Risk signal</th><th>Scenario</th><th></th></tr></thead><tbody>{visible.map((alert) => <tr key={alert.alertId} data-testid={`row-alert-${alert.alertId}`}><td><Link href={`/alerts/${encodeURIComponent(alert.alertId)}`} title={alert.alertId} data-testid={`link-alert-${alert.alertId}`}>{alert.alertId.slice(0, 8)}</Link><div className="recent-meta" style={{ marginTop: 5 }}>{dateTime(alert.timestamp)}{correlatedCounts.has(alert.alertId) && <span style={{ color: '#257f73', marginLeft: 7 }}>· {correlatedCounts.get(alert.alertId)} related / 60s</span>}</div></td><td><strong style={{ color: '#38535c' }}>{alert.alertType}</strong><div className="recent-meta" style={{ marginTop: 5 }}>{alert.sourceIp}:{alert.sourcePort} → {alert.destinationIp}:{alert.destinationPort} · {alert.protocol}</div></td><td><SeverityChip severity={alert.severity} /></td><td><StatusChip status={alert.status} /></td><td><RiskValue score={alert.riskScore} /></td><td><span className="recent-meta">{titleCase(alert.scenarioType)}</span></td><td><Link className="btn btn-quiet" href={`/alerts/${encodeURIComponent(alert.alertId)}`} data-testid={`button-investigate-${alert.alertId}`}>Investigate <ArrowRight size={12} /></Link></td></tr>)}</tbody></table></div>}
    </div>
  </>;
}

function RiskValue({ score }: { score: number }) {
  return <span className="risk-number" data-testid={`text-risk-${score}`}>{score}<span style={{ color: '#98a8aa' }}>/100</span></span>;
}
function TableLoading() {
  return <div style={{ padding: '12px 18px' }} aria-label="Loading records">{[0, 1, 2, 3, 4].map((n) => <div className="skeleton skeleton-line" key={n} />)}</div>;
}

function AlertInvestigation() {
  const { alertId = '' } = useParams<{ alertId: string }>();
  const detail = useGetAlert(alertId, { query: { queryKey: getGetAlertQueryKey(alertId), refetchInterval: 12000 } });
  const addNote = useAddAlertNote();
  const updateStatus = useUpdateAlertStatus();
  const qc = useQueryClient();
  const [note, setNote] = useState('');
  const [resolutionNotes, setResolutionNotes] = useState('');
  const [notice, setNotice] = useState('');
  const [actionError, setActionError] = useState('');
  const data = detail.data;
  const alert = data?.alert;
  const flow = data?.flow;
  const refreshAlertViews = () => {
    void qc.invalidateQueries({ queryKey: getGetAlertQueryKey(alertId) });
    void qc.invalidateQueries({ queryKey: getGetAlertsQueryKey() });
    void qc.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
  };
  const submitNote = (event: React.FormEvent) => {
    event.preventDefault();
    if (!note.trim()) return;
    setActionError('');
    addNote.mutate({ alertId, data: { note: note.trim() } }, { onSuccess: () => { setNote(''); setNotice('Analyst note added.'); refreshAlertViews(); }, onError: () => setActionError('Note could not be saved. Try again.') });
  };
  const setDisposition = (next: Status) => {
    setActionError('');
    updateStatus.mutate({ alertId, data: { status: next, ...(resolutionNotes.trim() ? { resolutionNotes: resolutionNotes.trim() } : {}) } }, { onSuccess: () => { setNotice(`Disposition updated to ${titleCase(next)}.`); refreshAlertViews(); }, onError: () => setActionError('Disposition was not saved. Try again.') });
  };
  if (detail.isLoading) return <><PageHeading eyebrow="Triage / investigation" title="Loading investigation…" subtitle="Retrieving linked alert and flow evidence." /><div className="page-stack"><div className="skeleton" style={{ height: 180 }} /><div className="skeleton" style={{ height: 260 }} /></div></>;
  if (detail.isError || !alert || !flow) return <><PageHeading eyebrow="Triage / investigation" title="Investigation unavailable" subtitle="The alert record may have moved or could not be loaded." /><div className="panel"><ErrorMessage onRetry={() => void detail.refetch()} /></div><Link className="btn btn-secondary" href="/alerts" data-testid="link-back-to-alerts"><ArrowRight size={13} />Return to alert queue</Link></>;
  return <>
    <PageHeading eyebrow={`Triage / ${alert.alertId}`} title={alert.alertType} subtitle={`${alert.sourceIp}:${alert.sourcePort} → ${alert.destinationIp}:${alert.destinationPort} · ${dateTime(alert.timestamp)}`}>
      <Link className="btn btn-secondary" href="/alerts" data-testid="link-back-to-alerts"><ArrowRight size={13} />Back to queue</Link>
    </PageHeading>
    {(notice || actionError) && <div className="result-banner" role={actionError ? 'alert' : 'status'} data-testid={actionError ? 'status-investigation-error' : 'status-investigation-success'}><span>{actionError || notice}</span><button className="btn btn-quiet" onClick={() => { setNotice(''); setActionError(''); }} data-testid="button-dismiss-investigation-message"><X size={13} />Dismiss</button></div>}
    <div className="detail-grid">
      <div className="detail-primary">
        <section className="panel"><div className="panel-head"><div><div className="section-label">Alert context</div><h2 className="panel-title" style={{ marginTop: 5 }}>{alert.description}</h2></div><div style={{ display: 'flex', gap: 7 }}><SeverityChip severity={alert.severity} /><StatusChip status={alert.status} /></div></div>
          <div className="score-row"><ScoreMeter label="Risk score" score={alert.riskScore} /><ScoreMeter label="Anomaly score" score={alert.anomalyScore} /></div>
          <div style={{ padding: '0 20px 15px' }}><div className="notice"><CircleHelp size={14} /><span>These scores are prioritization signals generated from synthetic flow features. They do not establish malicious intent.</span></div></div>
        </section>
        <section className="panel"><PanelTitle title="Related flow record" hint={`Flow ${flow.flowId} · ${titleCase(flow.scenarioType)}`} action={<ClassChip classification={flow.classification} />} />
          <div style={{ padding: '18px 20px 3px' }}><div className="flow-route"><span className="flow-node">{flow.sourceIp}:{flow.sourcePort}</span><ArrowRight size={16} className="flow-arrow" /><span className="flow-node">{flow.destinationIp}:{flow.destinationPort}</span><span className="recent-meta">{flow.protocol}</span></div></div>
          <div className="flow-grid">{[
            ['Observed at', dateTime(flow.timestamp)], ['Packets', fmt(flow.packetCount)], ['Bytes', fmt(flow.byteCount)], ['Duration', `${flow.durationSeconds}s`], ['Connections', fmt(flow.connectionCount)], ['Failed connects', fmt(flow.failedConnectionCount)], ['SYN count', fmt(flow.synCount)], ['RST count', fmt(flow.rstCount)], ['Avg packet size', `${flow.averagePacketSize} B`],
          ].map(([label, value]) => <div className="flow-item" key={label} data-testid={`flow-field-${label.toLowerCase().replaceAll(' ', '-')}`}><small>{label}</small><strong>{value}</strong></div>)}</div>
          <div style={{ padding: '0 20px 17px', display: 'flex', gap: 7, flexWrap: 'wrap' }}>{flow.ruleIds.length ? flow.ruleIds.map((id) => <span className="rule-ref" key={id}>{id}</span>) : <span className="recent-meta">No rule IDs attached to this flow</span>}</div>
        </section>
        <section className="panel"><PanelTitle title="Detection explanation" hint={`Matched rule ${alert.ruleId}`} /><div className="explain-card"><p className="explain-lead">{alert.description}</p><div className="steps">{(data.investigationSteps.length ? data.investigationSteps : ['Review flow-level counts and connection outcomes.', 'Compare risk and anomaly scores with the matched rule.', 'Record an analyst disposition after checking the synthetic evidence.']).map((step, index) => <div className="step" key={`${step}-${index}`}><span className="step-number">{String(index + 1).padStart(2, '0')}</span><span>{step}</span></div>)}</div></div></section>
      </div>
      <aside className="detail-side">
        <section className="panel"><PanelTitle title="Analyst disposition" hint="Record a decision on this signal" /><div className="disposition">{(['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'] as Status[]).map((status) => <button key={status} className={`btn ${alert.status === status ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setDisposition(status)} disabled={updateStatus.isPending || alert.status === status} data-testid={`button-disposition-${status.toLowerCase()}`}>{alert.status === status ? <Check size={14} /> : <ArrowRight size={13} />}{titleCase(status)}</button>)}<div className="field" style={{ marginTop: 6 }}><label htmlFor="resolution-notes">DISPOSITION NOTE (OPTIONAL)</label><textarea id="resolution-notes" className="control" maxLength={2000} rows={3} value={resolutionNotes} onChange={(e) => setResolutionNotes(e.target.value)} placeholder="Briefly explain your decision…" data-testid="input-resolution-notes" /></div>{updateStatus.isPending && <span className="recent-meta">Saving disposition…</span>}</div></section>
        <section className="panel"><PanelTitle title="Analyst notes" hint={`${data.notes.length} notes on this investigation`} /><div className="notes-list">{data.notes.length ? data.notes.map((item) => <div className="note-item" key={item.noteId} data-testid={`note-${item.noteId}`}><p className="note-text">{item.note}</p><span className="note-time">{dateTime(item.createdAt)}</span></div>) : <div className="empty-state" style={{ padding: '24px 12px' }}><div className="empty-icon"><FileSearch size={17} /></div><strong>No analyst notes</strong><p>Add a concise observation below.</p></div>}</div><form className="note-form" onSubmit={submitNote}><label className="section-label" htmlFor="analyst-note">ADD OBSERVATION</label><textarea id="analyst-note" className="control" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} placeholder="What evidence supports your assessment?" data-testid="input-analyst-note" /><button className="btn btn-primary" type="submit" disabled={!note.trim() || addNote.isPending} data-testid="button-add-note">{addNote.isPending ? <LoaderCircle size={14} /> : <Plus size={14} />}{addNote.isPending ? 'Saving note' : 'Add note'}</button></form></section>
      </aside>
    </div>
  </>;
}

function ScoreMeter({ label, score }: { label: string; score: number }) {
  return <div className="score-box" data-testid={`score-${label.toLowerCase().replaceAll(' ', '-')}`}><div className="score-head"><span>{label}</span><strong>{score} / 100</strong></div><div className="score-track"><div className={`score-fill ${score >= 65 ? 'warn' : ''}`} style={{ width: `${Math.max(0, Math.min(100, score))}%` }} /></div></div>;
}

function FlowsPage() {
  const [classification, setClassification] = useState('');
  const [search, setSearch] = useState('');
  const params = { limit: 200, ...(classification ? { classification: classification as Flow['classification'] } : {}) };
  const query = useGetFlows(params);
  const visible = useMemo(() => (query.data ?? []).filter((flow) => `${flow.flowId} ${flow.sourceIp} ${flow.destinationIp} ${flow.protocol} ${flow.scenarioType} ${flow.ruleIds.join(' ')}`.toLowerCase().includes(search.toLowerCase())), [query.data, search]);
  return <>
    <PageHeading eyebrow="Observations / flow records" title="Synthetic flow records" subtitle="Inspect the aggregate network metadata used by detection rules. No packet payloads are collected.">
      <span className="section-label">{visible.length} RECORDS</span>
    </PageHeading>
    <div className="panel">
      <div className="toolbar"><div className="search-control"><Search size={15} /><input className="control" type="search" placeholder="Search flow ID, IP, protocol…" value={search} onChange={(e) => setSearch(e.target.value)} data-testid="input-search-flows" /></div><select className="control" value={classification} onChange={(e) => setClassification(e.target.value)} aria-label="Filter by classification" data-testid="select-flow-classification"><option value="">All classifications</option><option value="NORMAL">Normal</option><option value="SUSPICIOUS">Suspicious</option><option value="POTENTIAL_INTRUSION">Potential intrusion</option></select><button className="btn btn-secondary" onClick={() => void query.refetch()} data-testid="button-refresh-flows"><RefreshCw size={13} />Refresh</button></div>
      {query.isLoading ? <TableLoading /> : query.isError ? <ErrorMessage onRetry={() => void query.refetch()} /> : visible.length === 0 ? <div className="empty-state"><div className="empty-icon"><Database size={18} /></div><strong>{search || classification ? 'No matching flow records' : 'No synthetic flows yet'}</strong><p>Run a simulation from the overview to create records for review.</p><Link className="btn btn-quiet" href="/" data-testid="link-generate-from-flows">Go to simulation <ArrowRight size={13} /></Link></div> : <div className="table-wrap"><table className="data-table"><thead><tr><th>Flow / timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Volume</th><th>Classification</th><th>Risk / anomaly</th><th>Scenario</th></tr></thead><tbody>{visible.map((flow) => <tr key={flow.flowId} data-testid={`row-flow-${flow.flowId}`}><td><strong className="mono" style={{ color: '#32806f' }}>{flow.flowId}</strong><div className="recent-meta" style={{ marginTop: 5 }}>{dateTime(flow.timestamp)}</div></td><td className="mono">{flow.sourceIp}:{flow.sourcePort}</td><td className="mono">{flow.destinationIp}:{flow.destinationPort}</td><td>{flow.protocol}</td><td><span className="mono">{fmt(flow.packetCount)} pkts</span><div className="recent-meta" style={{ marginTop: 5 }}>{fmt(flow.byteCount)} bytes</div></td><td><ClassChip classification={flow.classification} /></td><td><div className="mono">R {flow.riskScore} · A {flow.anomalyScore}</div></td><td>{titleCase(flow.scenarioType)}</td></tr>)}</tbody></table></div>}
    </div>
    <div className="notice" style={{ marginTop: 14 }}><ShieldCheck size={14} /><span>Flow records contain aggregate counters only. “Potential intrusion” and risk labels are automated triage classifications, not verified conclusions.</span></div>
  </>;
}

function RulesPage() {
  const query = useGetRules();
  const update = useUpdateRule();
  const qc = useQueryClient();
  const [thresholdValues, setThresholdValues] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState('');
  const [failure, setFailure] = useState('');
  const commitUpdate = (rule: DetectionRule, change: { enabled?: boolean; threshold?: number }) => {
    setFailure('');
    update.mutate({ ruleId: rule.ruleId, data: change }, {
      onSuccess: () => { setSaved(`${rule.ruleId} updated`); void qc.invalidateQueries({ queryKey: getGetRulesQueryKey() }); },
      onError: () => setFailure(`${rule.ruleId} could not be updated. Please retry.`),
    });
  };
  return <>
    <PageHeading eyebrow="Detection / configuration" title="Detection rules" subtitle="Tune thresholds and enable or pause explainable pattern matching. Changes affect future synthetic analysis.">
      <button className="btn btn-secondary" onClick={() => void query.refetch()} data-testid="button-refresh-rules"><RefreshCw size={13} />Refresh</button>
    </PageHeading>
    {saved && <div className="result-banner" role="status" data-testid="status-rule-success"><span><Check size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />{saved}. Detection configuration is current.</span><button className="btn btn-quiet" onClick={() => setSaved('')} data-testid="button-dismiss-rule-success"><X size={13} />Dismiss</button></div>}
    {failure && <div className="result-banner" role="alert" style={{ background: '#fbefed', color: '#975248' }} data-testid="status-rule-error"><span>{failure}</span><button className="btn btn-secondary" onClick={() => setFailure('')} data-testid="button-dismiss-rule-error"><X size={13} />Dismiss</button></div>}
    {query.isLoading ? <div className="rules-list">{[0, 1, 2, 3].map((n) => <div className="skeleton" style={{ height: 112 }} key={n} />)}</div> : query.isError ? <div className="panel"><ErrorMessage onRetry={() => void query.refetch()} /></div> : !query.data?.length ? <div className="panel empty-state"><div className="empty-icon"><GitBranch size={18} /></div><strong>No detection rules found</strong><p>Rule configuration is not available right now.</p></div> : <div className="rules-list">{query.data.map((rule, index) => <RuleCard key={rule.ruleId} rule={rule} index={index} thresholdValue={thresholdValues[rule.ruleId] ?? String(rule.threshold)} pending={update.isPending} onThresholdChange={(value) => setThresholdValues((current) => ({ ...current, [rule.ruleId]: value }))} onThresholdCommit={() => { const parsed = Number(thresholdValues[rule.ruleId] ?? rule.threshold); if (Number.isFinite(parsed) && parsed >= 0 && parsed !== rule.threshold) commitUpdate(rule, { threshold: parsed }); else setThresholdValues((current) => ({ ...current, [rule.ruleId]: String(rule.threshold) })); }} onToggle={() => commitUpdate(rule, { enabled: !rule.enabled })} />)}</div>}
    <div className="notice" style={{ marginTop: 16 }}><CircleHelp size={14} /><span>Threshold direction and interpretation are defined by each rule. Lower or higher values may change sensitivity. Scores and matches remain triage signals.</span></div>
  </>;
}
function RuleCard({ rule, index, thresholdValue, pending, onThresholdChange, onThresholdCommit, onToggle }: { rule: DetectionRule; index: number; thresholdValue: string; pending: boolean; onThresholdChange: (value: string) => void; onThresholdCommit: () => void; onToggle: () => void }) {
  return <article className="panel rule-card" data-testid={`card-rule-${rule.ruleId}`}><div className="rule-main"><div className="rule-index">{String(index + 1).padStart(2, '0')}</div><div><h2 className="rule-name">{rule.name}</h2><p className="rule-description">{rule.description}</p><div className="rule-meta"><span className="mono" style={{ color: '#829599', fontSize: 10 }}>{rule.ruleId}</span><SeverityChip severity={rule.severity} /><span className="recent-meta">Threshold: {rule.thresholdLabel}</span></div></div></div><div className="rule-controls"><div className="threshold-control"><label htmlFor={`threshold-${rule.ruleId}`}>Value</label><input id={`threshold-${rule.ruleId}`} className="control" type="number" min="0" step="1" value={thresholdValue} onChange={(e) => onThresholdChange(e.target.value)} onBlur={onThresholdCommit} onKeyDown={(e) => { if (e.key === 'Enter') { (e.target as HTMLInputElement).blur(); } }} aria-label={`${rule.name} threshold`} data-testid={`input-rule-threshold-${rule.ruleId}`} /></div><button type="button" role="switch" aria-checked={rule.enabled} aria-label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.name}`} className={`switch ${rule.enabled ? 'on' : ''}`} onClick={onToggle} disabled={pending} data-testid={`switch-rule-${rule.ruleId}`}><span /></button><span className="recent-meta">{rule.enabled ? 'ON' : 'OFF'}</span></div></article>;
}

function NotFound() {
  return <div className="panel empty-state" style={{ padding: 60 }}><div className="empty-icon"><FileSearch size={19} /></div><strong>Page not found</strong><p>This workspace route does not exist.</p><Link className="btn btn-primary" href="/" style={{ marginTop: 16 }} data-testid="link-return-overview">Return to overview <ArrowRight size={13} /></Link></div>;
}

function Router() {
  const [location] = useLocation();
  return <AppShell><Switch>
    <Route path="/" component={Overview} />
    <Route path="/alerts/:alertId" component={AlertInvestigation} />
    <Route path="/alerts" component={AlertsPage} />
    <Route path="/flows" component={FlowsPage} />
    <Route path="/rules" component={RulesPage} />
    <Route component={NotFound} />
  </Switch></AppShell>;
}

function App() {
  return <QueryClientProvider client={queryClient}><TooltipProvider><Router /><Toaster /></TooltipProvider></QueryClientProvider>;
}

export default App;