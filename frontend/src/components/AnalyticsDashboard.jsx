import React, { useEffect, useState, useRef } from 'react';

export default function AnalyticsDashboard({
  active,
  totalProcessed,
  threatsIntercepted,
  allowedProcessed,
  blockedProcessed,
  avgLatency,
  attackTypes,
  latestModelScores,
  onRedirectToAdmin,
}) {
  const [health, setHealth] = useState({ kafka: false, es: false, vault: false, model: false });
  const [vaultCreds, setVaultCreds] = useState({ db_password: '****', api_key: '****', service_token: '****', rotations: 0, reason: 'none' });
  const [kafkaStats, setKafkaStats] = useState({ brokers: '—', topics: '—', totalMsgs: '—', lag: '—', partitions: [] });
  const [esStats, setEsStats] = useState({ audit: '—', threats: '—', breakdown: [] });
  const [vaultUsers, setVaultUsers] = useState([]);
  const [vaultUserCountText, setVaultUserCountText] = useState('');
  
  // Table filters
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const prevRotations = useRef(0);
  const [highlightVault, setHighlightVault] = useState(false);

  // Poll Health, Credentials, and Stats
  useEffect(() => {
    if (!active) return;

    const fetchHealth = async () => {
      try {
        const res = await fetch('/api/health');
        if (!res.ok) throw new Error();
        const data = await res.json();
        setHealth({
          kafka: data.kafka_connected,
          es: data.elasticsearch_connected,
          vault: data.vault_connected,
          model: data.model_loaded,
        });
      } catch (e) {
        setHealth({ kafka: false, es: false, vault: false, model: false });
      }
    };

    const fetchVaultCreds = async () => {
      try {
        const res = await fetch('/api/vault/credentials');
        if (!res.ok) return;
        const data = await res.json();
        if (data.error) return;
        setVaultCreds({
          db_password: data.db_password,
          api_key: data.api_key,
          service_token: data.service_token,
          rotations: data.rotation_count || 0,
          reason: data.rotation_reason || 'none',
        });

        const newCount = data.rotation_count || 0;
        if (newCount > prevRotations.current) {
          setHighlightVault(true);
          setTimeout(() => setHighlightVault(false), 1500);
          prevRotations.current = newCount;
        }
      } catch (e) {}
    };

    const fetchKafkaStats = async () => {
      try {
        const res = await fetch('/api/kafka/stats');
        if (!res.ok) return;
        const data = await res.json();
        if (data.error) {
          setKafkaStats({ brokers: '—', topics: '—', totalMsgs: '—', lag: '—', partitions: [] });
          return;
        }

        const lagEntries = Object.values(data.consumer_lag || {});
        const totalLag = lagEntries.reduce((sum, l) => sum + (l.lag || 0), 0);

        setKafkaStats({
          brokers: data.broker_count || 0,
          topics: Object.keys(data.topics || {}).length,
          totalMsgs: (data.total_messages_in_topics || 0).toLocaleString(),
          lag: totalLag,
          partitions: lagEntries,
        });
      } catch (e) {}
    };

    const fetchEsStats = async () => {
      try {
        const res = await fetch('/api/elasticsearch/stats');
        if (!res.ok) return;
        const data = await res.json();
        const docs = data.index_doc_counts || {};
        const breakdown = Object.entries(data.threat_breakdown || {}).sort((a, b) => b[1] - a[1]);

        setEsStats({
          audit: (docs['hpe-audit-logs'] || 0).toLocaleString(),
          threats: (docs['hpe-threats'] || 0).toLocaleString(),
          breakdown: breakdown,
        });
      } catch (e) {}
    };

    const fetchVaultUsers = async () => {
      try {
        const res = await fetch('/api/vault/users');
        if (!res.ok) throw new Error();
        const data = await res.json();
        setVaultUsers(data.users || []);
        setVaultUserCountText(`${data.total_users} users · ${data.global_rotation_count} total rotations`);
      } catch (e) {
        setVaultUsers([]);
      }
    };

    fetchHealth();
    fetchVaultCreds();
    fetchKafkaStats();
    fetchEsStats();
    fetchVaultUsers();

    const healthTimer = setInterval(fetchHealth, 10000);
    const vaultCredsTimer = setInterval(fetchVaultCreds, 5000);
    const kafkaTimer = setInterval(fetchKafkaStats, 8000);
    const esTimer = setInterval(fetchEsStats, 10000);
    const usersTimer = setInterval(fetchVaultUsers, 15000);

    return () => {
      clearInterval(healthTimer);
      clearInterval(vaultCredsTimer);
      clearInterval(kafkaTimer);
      clearInterval(esTimer);
      clearInterval(usersTimer);
    };
  }, [active]);

  if (!active) return null;

  // Local filtering logic for users table
  const filteredUsers = vaultUsers.filter(u => {
    const q = search.toLowerCase();
    const matchesSearch = !search || (u.user_id || '').toLowerCase().includes(q);
    const matchesRole = !roleFilter || u.role === roleFilter;
    const matchesStatus = !statusFilter || u.status === statusFilter;
    return matchesSearch && matchesRole && matchesStatus;
  });

  const detectionRate = totalProcessed > 0
    ? ((allowedProcessed / totalProcessed) * 100).toFixed(1)
    : '100';

  const lagClass = kafkaStats.lag > 50 ? 'magenta' : kafkaStats.lag > 10 ? 'amber' : 'lime';

  return (
    <section className="section active" id="dashboard-section">
      <div className="section-title">Threat Intelligence</div>
      <h2 className="section-heading">Real-Time Analytics Dashboard</h2>

      {/* Metrics Cards */}
      <div className="dashboard-grid">
        <div className="metric-card">
          <div className="metric-label">Total Processed</div>
          <div className="metric-value cyan">{totalProcessed.toLocaleString()}</div>
          <div className="metric-change">Events through pipeline</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Threats Detected</div>
          <div className="metric-value magenta">{threatsIntercepted.toLocaleString()}</div>
          <div className="metric-change">Anomalies identified by AI</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Allowed</div>
          <div className="metric-value lime">{allowedProcessed.toLocaleString()}</div>
          <div className="metric-change">Safe connections passed</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Blocked / Critical</div>
          <div className="metric-value magenta">{blockedProcessed.toLocaleString()}</div>
          <div className="metric-change">Threats neutralized</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Avg Latency</div>
          <div className="metric-value amber">{avgLatency.toFixed(1)}ms</div>
          <div className="metric-change">Pipeline processing time</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Detection Rate</div>
          <div className="metric-value lime">{detectionRate}%</div>
          <div className="metric-change">Model accuracy (F1)</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 'var(--space-lg)', flexWrap: 'wrap', marginTop: 'var(--space-2xl)' }}>
        {/* Left Column: Models & Health */}
        <div style={{ flex: '1 1 500px', display: 'flex', flexDirection: 'column', gap: 'var(--space-lg)' }}>
          {/* Model Performance */}
          <div>
            <div className="section-title">Model Performance</div>
            <div className="model-perf-grid">
              <div className="perf-card">
                <div className="perf-card-title">XGBoost Prob</div>
                <div className="perf-card-value">{latestModelScores.xgb !== null ? latestModelScores.xgb.toFixed(4) : '--'}</div>
              </div>
              <div className="perf-card">
                <div className="perf-card-title">LightGBM Prob</div>
                <div className="perf-card-value">{latestModelScores.lgb !== null ? latestModelScores.lgb.toFixed(4) : '--'}</div>
              </div>
              <div className="perf-card">
                <div className="perf-card-title">Ensemble Score</div>
                <div className="perf-card-value">{latestModelScores.ensemble !== null ? latestModelScores.ensemble.toFixed(4) : '--'}</div>
              </div>
              <div className="perf-card">
                <div className="perf-card-title">Threshold</div>
                <div className="perf-card-value" style={{ color: 'var(--amber)' }}>
                  {latestModelScores.threshold !== null ? latestModelScores.threshold.toFixed(4) : '--'}
                </div>
              </div>
            </div>
          </div>

          {/* Vault Dynamic secrets */}
          <div>
            <div className="section-title">HashiCorp Vault Credentials</div>
            <div
              className="metric-card"
              style={{
                borderColor: highlightVault ? 'var(--red-stark)' : 'var(--panel-border)',
                boxShadow: highlightVault ? '4px 4px 0px var(--red-stark)' : '4px 4px 0px rgba(0, 0, 0, 0.95)',
                transition: 'all 0.3s ease',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--space-md)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>DB_PASSWORD</div>
                <div style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>{vaultCreds.db_password}</div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--space-md)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>API_KEY</div>
                <div style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>{vaultCreds.api_key}</div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--space-md)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>SERVICE_TOKEN</div>
                <div style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>{vaultCreds.service_token}</div>
              </div>
              <div style={{ borderTop: '2px solid var(--panel-border)', marginTop: 'var(--space-md)', paddingTop: 'var(--space-md)', display: 'flex', justifyContent: 'space-between' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                  Rotations: <span style={{ color: 'var(--red-stark)', fontWeight: 600 }}>{vaultCreds.rotations}</span>
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                  Last Reason: <span style={{ color: 'var(--amber)' }}>{vaultCreds.reason}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Attack Breakdown & Health */}
        <div style={{ flex: '1 1 400px', display: 'flex', flexDirection: 'column', gap: 'var(--space-lg)' }}>
          {/* Attack Breakdown */}
          <div>
            <div className="section-title">Attack Type Breakdown</div>
            <div id="attack-breakdown" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-sm)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
              {Object.keys(attackTypes).length === 0 ? (
                <div style={{ color: 'var(--text-muted)', gridColumn: 'span 2' }}>No anomalies recorded</div>
              ) : (
                Object.entries(attackTypes)
                  .sort((a, b) => b[1] - a[1])
                  .map(([type, count]) => (
                    <div key={type} style={{ display: 'flex', justifyContent: 'space-between', background: 'rgba(0,0,0,0.2)', padding: '4px 8px', border: '1px solid var(--panel-border)' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>{type}</span>
                      <span style={{ color: 'var(--red-stark)', fontWeight: 600 }}>{count}</span>
                    </div>
                  ))
              )}
            </div>
          </div>

          {/* Infrastructure Health */}
          <div>
            <div className="section-title">Infrastructure Health</div>
            <div className="pipeline-health-grid">
              <div className="health-item">
                <div className={`status-dot ${health.kafka ? '' : 'danger'}`} />
                <span>Kafka</span>
              </div>
              <div className="health-item">
                <div className={`status-dot ${health.es ? '' : 'danger'}`} />
                <span>Elasticsearch</span>
              </div>
              <div className="health-item">
                <div className={`status-dot ${health.vault ? '' : 'danger'}`} />
                <span>Vault</span>
              </div>
              <div className="health-item">
                <div className={`status-dot ${health.model ? '' : 'danger'}`} />
                <span>AI Model</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Kafka & Elasticsearch Stats */}
      <div style={{ display: 'flex', gap: 'var(--space-lg)', flexWrap: 'wrap', marginTop: 'var(--space-2xl)' }}>
        {/* Kafka Stats */}
        <div style={{ flex: '1 1 400px' }}>
          <div className="section-title">Apache Kafka — Live Stats</div>
          <div className="infra-stats-card">
            <div className="infra-stats-grid">
              <div className="infra-stat">
                <span className="infra-stat-label">Brokers</span>
                <span className="infra-stat-value">{kafkaStats.brokers}</span>
              </div>
              <div className="infra-stat">
                <span className="infra-stat-label">Topics</span>
                <span className="infra-stat-value">{kafkaStats.topics}</span>
              </div>
              <div className="infra-stat">
                <span className="infra-stat-label">Total Messages</span>
                <span className="infra-stat-value cyan">{kafkaStats.totalMsgs}</span>
              </div>
              <div className="infra-stat">
                <span className="infra-stat-label">Consumer Lag</span>
                <span className={`infra-stat-value ${lagClass}`}>{kafkaStats.lag.toLocaleString()}</span>
              </div>
            </div>
            {kafkaStats.partitions.length > 0 ? (
              <div style={{ marginTop: 'var(--space-md)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                {kafkaStats.partitions.map((l, i) => (
                  <div className="kafka-partition-row" key={i}>
                    <span style={{ color: 'var(--text-muted)' }}>{l.topic}[{l.partition}]</span>
                    <span style={{ color: 'var(--cyan)' }}>offset: {l.committed_offset}</span>
                    <span style={{ color: 'var(--amber)' }}>latest: {l.latest_offset}</span>
                    <span className={l.lag > 10 ? 'lag-warning' : 'lag-ok'}>lag: {l.lag}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ marginTop: 'var(--space-md)', color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                No active partitions
              </div>
            )}
          </div>
        </div>

        {/* ES Stats */}
        <div style={{ flex: '1 1 400px' }}>
          <div className="section-title">Elasticsearch — Index Stats</div>
          <div className="infra-stats-card">
            <div className="infra-stats-grid">
              <div className="infra-stat">
                <span className="infra-stat-label">Audit Logs</span>
                <span className="infra-stat-value lime">{esStats.audit}</span>
              </div>
              <div className="infra-stat">
                <span className="infra-stat-label">Threats Indexed</span>
                <span className="infra-stat-value magenta">{esStats.threats}</span>
              </div>
            </div>
            {esStats.breakdown.length > 0 && (
              <div style={{ marginTop: 'var(--space-md)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                <div style={{ color: 'var(--text-muted)', marginBottom: '4px' }}>Threat Actions:</div>
                {esStats.breakdown.map(([action, count]) => (
                  <div style={{ display: 'flex', justifyContent: 'space-between', padding: '2px 0' }} key={action}>
                    <span style={{ color: 'var(--text-secondary)' }}>{action}</span>
                    <span style={{ color: 'var(--red-stark)', fontWeight: 600 }}>{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Vault Users Table */}
      <div style={{ marginTop: 'var(--space-2xl)' }}>
        <div className="section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>🔐 HashiCorp Vault — 200 User Credentials</span>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 400 }}>{vaultUserCountText}</span>
        </div>
        <div className="vault-table-controls">
          <input
            type="text"
            placeholder="Search user ID..."
            className="vault-search-input"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <select className="vault-filter-select" value={roleFilter} onChange={e => setRoleFilter(e.target.value)}>
            <option value="">All Roles</option>
            <option value="Admin">Admin</option>
            <option value="Developer">Developer</option>
            <option value="Finance">Finance</option>
            <option value="HR">HR</option>
            <option value="Sales">Sales</option>
          </select>
          <select className="vault-filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="rotated">Rotated</option>
          </select>
        </div>
        <div className="vault-table-wrapper">
          <table className="vault-table">
            <thead>
              <tr>
                <th>User ID</th>
                <th>Role</th>
                <th>Region</th>
                <th>DB Password</th>
                <th>API Key</th>
                <th>Rotations</th>
                <th>Status</th>
                <th>Last Reason</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan="8" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                    No users match filters or Vault disconnected
                  </td>
                </tr>
              ) : (
                filteredUsers.map(u => (
                  <tr className={`vault-row ${u.status === 'rotated' ? 'row-rotated' : ''}`} key={u.user_id}>
                    <td className="user-id-cell">{u.user_id}</td>
                    <td><span className={`role-badge role-${(u.role || '').toLowerCase()}`}>{u.role}</span></td>
                    <td>{u.home_region || '—'}</td>
                    <td className="mono-cell">{u.db_password || '****'}</td>
                    <td className="mono-cell">{u.api_key || '****'}</td>
                    <td style={{ textAlign: 'center' }}>{u.rotation_count || 0}</td>
                    <td>
                      <span className={u.status === 'rotated' ? 'status-rotated' : 'status-active'}>
                        {u.status === 'rotated' ? '🔄 ROTATED' : '✅ ACTIVE'}
                      </span>
                    </td>
                    <td className="reason-cell" title={u.last_rotation_reason || ''}>
                      {u.last_rotation_reason || '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <footer className="section-footer">
        HPE — AI-Powered Network Threat Detection Pipeline — Cyber Command Center
      </footer>
    </section>
  );
}
