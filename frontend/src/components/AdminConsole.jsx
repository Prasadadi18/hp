import React, { useState, useEffect, useCallback } from 'react';

export default function AdminConsole({
  active,
  refreshTrigger,
  onShowToast,
  adminToken,
  setAdminToken,
  adminUser,
  setAdminUser,
}) {
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [loginError, setLoginError] = useState('');
  const [authenticating, setAuthenticating] = useState(false);

  // States for admin data
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [loadingForensics, setLoadingForensics] = useState(false);
  const [adminNotes, setAdminNotes] = useState('');
  const [actioningAlert, setActioningAlert] = useState(false);

  const [adminStats, setAdminStats] = useState({
    pending_count: 0,
    critical_pending: 0,
    total_approved: 0,
    total_rejected: 0,
    total_alerts: 0,
  });
  const [registrations, setRegistrations] = useState([]);
  const [auditLog, setAuditLog] = useState([]);

  // Custom modals state variables
  const [pendingApproveReg, setPendingApproveReg] = useState(null);
  const [tempPasswordInput, setTempPasswordInput] = useState('');
  const [pendingRejectReg, setPendingRejectReg] = useState(null);
  const [pipelineResetStep, setPipelineResetStep] = useState(0); // 0 = closed, 1 = first warning, 2 = second warning
  const [resetConfirmToken, setResetConfirmToken] = useState('');
  const [resetLoading, setResetLoading] = useState(false);


  // Filter states
  const [statusFilter, setStatusFilter] = useState('pending');
  const [severityFilter, setSeverityFilter] = useState('');

  const handleLogout = useCallback(() => {
    console.log('[ADMIN] Logging out and clearing credentials');
    setAdminToken(null);
    setAdminUser('admin');
    sessionStorage.removeItem('admin_jwt');
    sessionStorage.removeItem('admin_user');
    setSelectedAlert(null);
    setSelectedAlertId(null);
  }, [setAdminToken, setAdminUser, setSelectedAlert, setSelectedAlertId]);

  // Auth Headers helper
  const getAuthHeaders = useCallback(() => {
    return adminToken
      ? { 'Authorization': `Bearer ${adminToken}`, 'Content-Type': 'application/json' }
      : { 'Content-Type': 'application/json' };
  }, [adminToken]);

  // Admin fetch wrapper
  const adminFetch = useCallback(async (url, options = {}) => {
    const headers = {
      ...(options.headers || {}),
      ...getAuthHeaders(),
    };
    console.log(`[ADMIN] fetch: ${options.method || 'GET'} ${url}`, options.body || '');
    try {
      const res = await fetch(url, { ...options, headers });
      console.log(`[ADMIN] fetch response: ${url} status=${res.status}`);
      if (res.status === 401) {
        console.warn('[ADMIN] Unauthorized request (401), logging out...');
        handleLogout();
        return null;
      }
      return res;
    } catch (e) {
      console.error(`[ADMIN] Fetch error for ${url}:`, e);
      throw e;
    }
  }, [getAuthHeaders, handleLogout]);

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    if (!usernameInput.trim() || !passwordInput) {
      setLoginError('Please enter both username and password.');
      return;
    }
    setAuthenticating(true);
    setLoginError('');

    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usernameInput.trim(), password: passwordInput }),
      });

      if (res.status === 401) {
        setLoginError('Invalid credentials.');
      } else if (res.status === 403) {
        const data = await res.json();
        setLoginError(data.detail || 'Security department role required.');
      } else if (!res.ok) {
        setLoginError('Authentication failed. Please try again.');
      } else {
        const data = await res.json();
        const token = data.token;
        const user = data.username || usernameInput.trim();
        setAdminToken(token);
        setAdminUser(user);
        sessionStorage.setItem('admin_jwt', token);
        sessionStorage.setItem('admin_user', user);
        // Inform parent about login to trigger WS connection
        if (window.dispatchEvent) {
          window.dispatchEvent(new CustomEvent('admin-login-success', { detail: { token, user } }));
        }
      }
    } catch (err) {
      setLoginError('Network error. Please try again later.');
    } finally {
      setAuthenticating(false);
    }
  };

  // Data Loading functions
  const loadAlerts = useCallback(async () => {
    if (!adminToken) return;
    try {
      let url = '/api/admin/alerts?limit=100';
      if (statusFilter) url += `&status=${statusFilter}`;
      if (severityFilter) url += `&severity=${severityFilter}`;

      const res = await adminFetch(url);
      if (!res || !res.ok) return;
      const data = await res.json();
      setAlerts(data.alerts || []);
    } catch (e) {
      console.warn('[ADMIN] Could not load alerts');
    }
  }, [adminToken, statusFilter, severityFilter, adminFetch]);

  const loadAdminStats = useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await adminFetch('/api/admin/stats');
      if (!res || !res.ok) return;
      const data = await res.json();
      setAdminStats(data);
    } catch (e) {
      console.warn('[ADMIN] Could not load stats');
    }
  }, [adminToken, adminFetch]);

  const loadAuditLog = useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await adminFetch('/api/admin/audit-log?limit=50');
      if (!res || !res.ok) return;
      const data = await res.json();
      setAuditLog(data.entries || []);
    } catch (e) {
      console.warn('[ADMIN] Could not load audit log');
    }
  }, [adminToken, adminFetch]);

  const loadRegistrations = useCallback(async () => {
    if (!adminToken) return;
    try {
      const res = await adminFetch('/api/admin/registrations');
      if (!res || !res.ok) return;
      const data = await res.json();
      setRegistrations(data.registrations || []);
    } catch (e) {
      console.warn('[ADMIN] Could not load registrations');
    }
  }, [adminToken, adminFetch]);

  const selectAlert = useCallback(async (alertId) => {
    setSelectedAlertId(alertId);
    setLoadingForensics(true);
    try {
      const res = await adminFetch(`/api/admin/alerts/${alertId}`);
      if (!res || !res.ok) throw new Error('Failed to load alert details');
      const data = await res.json();
      setSelectedAlert(data);
    } catch (err) {
      console.error(err);
      setSelectedAlert(null);
    } finally {
      setLoadingForensics(false);
    }
  }, [adminFetch]);

  // Alert Action handlers
  const handleApproveAlert = async (alertId) => {
    setActioningAlert(true);
    console.log(`[ADMIN] Approving alert ${alertId}`);
    try {
      const res = await adminFetch(`/api/admin/alerts/${alertId}/approve`, {
        method: 'POST',
        body: JSON.stringify({ admin_notes: adminNotes }),
      });
      if (!res) {
        console.warn('[ADMIN] Approve alert request returned empty response');
        return;
      }
      const data = await res.json();
      console.log('[ADMIN] Approve alert result:', data);

      if (data.success) {
        const rotatedUser = data.rotation_result?.user_rotation?.user_id || selectedAlert?.user_id || 'user';
        onShowToast('✅ Rotation Approved', `Credentials rotated for ${rotatedUser}`);
        setAdminNotes('');
      } else {
        onShowToast('⚠ Error', data.message || 'Approval failed');
      }
      // Reload
      loadAlerts();
      loadAdminStats();
      loadAuditLog();
      selectAlert(alertId);
    } catch (err) {
      console.error('[ADMIN] Error approving alert:', err);
      onShowToast('❌ Error', 'Network error during approval');
    } finally {
      setActioningAlert(false);
    }
  };

  const handleRejectAlert = async (alertId) => {
    setActioningAlert(true);
    console.log(`[ADMIN] Rejecting alert ${alertId}`);
    try {
      const res = await adminFetch(`/api/admin/alerts/${alertId}/reject`, {
        method: 'POST',
        body: JSON.stringify({ admin_notes: adminNotes }),
      });
      if (!res) {
        console.warn('[ADMIN] Reject alert request returned empty response');
        return;
      }
      const data = await res.json();
      console.log('[ADMIN] Reject alert result:', data);

      if (data.success) {
        onShowToast('❌ Alert Rejected', 'Marked as false positive');
        setAdminNotes('');
      } else {
        onShowToast('⚠ Error', data.message || 'Rejection failed');
      }
      // Reload
      loadAlerts();
      loadAdminStats();
      loadAuditLog();
      selectAlert(alertId);
    } catch (err) {
      console.error('[ADMIN] Error rejecting alert:', err);
      onShowToast('❌ Error', 'Network error during rejection');
    } finally {
      setActioningAlert(false);
    }
  };

  // Access requests actions
  const handleApproveReg = (username) => {
    setPendingApproveReg(username);
    setTempPasswordInput(`HPE-${Math.floor(100000 + Math.random() * 900000)}`);
  };

  const executeApproveReg = async () => {
    if (!tempPasswordInput) return;
    const username = pendingApproveReg;
    setPendingApproveReg(null);
    try {
      const res = await adminFetch(`/api/admin/registrations/${username}/approve`, {
        method: 'POST',
        body: JSON.stringify({ password: tempPasswordInput }),
      });
      if (!res) return;
      const data = await res.json();
      if (data.success) {
        onShowToast('✅ User Approved', `${username} is now active with the provided credentials.`);
        loadRegistrations();
        loadAuditLog();
      } else {
        onShowToast('❌ Error', data.message || 'Failed to approve registration');
      }
    } catch (e) {
      onShowToast('❌ Error', 'Failed to approve registration');
    }
  };

  const handleRejectReg = (username) => {
    setPendingRejectReg(username);
  };

  const executeRejectReg = async () => {
    const username = pendingRejectReg;
    setPendingRejectReg(null);
    try {
      const res = await adminFetch(`/api/admin/registrations/${username}/reject`, {
        method: 'POST',
      });
      if (!res) return;
      const data = await res.json();
      if (data.success) {
        onShowToast('🗑️ User Rejected', `Registration for ${username} deleted.`);
        loadRegistrations();
        loadAuditLog();
      } else {
        onShowToast('❌ Error', data.message || 'Failed to reject registration');
      }
    } catch (e) {
      onShowToast('❌ Error', 'Failed to reject registration');
    }
  };

  // Danger Zone Wipes
  const handlePipelineReset = () => {
    setPipelineResetStep(1);
  };

  const executeResetRequest = async () => {
    setResetLoading(true);
    console.log('[ADMIN] Initiating pipeline reset request...');
    try {
      const res = await adminFetch('/api/admin/reset/request', { method: 'POST' });
      if (!res || !res.ok) {
        onShowToast('❌ Reset Failed', 'Could not request a reset token.');
        setPipelineResetStep(0);
        return;
      }
      const data = await res.json();
      const token = data.confirm_token;
      console.log('[ADMIN] Reset token received:', token);
      setResetConfirmToken(token);
      setPipelineResetStep(2);
    } catch (err) {
      console.error('[ADMIN] Error requesting reset token:', err);
      onShowToast('❌ Reset Error', 'An error occurred during reset token request.');
      setPipelineResetStep(0);
    } finally {
      setResetLoading(false);
    }
  };

  const executeResetConfirm = async () => {
    setResetLoading(true);
    console.log('[ADMIN] Executing pipeline reset confirmation...');
    try {
      const confirmRes = await adminFetch('/api/admin/reset/confirm', {
        method: 'POST',
        body: JSON.stringify({ confirm_token: resetConfirmToken }),
      });
      if (confirmRes && confirmRes.ok) {
        const confirmData = await confirmRes.json();
        console.log('[ADMIN] Reset confirmation result:', confirmData);
        if (confirmData.success) {
          onShowToast('🔥 Pipeline Reset Complete', 'All data wiped successfully.');
          loadAlerts();
          loadAdminStats();
          loadAuditLog();
          loadRegistrations();
          setSelectedAlert(null);
          setSelectedAlertId(null);
        } else {
          onShowToast('❌ Reset Failed', confirmData.message || 'Reset failed.');
        }
      } else {
        const errData = confirmRes ? await confirmRes.json() : {};
        onShowToast('❌ Reset Failed', errData.detail || 'Confirmation failed or expired.');
      }
    } catch (err) {
      console.error('[ADMIN] Error during pipeline reset confirmation:', err);
      onShowToast('❌ Reset Error', 'An error occurred during reset confirmation.');
    } finally {
      setResetLoading(false);
      setPipelineResetStep(0);
    }
  };


  // Effects
  useEffect(() => {
    if (active && adminToken) {
      loadAlerts();
      loadAdminStats();
      loadAuditLog();
      loadRegistrations();
    }
  }, [active, adminToken, statusFilter, severityFilter, refreshTrigger, loadAlerts, loadAdminStats, loadAuditLog, loadRegistrations]);

  // Periodic polling when tab is active and logged in
  useEffect(() => {
    if (!active || !adminToken) return;

    const timerStatsAlerts = setInterval(() => {
      loadAlerts();
      loadAdminStats();
    }, 5000);

    const timerAuditReg = setInterval(() => {
      loadAuditLog();
      loadRegistrations();
    }, 10000);

    return () => {
      clearInterval(timerStatsAlerts);
      clearInterval(timerAuditReg);
    };
  }, [active, adminToken, loadAlerts, loadAdminStats, loadAuditLog, loadRegistrations]);

  if (!active) return null;

  // Login View
  if (!adminToken) {
    return (
      <section className="section active" id="admin-section">
        <div className="admin-login-overlay">
          <form className="admin-login-card" onSubmit={handleLogin}>
            <div className="admin-login-icon">🔒</div>
            <h3>Admin Authentication Required</h3>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>
              Enter Security department credentials to access the admin console.
            </p>
            <input
              type="text"
              placeholder="Username"
              style={{ width: '100%', boxSizing: 'border-box' }}
              value={usernameInput}
              onChange={e => setUsernameInput(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              style={{ width: '100%', boxSizing: 'border-box' }}
              value={passwordInput}
              onChange={e => setPasswordInput(e.target.value)}
            />
            <button type="submit" disabled={authenticating}>
              {authenticating ? 'Authenticating...' : 'Authenticate'}
            </button>
            {loginError && <div className="admin-login-error">{loginError}</div>}
          </form>
        </div>
      </section>
    );
  }

  // Helper to render individual alert cards
  const renderAlertCard = (alert, selectedAlertId, selectAlert) => {
    const isCritical = alert.threat_action === 'CRITICAL_ALERT';
    const isBlock = alert.threat_action === 'BLOCK';
    const severityClass = isCritical ? 'severity-critical' : isBlock ? 'severity-high' : 'severity-medium';
    const statusClass = alert.status === 'pending' ? 'status-pending'
      : alert.status === 'approved' ? 'status-approved' : 'status-rejected';
    const isSelected = alert.alert_id === selectedAlertId;

    const scorePercent = ((alert.threat_score || 0) * 100).toFixed(1);
    const timeStr = alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : '--';

    const src = alert.event_data?.event_source || 'replayed_dataset';
    const isLive = src !== 'replayed_dataset';
    const sourceBadgeHtml = isLive
      ? <span className="badge-live" style={{ marginLeft: '8px', background: 'rgba(0,255,180,0.15)', color: '#00ffb4', border: '1px solid #00ffb4', borderRadius: '4px', padding: '1px 6px', fontSize: '10px', fontWeight: 700 }}>🌐 LIVE PORTAL</span>
      : <span className="badge-replayed" style={{ marginLeft: '8px', background: 'rgba(100,160,255,0.12)', color: '#64a0ff', border: '1px solid #64a0ff', borderRadius: '4px', padding: '1px 6px', fontSize: '10px', fontWeight: 700 }}>📊 REPLAYED</span>;

    return (
      <div
        key={alert.alert_id}
        className={`admin-alert-card ${severityClass} ${statusClass} ${isSelected ? 'selected' : ''}`}
        onClick={() => selectAlert(alert.alert_id)}
      >
        <div className="admin-alert-card-header">
          <span className={`admin-severity-badge ${severityClass}`}>
            {isCritical ? '🔴 CRITICAL' : isBlock ? '🟠 BLOCK' : '🟡 MONITOR'}
          </span>
          {sourceBadgeHtml}
          <span className={`admin-alert-status ${statusClass}`}>
            {alert.status.toUpperCase()}
          </span>
        </div>
        <div className="admin-alert-card-body">
          <div className="admin-alert-user">{alert.user_id || 'unknown'}</div>
          <div className="admin-alert-meta">
            <span>Score: <strong>{scorePercent}%</strong></span>
            <span>IP: {alert.event_data?.source_ip || '--'}</span>
            <span>{timeStr}</span>
          </div>
          <div className="admin-alert-type">{alert.event_data?.anomaly_type || 'Unknown'}</div>
        </div>
        <div className="admin-alert-id">{alert.alert_id}</div>
      </div>
    );
  };

  // Filter alerts locally by status and severity
  const filteredAlerts = alerts.filter(a => {
    if (statusFilter && a.status !== statusFilter) return false;
    if (severityFilter) {
      const isCritical = a.threat_action === 'CRITICAL_ALERT';
      const isBlock = a.threat_action === 'BLOCK';
      const severity = isCritical ? 'critical' : isBlock ? 'high' : 'medium';
      if (severity !== severityFilter) return false;
    }
    return true;
  });

  const livePortalAlerts = filteredAlerts.filter(a => (a.event_data?.event_source || 'replayed_dataset') !== 'replayed_dataset');
  const replayedAlerts = filteredAlerts.filter(a => (a.event_data?.event_source || 'replayed_dataset') === 'replayed_dataset');

  return (
    <section className="section active" id="admin-section">
      {/* Admin Console Header with Logout */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignSelf: 'stretch', alignItems: 'center', marginBottom: '24px', paddingBottom: '12px', borderBottom: '1px solid var(--panel-border)' }}>
        <div style={{ color: 'var(--text-muted)', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
          Logged in as: <strong style={{ color: 'var(--cyan)' }}>{adminUser}</strong>
        </div>
        <button
          className="admin-btn-action reject"
          style={{
            background: 'rgba(255,255,255,0.05)',
            border: '1px solid var(--panel-border)',
            color: 'var(--text-primary)',
            padding: '6px 16px',
            cursor: 'pointer',
            fontSize: '12px',
          }}
          onClick={handleLogout}
        >
          Sign Out
        </button>
      </div>

      {/* Admin Stats Row */}
      <div className="admin-stats-row">
        <div className={`admin-stat-card critical-glow ${adminStats.pending_count > 0 ? 'has-pending' : ''}`}>
          <div className="admin-stat-icon">🚨</div>
          <div className="admin-stat-value">{adminStats.pending_count || 0}</div>
          <div className="admin-stat-label">Pending Alerts</div>
        </div>
        <div className="admin-stat-card">
          <div className="admin-stat-icon">⚡</div>
          <div className="admin-stat-value">{adminStats.critical_pending || 0}</div>
          <div className="admin-stat-label">Critical Pending</div>
        </div>
        <div className="admin-stat-card">
          <div className="admin-stat-icon">✅</div>
          <div className="admin-stat-value">{adminStats.total_approved || 0}</div>
          <div className="admin-stat-label">Approved</div>
        </div>
        <div className="admin-stat-card">
          <div className="admin-stat-icon">❌</div>
          <div className="admin-stat-value">{adminStats.total_rejected || 0}</div>
          <div className="admin-stat-label">Rejected</div>
        </div>
        <div className="admin-stat-card">
          <div className="admin-stat-icon">📊</div>
          <div className="admin-stat-value">{adminStats.total_alerts || 0}</div>
          <div className="admin-stat-label">Total Alerts</div>
        </div>
      </div>

      {/* Main Admin Layout: Alert Queue + Detail */}
      <div className="admin-main-layout" style={{ width: '100%' }}>
        {/* Left: Alert Queue */}
        <div className="admin-alert-queue">
          <div className="admin-panel-header">
            <span className="admin-panel-title">🔔 Alert Queue</span>
            <div className="admin-filter-row">
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="admin-filter-select"
              >
                <option value="">All Status</option>
                <option value="pending">Pending</option>
                <option value="approved">Approved</option>
                <option value="rejected">Rejected</option>
              </select>
              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="admin-filter-select"
              >
                <option value="">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
              </select>
            </div>
          </div>
          <div className="admin-alert-list">
            {/* ── Live Portal Alerts Section ── */}
            <div style={{
              padding: '10px 14px',
              background: 'linear-gradient(90deg, rgba(0,255,180,0.08) 0%, rgba(0,0,0,0) 100%)',
              borderBottom: '2px solid rgba(0,255,180,0.35)',
              borderLeft: '3px solid #00ffb4',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '12px',
              color: '#00ffb4',
              fontWeight: 'bold',
              textTransform: 'uppercase',
              letterSpacing: '1px',
            }}>
              🌐 Live Portal Alerts
              <span style={{ marginLeft: 'auto', background: 'rgba(0,255,180,0.15)', border: '1px solid #00ffb4', borderRadius: '10px', padding: '1px 8px', fontSize: '11px' }}>
                {livePortalAlerts.length}
              </span>
            </div>
            {livePortalAlerts.length === 0 ? (
              <div className="admin-empty" style={{ padding: '16px', fontSize: '13px', color: 'rgba(0,255,180,0.5)', borderLeft: '3px solid rgba(0,255,180,0.15)' }}>
                No live portal alerts — trigger a login or VPN simulation to see events here
              </div>
            ) : (
              livePortalAlerts.map(alert => renderAlertCard(alert, selectedAlertId, selectAlert))
            )}

            {/* ── Replayed Dataset Alerts Section ── */}
            <div style={{
              padding: '10px 14px',
              marginTop: '12px',
              background: 'linear-gradient(90deg, rgba(100,160,255,0.08) 0%, rgba(0,0,0,0) 100%)',
              borderBottom: '2px solid rgba(100,160,255,0.35)',
              borderLeft: '3px solid #64a0ff',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '12px',
              color: '#64a0ff',
              fontWeight: 'bold',
              textTransform: 'uppercase',
              letterSpacing: '1px',
            }}>
              📊 Replayed Dataset Alerts
              <span style={{ marginLeft: 'auto', background: 'rgba(100,160,255,0.15)', border: '1px solid #64a0ff', borderRadius: '10px', padding: '1px 8px', fontSize: '11px' }}>
                {replayedAlerts.length}
              </span>
            </div>
            {replayedAlerts.length === 0 ? (
              <div className="admin-empty" style={{ padding: '16px', fontSize: '13px', color: 'rgba(100,160,255,0.5)', borderLeft: '3px solid rgba(100,160,255,0.15)' }}>
                No replayed dataset alerts match filters
              </div>
            ) : (
              replayedAlerts.map(alert => renderAlertCard(alert, selectedAlertId, selectAlert))
            )}
          </div>
        </div>

        {/* Right: Alert Detail / Forensics */}
        <div className="admin-alert-detail">
          {loadingForensics ? (
            <div className="admin-loading">Loading forensic data...</div>
          ) : selectedAlert ? (
            <div className="admin-detail-content">
              {/* Alert Header */}
              <div className={`admin-detail-header ${selectedAlert.threat_action === 'CRITICAL_ALERT' ? 'critical' : 'high'}`}>
                <div className="admin-detail-severity">
                  {selectedAlert.threat_action === 'CRITICAL_ALERT' ? '🔴 CRITICAL ALERT' : '🟠 HIGH SEVERITY ALERT'}
                </div>
                <div className="admin-detail-id">{selectedAlert.alert_id}</div>
              </div>

              {/* Threat Score Section */}
              <div className="admin-score-section">
                <div className="admin-score-main">
                  <div className="admin-score-label">Threat Score</div>
                  <div className={`admin-score-value ${selectedAlert.threat_action === 'CRITICAL_ALERT' ? 'critical' : 'high'}`}>
                    {((selectedAlert.threat_score || 0) * 100).toFixed(1)}%
                  </div>
                  <div className="admin-score-bar">
                    <div
                      className="admin-score-fill"
                      style={{
                        width: `${(selectedAlert.threat_score || 0) * 100}%`,
                        background: selectedAlert.threat_action === 'CRITICAL_ALERT' ? 'var(--magenta)' : 'var(--amber)',
                      }}
                    />
                  </div>
                </div>
                <div className="admin-model-scores">
                  <div className="admin-model-score">
                    <span className="admin-model-label">XGBoost</span>
                    <span className="admin-model-value">{(selectedAlert.xgb_score || 0).toFixed(4)}</span>
                  </div>
                  <div className="admin-model-score">
                    <span className="admin-model-label">LightGBM</span>
                    <span className="admin-model-value">{(selectedAlert.lgb_score || 0).toFixed(4)}</span>
                  </div>
                  <div className="admin-model-score">
                    <span className="admin-model-label">Ensemble</span>
                    <span className="admin-model-value">{(selectedAlert.ensemble_score || 0).toFixed(4)}</span>
                  </div>
                  <div className="admin-model-score">
                    <span className="admin-model-label">Threshold</span>
                    <span className="admin-model-value" style={{ color: 'var(--amber)' }}>
                      {(selectedAlert.threshold || 0).toFixed(4)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Event Facts */}
              <div className="admin-facts-section">
                <div className="admin-section-label">📋 Event Facts</div>
                <div className="admin-facts-grid">
                  <div className="admin-fact">
                    <span className="admin-fact-key">User</span>
                    <span className="admin-fact-val">{selectedAlert.event_data?.user || '--'}</span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Source IP</span>
                    <span className="admin-fact-val">{selectedAlert.event_data?.source_ip || '--'}</span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Region</span>
                    <span className="admin-fact-val">{selectedAlert.event_data?.ip_region || '--'}</span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Action</span>
                    <span className="admin-fact-val">{selectedAlert.event_data?.action || '--'}</span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Anomaly Type</span>
                    <span className="admin-fact-val admin-anomaly-type">
                      {selectedAlert.event_data?.anomaly_type || 'None'}
                    </span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Geo Mismatch</span>
                    <span className={`admin-fact-val ${selectedAlert.event_data?.geo_mismatch ? 'danger' : ''}`}>
                      {selectedAlert.event_data?.geo_mismatch ? '⚠ YES' : 'No'}
                    </span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Impossible Travel</span>
                    <span className={`admin-fact-val ${selectedAlert.event_data?.impossible_travel ? 'danger' : ''}`}>
                      {selectedAlert.event_data?.impossible_travel ? '⚠ YES' : 'No'}
                    </span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Login Hour</span>
                    <span className="admin-fact-val">{selectedAlert.event_data?.login_hour ?? '--'}</span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Failed Attempts (15m)</span>
                    <span className={`admin-fact-val ${(selectedAlert.event_data?.failed_attempts_last_15m || 0) >= 5 ? 'danger' : ''}`}>
                      {selectedAlert.event_data?.failed_attempts_last_15m ?? 0}
                    </span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Data Downloaded</span>
                    <span className="admin-fact-val">
                      {(selectedAlert.event_data?.data_downloaded_mb || 0).toFixed(1)} MB
                    </span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Pipeline Latency</span>
                    <span className="admin-fact-val">
                      {(selectedAlert.total_latency_ms || 0).toFixed(1)}ms
                    </span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Created</span>
                    <span className="admin-fact-val">
                      {selectedAlert.created_at ? new Date(selectedAlert.created_at).toLocaleString() : '--'}
                    </span>
                  </div>
                  <div className="admin-fact">
                    <span className="admin-fact-key">Event Source</span>
                    <span className={`admin-fact-val badge-${(selectedAlert.event_data?.event_source || 'replayed_dataset') === 'live_portal' ? 'live' : 'replayed'}`}>
                      {(selectedAlert.event_data?.event_source || 'replayed_dataset') === 'live_portal' ? '🌐 Live Portal' : '📊 Replayed Dataset'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Threat Trigger Reasons */}
              <div className="admin-facts-section">
                <div className="admin-section-label">⚠️ Threat Trigger Reasons</div>
                {selectedAlert.event_data?.threat_reasons && selectedAlert.event_data.threat_reasons.length > 0 ? (
                  <ul className="admin-reasons-list">
                    {selectedAlert.event_data.threat_reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '8px', fontFamily: 'var(--font-mono)', paddingLeft: '8px' }}>
                    No explicit anomalous factors detected (ensemble probability model match)
                  </div>
                )}
              </div>

              {/* Geo Info */}
              <div className="admin-facts-section">
                <div className="admin-section-label">🌐 Geographic Data</div>
                <div className="admin-geo-row">
                  <div className="admin-geo-card">
                    <div className="admin-geo-label">Source</div>
                    <div className="admin-geo-city">{selectedAlert.source_geo?.city || 'Unknown'}</div>
                    <div className="admin-geo-coords">
                      {selectedAlert.source_geo?.lat?.toFixed(2) || 0}°, {selectedAlert.source_geo?.lng?.toFixed(2) || 0}°
                    </div>
                  </div>
                  <div className="admin-geo-arrow">→</div>
                  <div className="admin-geo-card">
                    <div className="admin-geo-label">Destination</div>
                    <div className="admin-geo-city">{selectedAlert.destination_geo?.city || 'Unknown'}</div>
                    <div className="admin-geo-coords">
                      {selectedAlert.destination_geo?.lat?.toFixed(2) || 0}°, {selectedAlert.destination_geo?.lng?.toFixed(2) || 0}°
                    </div>
                  </div>
                </div>
              </div>

              {/* Pipeline Stages */}
              <div className="admin-facts-section">
                <div className="admin-section-label">⚡ Pipeline Stages</div>
                <div className="admin-stages-table-wrapper">
                  <table className="admin-stages-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Stage</th>
                        <th>Status</th>
                        <th>Latency</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(selectedAlert.pipeline_stages || []).map((s, i) => (
                        <tr key={i}>
                          <td style={{ color: 'var(--text-muted)' }}>{s.stage_number || i + 1}</td>
                          <td>{s.stage_name || '--'}</td>
                          <td>
                            <span className={`admin-stage-status ${s.status === 'pending_approval' ? 'pending' : ''}`}>
                              {s.status || '--'}
                            </span>
                          </td>
                          <td style={{ color: 'var(--amber)' }}>{(s.latency_ms || 0).toFixed(1)}ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Rotation Result */}
              {selectedAlert.rotation_result?.user_rotation && (
                <div className="admin-facts-section">
                  <div className="admin-section-label">🔐 Vault Rotation Result</div>
                  <div className="admin-rotation-result">
                    <div className="admin-fact">
                      <span className="admin-fact-key">Success</span>
                      <span className={`admin-fact-val ${selectedAlert.rotation_result.user_rotation.success ? 'success' : 'danger'}`}>
                        {selectedAlert.rotation_result.user_rotation.success ? '✅ YES' : '❌ FAILED'}
                      </span>
                    </div>
                    <div className="admin-fact">
                      <span className="admin-fact-key">Rotation #</span>
                      <span className="admin-fact-val">{selectedAlert.rotation_result.user_rotation.rotation_number || '--'}</span>
                    </div>
                    <div className="admin-fact">
                      <span className="admin-fact-key">Rotation ID</span>
                      <span className="admin-fact-val" style={{ fontSize: '10px' }}>
                        {selectedAlert.rotation_result.user_rotation.rotation_id || '--'}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {selectedAlert.admin_notes && (
                <div className="admin-facts-section">
                  <div className="admin-section-label">📝 Admin Notes</div>
                  <div className="admin-notes-text">{selectedAlert.admin_notes}</div>
                </div>
              )}

              {/* Action Buttons */}
              {selectedAlert.status === 'pending' ? (
                <div className="admin-action-section">
                  <textarea
                    className="admin-notes-input"
                    placeholder="Add notes (optional)..."
                    rows="2"
                    value={adminNotes}
                    onChange={e => setAdminNotes(e.target.value)}
                  />
                  <div className="admin-action-buttons">
                    <button
                      className="admin-btn admin-btn-approve"
                      disabled={actioningAlert}
                      onClick={() => handleApproveAlert(selectedAlert.alert_id)}
                    >
                      {actioningAlert ? '⏳ Rotating credentials...' : '✅ Approve Credential Rotation'}
                    </button>
                    <button
                      className="admin-btn admin-btn-reject"
                      disabled={actioningAlert}
                      onClick={() => handleRejectAlert(selectedAlert.alert_id)}
                    >
                      ❌ Reject (False Positive)
                    </button>
                  </div>
                </div>
              ) : (
                <div className={`admin-resolved-banner ${selectedAlert.status}`}>
                  {selectedAlert.status === 'approved' ? '✅ APPROVED' : '❌ REJECTED'} —{' '}
                  {selectedAlert.resolved_at ? new Date(selectedAlert.resolved_at).toLocaleString() : ''}
                </div>
              )}
            </div>
          ) : (
            <div className="admin-detail-placeholder">
              <div className="admin-detail-placeholder-icon">🔍</div>
              <div className="admin-detail-placeholder-text">Select an alert to view forensic details</div>
            </div>
          )}
        </div>
      </div>

      {/* Pending Access Requests */}
      <div className="admin-audit-section" style={{ width: '100%' }}>
        <div className="admin-panel-header">
          <span className="admin-panel-title">👤 Pending Access Requests</span>
          <span className="admin-audit-count">{registrations.length} requests</span>
        </div>
        <div className="admin-audit-table-wrapper">
          <table className="admin-audit-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Department</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {registrations.length === 0 ? (
                <tr>
                  <td colSpan="4" className="admin-empty">No pending registrations</td>
                </tr>
              ) : (
                registrations.map(reg => {
                  const vpnBadgeHtml = reg.is_vpn && (
                    <span className="badge-vpn-warn" style={{ marginLeft: '8px' }}>
                      ⚠️ VPN IP Endpoint
                    </span>
                  );
                  return (
                    <tr key={reg.username}>
                      <td><strong>{reg.username}</strong></td>
                      <td>{reg.department || '--'}{vpnBadgeHtml}</td>
                      <td><span className="admin-stage-status pending">PENDING</span></td>
                      <td>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            className="admin-btn-action approve"
                            onClick={() => handleApproveReg(reg.username)}
                          >
                            Approve
                          </button>
                          <button
                            className="admin-btn-action reject"
                            onClick={() => handleRejectReg(reg.username)}
                          >
                            Reject
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Log */}
      <div className="admin-audit-section" style={{ width: '100%' }}>
        <div className="admin-panel-header">
          <span className="admin-panel-title">📋 Admin Audit Log</span>
          <span className="admin-audit-count">{auditLog.length} entries</span>
        </div>
        <div className="admin-audit-table-wrapper">
          <table className="admin-audit-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Alert ID</th>
                <th>User</th>
                <th>Score</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {auditLog.length === 0 ? (
                <tr>
                  <td colSpan="6" className="admin-empty">No admin actions yet</td>
                </tr>
              ) : (
                auditLog.map((entry, idx) => {
                  const time = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '--';
                  const actionClass = entry.action === 'approve' ? 'action-approve' : 'action-reject';
                  return (
                    <tr key={idx}>
                      <td>{time}</td>
                      <td>
                        <span className={`admin-action-badge ${actionClass}`}>
                          {entry.action?.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{entry.alert_id || '--'}</td>
                      <td>{entry.user_id || '--'}</td>
                      <td style={{ color: 'var(--magenta)' }}>{((entry.threat_score || 0) * 100).toFixed(1)}%</td>
                      <td style={{ color: 'var(--text-muted)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {entry.admin_notes || '--'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="admin-audit-section danger-zone-section" style={{ width: '100%', border: '1px solid var(--magenta)', marginTop: '32px', background: 'rgba(214, 48, 49, 0.05)', padding: '24px' }}>
        <div className="admin-panel-header" style={{ borderBottom: '1px solid rgba(214, 48, 49, 0.2)', paddingBottom: '12px', marginBottom: '16px' }}>
          <span className="admin-panel-title" style={{ color: 'var(--magenta)', fontWeight: 'bold' }}>⚠️ Danger Zone</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h4 style={{ margin: '0 0 8px 0', color: 'var(--text-primary)' }}>Reset Pipeline State</h4>
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '13px' }}>
              Wipe all Postgres database records, Kafka topics, and Elasticsearch indices to start fresh.
            </p>
          </div>
          <button
            className="admin-btn-action reject"
            style={{
              background: 'var(--magenta)',
              color: '#fff',
              padding: '12px 24px',
              fontWeight: 'bold',
              border: 'none',
              cursor: 'pointer',
            }}
            onClick={handlePipelineReset}
          >
            Reset Pipeline
          </button>
        </div>
      </div>

      {/* Custom Approval Modal */}
      {pendingApproveReg && (
        <div className="stage-modal" style={{ zIndex: 11000 }}>
          <div className="stage-modal-content" style={{ border: '2px solid var(--lime)' }}>
            <button className="stage-modal-close" onClick={() => setPendingApproveReg(null)}>×</button>
            <div className="stage-modal-header" style={{ color: 'var(--lime)' }}>👤 Approve User Registration</div>
            <div className="stage-modal-body">
              <p style={{ marginBottom: '16px', color: 'var(--text-primary)' }}>
                Please specify a temporary password to issue for <strong style={{ color: 'var(--cyan)' }}>{pendingApproveReg}</strong>:
              </p>
              <input
                type="text"
                style={{
                  width: '100%',
                  padding: '10px',
                  boxSizing: 'border-box',
                  background: 'rgba(0,0,0,0.2)',
                  border: '1px solid var(--panel-border)',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-mono)',
                  marginBottom: '20px',
                  fontSize: '14px'
                }}
                value={tempPasswordInput}
                onChange={e => setTempPasswordInput(e.target.value)}
              />
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                <button
                  className="admin-btn-action"
                  style={{
                    background: 'rgba(255,255,255,0.05)',
                    border: '1px solid var(--panel-border)',
                    color: 'var(--text-primary)',
                    padding: '8px 16px',
                    cursor: 'pointer'
                  }}
                  onClick={() => setPendingApproveReg(null)}
                >
                  Cancel
                </button>
                <button
                  className="admin-btn-action approve"
                  style={{ padding: '8px 16px', cursor: 'pointer' }}
                  onClick={executeApproveReg}
                >
                  Confirm Approve
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Custom Rejection Modal */}
      {pendingRejectReg && (
        <div className="stage-modal" style={{ zIndex: 11000 }}>
          <div className="stage-modal-content" style={{ border: '2px solid var(--magenta)' }}>
            <button className="stage-modal-close" onClick={() => setPendingRejectReg(null)}>×</button>
            <div className="stage-modal-header" style={{ color: 'var(--magenta)' }}>⚠️ Reject Registration</div>
            <div className="stage-modal-body">
              <p style={{ marginBottom: '20px', color: 'var(--text-primary)', lineHeight: '1.6' }}>
                Are you sure you want to reject and delete the registration request for <strong style={{ color: 'var(--cyan)' }}>{pendingRejectReg}</strong>? This action cannot be undone.
              </p>
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                <button
                  className="admin-btn-action"
                  style={{
                    background: 'rgba(255,255,255,0.05)',
                    border: '1px solid var(--panel-border)',
                    color: 'var(--text-primary)',
                    padding: '8px 16px',
                    cursor: 'pointer'
                  }}
                  onClick={() => setPendingRejectReg(null)}
                >
                  Cancel
                </button>
                <button
                  className="admin-btn-action reject"
                  style={{ padding: '8px 16px', cursor: 'pointer', background: 'var(--magenta)', color: '#fff' }}
                  onClick={executeRejectReg}
                >
                  Reject User
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Custom Pipeline Reset Modal */}
      {pipelineResetStep > 0 && (
        <div className="stage-modal" style={{ zIndex: 11000 }}>
          <div className="stage-modal-content" style={{ border: '2px solid var(--magenta)' }}>
            <button className="stage-modal-close" onClick={() => setPipelineResetStep(0)}>×</button>
            <div className="stage-modal-header" style={{ color: 'var(--magenta)' }}>
              {pipelineResetStep === 1 ? '⚠️ Pipeline Reset Warning' : '☢️ Critical Confirmation'}
            </div>
            <div className="stage-modal-body">
              {pipelineResetStep === 1 ? (
                <>
                  <p style={{ marginBottom: '20px', color: 'var(--text-primary)', lineHeight: '1.6' }}>
                    This will wipe all PostgreSQL database records, active infra leases, and Elasticsearch indices to start fresh.
                  </p>
                  <p style={{ marginBottom: '20px', color: 'var(--amber)', fontWeight: 'bold', lineHeight: '1.6' }}>
                    Audit logs and Kafka topics will be preserved. Are you sure you want to proceed?
                  </p>
                  <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                    <button
                      className="admin-btn-action"
                      style={{
                        background: 'rgba(255,255,255,0.05)',
                        border: '1px solid var(--panel-border)',
                        color: 'var(--text-primary)',
                        padding: '8px 16px',
                        cursor: 'pointer'
                      }}
                      onClick={() => setPipelineResetStep(0)}
                    >
                      Cancel
                    </button>
                    <button
                      className="admin-btn-action reject"
                      disabled={resetLoading}
                      style={{ padding: '8px 16px', cursor: 'pointer', background: 'var(--magenta)', color: '#fff' }}
                      onClick={executeResetRequest}
                    >
                      {resetLoading ? '⏳ Requesting...' : 'Request Reset Token'}
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <p style={{ marginBottom: '20px', color: 'var(--text-primary)', lineHeight: '1.6' }}>
                    A one-time reset confirmation token has been successfully issued by Vault (Expires in 60s).
                  </p>
                  <p style={{ marginBottom: '20px', color: 'var(--magenta)', fontWeight: 'bold', lineHeight: '1.6' }}>
                    Click CONFIRM RESET to wipe the pipeline state now, or Cancel to abort.
                  </p>
                  <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                    <button
                      className="admin-btn-action"
                      style={{
                        background: 'rgba(255,255,255,0.05)',
                        border: '1px solid var(--panel-border)',
                        color: 'var(--text-primary)',
                        padding: '8px 16px',
                        cursor: 'pointer'
                      }}
                      onClick={() => setPipelineResetStep(0)}
                    >
                      Cancel
                    </button>
                    <button
                      className="admin-btn-action reject"
                      disabled={resetLoading}
                      style={{ padding: '8px 16px', cursor: 'pointer', background: 'var(--magenta)', color: '#fff' }}
                      onClick={executeResetConfirm}
                    >
                      {resetLoading ? '⚡ Executing reset...' : 'Confirm Reset'}
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
