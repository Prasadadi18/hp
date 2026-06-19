import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header.jsx';
import StarField from './components/StarField.jsx';
import ThreatGlobe from './components/ThreatGlobe.jsx';
import PipelineFlow from './components/PipelineFlow.jsx';
import AnalyticsDashboard from './components/AnalyticsDashboard.jsx';
import AdminConsole from './components/AdminConsole.jsx';
import IframeSection from './components/IframeSection.jsx';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export default function App() {
  const [activeTab, setActiveTab] = useState('globe-section');
  const [connected, setConnected] = useState(false);
  const [adminToken, setAdminToken] = useState(sessionStorage.getItem('admin_jwt') || null);
  const [adminUser, setAdminUser] = useState(sessionStorage.getItem('admin_user') || 'admin');

  // Globe HUD / Counters
  const [eventsProcessed, setEventsProcessed] = useState(0);
  const [threatsIntercepted, setThreatsIntercepted] = useState(0);
  const [arcs, setArcs] = useState([]);

  // Dashboard Stats
  const [totalProcessed, setTotalProcessed] = useState(0);
  const [allowedProcessed, setAllowedProcessed] = useState(0);
  const [blockedProcessed, setBlockedProcessed] = useState(0);
  const [avgLatency, setAvgLatency] = useState(0);
  const [attackTypes, setAttackTypes] = useState({});
  const [latestModelScores, setLatestModelScores] = useState({
    xgb: null,
    lgb: null,
    ensemble: null,
    threshold: 0.5455,
  });

  // Refs to avoid stale closures in processing loop
  const totalProcessedRef = useRef(0);
  const threatsInterceptedRef = useRef(0);
  const allowedProcessedRef = useRef(0);
  const blockedProcessedRef = useRef(0);
  const latencySumRef = useRef(0);
  const attackTypesRef = useRef({});

  // Pipeline Animation States
  const [activeStage, setActiveStage] = useState(-1);
  const [activeConnector, setActiveConnector] = useState(-1);
  const [isThreatFlow, setIsThreatFlow] = useState(false);
  const [stageLatencies, setStageLatencies] = useState(Array(10).fill(0));
  const [vaultActive, setVaultActive] = useState(false);
  const [vaultLines, setVaultLines] = useState([]);
  const [eventsLog, setEventsLog] = useState([]);

  // Banners, Alerts, Toasts
  const [vpnAlerts, setVpnAlerts] = useState([]);
  const [toast, setToast] = useState(null);
  const [resultBanner, setResultBanner] = useState(null);
  const [adminRefreshTrigger, setAdminRefreshTrigger] = useState(0);

  // Queues
  const eventQueueRef = useRef([]);
  const processingRef = useRef(false);
  // Dedup guard: if the same event arrives twice (e.g. a duplicate/leaked WS
  // connection), drop the repeat so the pipeline/log never shows it twice.
  const seenEventIdsRef = useRef(new Set());

  // Expose switchTab globally
  useEffect(() => {
    window.switchTab = (tabId) => {
      setActiveTab(tabId);
    };
    return () => {
      delete window.switchTab;
    };
  }, []);

  // Sync ref values helper
  const syncRefs = (metrics) => {
    totalProcessedRef.current = metrics.totalProcessed;
    threatsInterceptedRef.current = metrics.threatsIntercepted;
    allowedProcessedRef.current = metrics.allowedProcessed;
    blockedProcessedRef.current = metrics.blockedProcessed;
    latencySumRef.current = metrics.latencySum;
    attackTypesRef.current = metrics.attackTypes;
  };

  // Fetch initial metrics on mount
  useEffect(() => {
    const initHUDAndDashboard = async () => {
      try {
        const res = await fetch('/api/metrics');
        if (!res.ok) return;
        const data = await res.json();
        const tp = data.total_requests || 0;
        const tt = data.total_threats || 0;
        const ta = (data.total_allowed || 0) + (data.total_monitored || 0);
        const tb = (data.total_blocked || 0) + (data.total_critical || 0);
        const al = data.avg_latency_ms || 0;
        const at = data.attack_types || {};

        const initialMetrics = {
          totalProcessed: tp,
          threatsIntercepted: tt,
          allowedProcessed: ta,
          blockedProcessed: tb,
          latencySum: al * tp,
          attackTypes: at,
        };

        syncRefs(initialMetrics);

        setEventsProcessed(tp);
        setThreatsIntercepted(tt);
        setTotalProcessed(tp);
        setAllowedProcessed(ta);
        setBlockedProcessed(tb);
        setAvgLatency(al);
        setAttackTypes(at);
      } catch (e) {
        console.warn('[HPE] Could not fetch initial metrics:', e);
      }
    };

    initHUDAndDashboard();
  }, []);

  // Process Event Queue Loop
  useEffect(() => {
    let isMounted = true;

    const processSingleEvent = async (data) => {
      const { event, prediction } = data;
      const isThreat = prediction.is_threat || false;
      const isLivePortal = (prediction.event_summary?.event_source === 'live_portal');
      const shouldAnimate = isLivePortal || (eventQueueRef.current.length < 3);

      // 1. Update Globe Arc
      const arcData = {
        startLat: prediction.source_geo?.lat || 0,
        startLng: prediction.source_geo?.lng || 0,
        endLat: prediction.destination_geo?.lat || 12.97,
        endLng: prediction.destination_geo?.lng || 77.59,
        source_city: prediction.source_geo?.city || 'Unknown',
        dest_city: prediction.destination_geo?.city || 'Bangalore',
        user: prediction.event_summary?.user || 'Unknown',
        event_type: prediction.event_summary?.anomaly_type || 'Unknown',
        threat_score: prediction.threat_score || 0,
        is_threat: isThreat,
      };

      setArcs(prev => {
        const next = [...prev, arcData];
        return next.length > 50 ? next.slice(-50) : next;
      });

      // 2. Update Pipeline Stage Latencies
      const stages = prediction.pipeline_stages || [];
      
      // Always update latencies for display
      if (stages && stages.length > 0) {
        setStageLatencies(stages.map(s => parseFloat(s.latency_ms?.toFixed(1) || 0)));
      }
      
      // Show vault terminal for threat events (credential rotation visualization)
      if (shouldAnimate && isThreat) {
        setVaultActive(true);
        setVaultLines([]);

        const lines = [
          { text: '> Initializing Vault connection via API...', delay: 200, class: '' },
          { text: '[OK] Vault authenticated. Protocol: TLS 1.3', delay: 150, class: 'success' },
          { text: `> Analyzing threat vector. Score: ${(prediction.threat_score * 100).toFixed(1)}%`, delay: 250, class: 'warning' },
          { text: '> Revoking compromised service tokens...', delay: 300, class: '' },
          { text: '[OK] Tokens revoked successfully.', delay: 100, class: 'success' },
          { text: '> Generating secure DB credentials (AES-256)...', delay: 350, class: '' },
          { text: '[OK] db_password updated.', delay: 100, class: 'success' },
          { text: '> Rotating API keys for Microservices...', delay: 250, class: '' },
          { text: '[OK] api_gateway, service_mesh credentials synced.', delay: 100, class: 'success' },
          { text: '> SECURE POSTURE RESTORED.', delay: 400, class: 'success' }
        ];

        for (const line of lines) {
          if (!isMounted) return;
          setVaultLines(prev => [...prev, line]);
          await sleep(line.delay);
        }
        await sleep(600);
        setVaultActive(false);
      }

      // 3. Show Temporary Result Banner
      const action = prediction.threat_action || 'ALLOW';
      setResultBanner({
        isThreat,
        action,
      });

      // 4. Update HUD and dashboard stats
      totalProcessedRef.current += 1;
      latencySumRef.current += prediction.total_latency_ms || 0;

      if (isThreat) {
        threatsInterceptedRef.current += 1;

        const aType = prediction.event_summary?.anomaly_type || 'Unknown';
        attackTypesRef.current = {
          ...attackTypesRef.current,
          [aType]: (attackTypesRef.current[aType] || 0) + 1,
        };
      }

      const threatAction = prediction.threat_action || 'ALLOW';
      if (threatAction === 'ALLOW' || threatAction === 'MONITOR') {
        allowedProcessedRef.current += 1;
      } else if (threatAction === 'BLOCK' || threatAction === 'CRITICAL_ALERT') {
        blockedProcessedRef.current += 1;
      }

      setEventsProcessed(totalProcessedRef.current);
      setThreatsIntercepted(threatsInterceptedRef.current);
      setTotalProcessed(totalProcessedRef.current);
      setAllowedProcessed(allowedProcessedRef.current);
      setBlockedProcessed(blockedProcessedRef.current);
      setAvgLatency(totalProcessedRef.current > 0 ? latencySumRef.current / totalProcessedRef.current : 0);
      setAttackTypes(attackTypesRef.current);

      if (prediction.xgb_score !== undefined) {
        setLatestModelScores({
          xgb: prediction.xgb_score,
          lgb: prediction.lgb_score,
          ensemble: prediction.ensemble_score,
          threshold: prediction.threshold || 0.5455,
        });
      }

      // 5. Append to Pipeline event log (all events including ALLOW)
      setEventsLog(prev => {
        const next = [prediction, ...prev];
        return next.length > 50 ? next.slice(0, 50) : next;
      });
    };

    const processQueue = async () => {
      while (isMounted) {
        if (eventQueueRef.current.length > 0 && !processingRef.current) {
          processingRef.current = true;
          const data = eventQueueRef.current.shift();
          try {
            await processSingleEvent(data);
          } catch (err) {
            console.error('[HPE] Error in processing queue event:', err);
          }
          processingRef.current = false;
        }
        await sleep(100);
      }
    };

    processQueue();

    return () => {
      isMounted = false;
    };
  }, []);

  // WebSockets Connections
  // 1. Simulation WS
  useEffect(() => {
    let ws = null;
    let isSimulating = false;
    let reconnectAttempts = 0;
    let localSimTimer = null;
    let reconnectTimer = null;

    const connectSimulation = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/simulate`;

      console.log(`[HPE] Connecting to simulation WebSocket: ${wsUrl}`);

      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log('[HPE] Simulation WebSocket connected');
          setConnected(true);
          isSimulating = true;
          reconnectAttempts = 0;
          if (localSimTimer) {
            clearTimeout(localSimTimer);
            localSimTimer = null;
          }
        };

        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            if (message.type === 'pipeline_result') {
              // Drop duplicate deliveries of the same event (e.g. a second/leaked
              // WS connection) so it is never rendered or logged twice.
              const eid = message.data?.prediction?.event_id;
              if (eid) {
                if (seenEventIdsRef.current.has(eid)) return;
                seenEventIdsRef.current.add(eid);
                if (seenEventIdsRef.current.size > 300) {
                  seenEventIdsRef.current = new Set(
                    Array.from(seenEventIdsRef.current).slice(-150)
                  );
                }
              }
              eventQueueRef.current.push(message.data);
            } else if (message.type === 'vpn_login_alert') {
              showVpnAlertBanner(message.data);
            }
          } catch (e) {
            console.error('[HPE] Failed to parse simulation message:', e);
          }
        };

        ws.onclose = () => {
          console.log('[HPE] Simulation WebSocket closed');
          setConnected(false);
          isSimulating = false;
          scheduleReconnect();
        };

        ws.onerror = (err) => {
          console.error('[HPE] Simulation WebSocket error:', err);
          setConnected(false);
          setTimeout(() => {
            if (!isSimulating) {
              startLocalSimulation();
            }
          }, 3000);
        };
      } catch (err) {
        console.error('[HPE] Simulation WebSocket connection failed:', err);
        scheduleReconnect();
      }
    };

    const scheduleReconnect = () => {
      if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;
      const baseDelay = 1000;
      const maxDelay = 30000;
      const delay = Math.min(maxDelay, baseDelay * Math.pow(2, reconnectAttempts));
      const jitter = (Math.random() - 0.5) * 0.4 * delay;
      const reconnectDelay = Math.max(1000, delay + jitter);
      reconnectAttempts++;
      reconnectTimer = setTimeout(connectSimulation, reconnectDelay);
    };

    const startLocalSimulation = async () => {
      console.log('[HPE] Loading sample events for local simulation...');
      try {
        const res = await fetch('/api/sample-events');
        if (!res.ok) {
          startInternalDemo();
          return;
        }
        const data = await res.json();
        const normal = data.sample_normal || [];
        const attack = data.sample_attack || [];
        const allEvents = [...normal, ...attack];
        if (allEvents.length === 0) {
          startInternalDemo();
          return;
        }

        let idx = 0;
        const runSim = async () => {
          if (isSimulating) return; // Web socket re-established
          const event = allEvents[idx % allEvents.length];
          idx++;

          try {
            const postRes = await fetch('/api/predict', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(event),
            });
            if (postRes.ok) {
              const prediction = await postRes.json();
              eventQueueRef.current.push({ event, prediction });
            }
          } catch (e) {
            console.error('[HPE] Local simulation error:', e);
          }
          localSimTimer = setTimeout(runSim, Math.random() * 2000 + 1000);
        };
        runSim();
      } catch (err) {
        startInternalDemo();
      }
    };

    const startInternalDemo = () => {
      console.log('[HPE] Running internal demo (no backend)');
      const demoEvents = [
        { user_id: 'USR-0175', source_ip: '109.223.221.101', ip_region: 'Asia-Pacific', user_region: 'Asia-Pacific', action: 'write', anomaly_type: 'None', geo_mismatch: false },
        { user_id: 'USR-0080', source_ip: '129.74.149.115', ip_region: 'Asia-Pacific', user_region: 'Asia-Pacific', action: 'read', anomaly_type: 'data_exfiltration', geo_mismatch: false },
        { user_id: 'USR-0057', source_ip: '140.56.194.153', ip_region: 'EU-Central', user_region: 'US-East', action: 'read', anomaly_type: 'impossible_travel', geo_mismatch: true },
        { user_id: 'USR-0032', source_ip: '162.245.203.53', ip_region: 'US-East', user_region: 'US-East', action: 'admin', anomaly_type: 'brute_force', geo_mismatch: false },
      ];

      const geoMap = {
        'US-East': { lat: 40.71, lng: -74.01, city: 'New York' },
        'US-West': { lat: 37.77, lng: -122.42, city: 'San Francisco' },
        'EU-Central': { lat: 50.11, lng: 8.68, city: 'Frankfurt' },
        'Asia-Pacific': { lat: 1.35, lng: 103.82, city: 'Singapore' },
        'South-America': { lat: -23.55, lng: -46.63, city: 'São Paulo' },
      };

      let idx = 0;
      const runDemo = () => {
        if (isSimulating) return;
        const event = demoEvents[idx % demoEvents.length];
        const isThreat = event.anomaly_type && event.anomaly_type !== 'None';

        const prediction = {
          event_id: `demo-${idx}`,
          is_threat: isThreat,
          threat_score: isThreat ? 0.85 + Math.random() * 0.15 : Math.random() * 0.1,
          threat_action: isThreat ? 'BLOCK' : 'ALLOW',
          xgb_score: isThreat ? 0.90 : Math.random() * 0.05,
          lgb_score: isThreat ? 0.88 : Math.random() * 0.08,
          ensemble_score: isThreat ? 0.89 : Math.random() * 0.06,
          threshold: 0.5455,
          source_geo: geoMap[event.ip_region] || { lat: 0, lng: 0, city: 'Unknown' },
          destination_geo: { lat: 12.97, lng: 77.59, city: 'Bangalore' },
          pipeline_stages: Array.from({ length: 10 }, (_, i) => ({
            stage_name: `Stage ${i + 1}`,
            latency_ms: Math.random() * 5 + 0.5,
            status: 'completed',
          })),
          total_latency_ms: Math.random() * 30 + 10,
          timestamp: new Date().toISOString(),
          event_summary: event,
        };

        eventQueueRef.current.push({ event, prediction });
        idx++;
        localSimTimer = setTimeout(runDemo, Math.random() * 3000 + 1500);
      };
      runDemo();
    };

    connectSimulation();

    return () => {
      if (ws) ws.close();
      if (localSimTimer) clearTimeout(localSimTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };
  }, []);

  // 2. Admin WS Connection
  useEffect(() => {
    if (!adminToken) return;

    let adminWs = null;
    let adminReconnectAttempts = 0;
    let reconnectTimer = null;

    const connectAdminWs = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/api/admin/ws?token=${adminToken}`;

      try {
        adminWs = new WebSocket(wsUrl);

        adminWs.onopen = () => {
          console.log('[ADMIN] WebSocket connected');
          adminReconnectAttempts = 0;
        };

        adminWs.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            handleAdminMessage(message);
          } catch (e) {
            console.error('[ADMIN] Failed to parse admin message:', e);
          }
        };

        adminWs.onclose = () => {
          console.log('[ADMIN] WebSocket closed');
          scheduleAdminReconnect();
        };

        adminWs.onerror = () => {
          console.error('[ADMIN] WebSocket error');
        };
      } catch (err) {
        console.error('[ADMIN] WebSocket connection failed:', err);
        scheduleAdminReconnect();
      }
    };

    const scheduleAdminReconnect = () => {
      if (adminWs && (adminWs.readyState === WebSocket.CONNECTING || adminWs.readyState === WebSocket.OPEN)) return;
      const baseDelay = 1000;
      const maxDelay = 30000;
      const delay = Math.min(maxDelay, baseDelay * Math.pow(2, adminReconnectAttempts));
      const jitter = (Math.random() - 0.5) * 0.4 * delay;
      const reconnectDelay = Math.max(1000, delay + jitter);
      adminReconnectAttempts++;
      reconnectTimer = setTimeout(connectAdminWs, reconnectDelay);
    };

    const handleAdminMessage = (message) => {
      switch (message.type) {
        case 'new_alert':
          const isCritical = message.data.threat_action === 'CRITICAL_ALERT';
          const title = isCritical ? '🚨 CRITICAL ALERT' : '⚠ New Threat Alert';
          const msg = `${message.data.user_id} — Score: ${((message.data.threat_score || 0) * 100).toFixed(1)}%`;
          showNotificationToast(title, msg);
          setAdminRefreshTrigger(prev => prev + 1);
          break;
        case 'alert_resolved':
          setAdminRefreshTrigger(prev => prev + 1);
          break;
        case 'new_registration':
          showNotificationToast('👤 New Access Request', `User ${message.data.username} (${message.data.department}) has requested access.`);
          setAdminRefreshTrigger(prev => prev + 1);
          break;
        case 'vpn_login_alert':
          const vpn = message.data;
          const status = vpn.login_success ? '✓ Login OK' : '✗ Login Failed';
          showNotificationToast(
            '🛡️ VPN LOGIN DETECTED',
            `${vpn.username} from ${vpn.source_ip} (${vpn.vpn_provider}, ${vpn.city}, ${vpn.country}) — ${status}`
          );
          showVpnAlertBanner(vpn);
          setAdminRefreshTrigger(prev => prev + 1);
          break;
        default:
          break;
      }
    };

    connectAdminWs();

    return () => {
      if (adminWs) adminWs.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };
  }, [adminToken]);

  // Toast / Banner Helpers
  const showNotificationToast = (title, message) => {
    setToast({ title, message });
  };

  const hideToast = () => {
    setToast(null);
  };

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => {
        setToast(null);
      }, 6000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  const showVpnAlertBanner = (data) => {
    const alertId = `vpn-alert-${Date.now()}-${Math.random()}`;
    const newAlert = { id: alertId, data };
    setVpnAlerts(prev => {
      const next = [...prev, newAlert];
      return next.length > 3 ? next.slice(-3) : next;
    });
  };

  const dismissVpnAlert = (id) => {
    setVpnAlerts(prev => prev.filter(a => a.id !== id));
  };

  // Listen to Admin login success triggers dispatched from components
  useEffect(() => {
    const handleLoginSuccess = (e) => {
      const { token, user } = e.detail;
      setAdminToken(token);
      setAdminUser(user);
    };
    window.addEventListener('admin-login-success', handleLoginSuccess);
    return () => {
      window.removeEventListener('admin-login-success', handleLoginSuccess);
    };
  }, []);

  const threatPercent = eventsProcessed > 0 ? (threatsIntercepted / eventsProcessed * 100) : 0;

  return (
    <div className="app-container">
      {/* Concrete StarField Twinkling Background */}
      <StarField />

      {/* Main Header navigation tabs */}
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        connected={connected}
      />

      {/* Section Views Router */}
      <div className="section-viewport">
        {/* Threat Globe Section */}
        <ThreatGlobe
          active={activeTab === 'globe-section'}
          eventsProcessed={eventsProcessed}
          threatsIntercepted={threatsIntercepted}
          threatPercent={threatPercent}
          arcs={arcs}
        />

        {/* Pipeline Flow Section */}
        <PipelineFlow
          active={activeTab === 'pipeline-section'}
          activeStage={activeStage}
          activeConnector={activeConnector}
          isThreatFlow={isThreatFlow}
          stageLatencies={stageLatencies}
          vaultActive={vaultActive}
          vaultLines={vaultLines}
          eventsLog={eventsLog}
        />

        {/* Analytics Dashboard Section */}
        <AnalyticsDashboard
          active={activeTab === 'dashboard-section'}
          totalProcessed={totalProcessed}
          threatsIntercepted={threatsIntercepted}
          allowedProcessed={allowedProcessed}
          blockedProcessed={blockedProcessed}
          avgLatency={avgLatency}
          attackTypes={attackTypes}
          latestModelScores={latestModelScores}
          onRedirectToAdmin={() => setActiveTab('admin-section')}
        />

        {/* Security Admin Console Section */}
        <AdminConsole
          active={activeTab === 'admin-section'}
          refreshTrigger={adminRefreshTrigger}
          onShowToast={showNotificationToast}
          adminToken={adminToken}
          setAdminToken={setAdminToken}
          adminUser={adminUser}
          setAdminUser={setAdminUser}
        />

        {/* Dynamic Lazy-loaded Database (Adminer) Section */}
        <IframeSection
          tabId="adminer-section"
          port={9090}
          active={activeTab === 'adminer-section'}
        />

        {/* Dynamic Lazy-loaded Kibana Logs Section */}
        <IframeSection
          tabId="kibana-section"
          port={5601}
          active={activeTab === 'kibana-section'}
        />
      </div>

      {/* Global Toast Notification */}
      {toast && (
        <div className="admin-toast show" style={{ display: 'flex', zIndex: 99999 }}>
          <div className="admin-toast-icon">🚨</div>
          <div className="admin-toast-content">
            <div className="admin-toast-title">{toast.title}</div>
            <div className="admin-toast-message">{toast.message}</div>
          </div>
          <button className="admin-toast-close" onClick={hideToast}>×</button>
        </div>
      )}

      {/* Global Pipeline Temporary Result Banner */}
      {resultBanner && (
        <div
          className={`result-banner ${resultBanner.isThreat ? 'neutralized' : 'secured'}`}
          style={{ zIndex: 99998 }}
        >
          {resultBanner.isThreat
            ? `⚠ THREAT NEUTRALIZED — ${resultBanner.action}`
            : '✓ SECURED — TRAFFIC ALLOWED'}
        </div>
      )}

      {/* VPN Login Alerts overlay */}
      <div className="vpn-alert-container" id="vpn-alert-container" style={{ zIndex: 99997 }}>
        {vpnAlerts.map(alert => (
          <VpnAlertBanner
            key={alert.id}
            id={alert.id}
            data={alert.data}
            onDismiss={dismissVpnAlert}
            onRedirect={() => setActiveTab('admin-section')}
          />
        ))}
      </div>
    </div>
  );
}

// Child component to manage its own countdown lifecycle for a clean timer
function VpnAlertBanner({ id, data, onDismiss, onRedirect }) {
  const [remaining, setRemaining] = useState(15);

  useEffect(() => {
    const interval = setInterval(() => {
      setRemaining(prev => {
        if (prev <= 1) {
          clearInterval(interval);
          onDismiss(id);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [id, onDismiss]);

  const statusClass = data.login_success ? 'vpn-status-success' : 'vpn-status-failure';
  const statusText = data.login_success ? '✓ LOGIN SUCCESS' : '✗ LOGIN FAILED';
  const timeStr = data.timestamp
    ? new Date(data.timestamp).toLocaleTimeString()
    : new Date().toLocaleTimeString();

  return (
    <div
      className="vpn-alert-banner"
      id={id}
      onClick={onRedirect}
      style={{ cursor: 'pointer' }}
    >
      <div className="vpn-alert-header">
        <div className="vpn-alert-title">
          <span className="vpn-shield-icon">🛡️</span>
          VPN Login Detected
        </div>
        <button
          className="vpn-alert-close"
          onClick={(e) => {
            e.stopPropagation();
            onDismiss(id);
          }}
        >
          ✕
        </button>
      </div>
      <div className="vpn-alert-body">
        <div className="vpn-alert-field">
          <span className="vpn-alert-field-label">Username</span>
          <span className="vpn-alert-field-value">{data.username || 'unknown'}</span>
        </div>
        <div className="vpn-alert-field">
          <span className="vpn-alert-field-label">Source IP</span>
          <span className="vpn-alert-field-value vpn-ip">{data.source_ip || '--'}</span>
        </div>
        <div className="vpn-alert-field">
          <span className="vpn-alert-field-label">VPN Provider / ISP</span>
          <span className="vpn-alert-field-value vpn-provider">{data.vpn_provider || 'Unknown'}</span>
        </div>
        <div className="vpn-alert-field">
          <span className="vpn-alert-field-label">Location</span>
          <span className="vpn-alert-field-value">{data.city || '?'}, {data.country || '?'}</span>
        </div>
        <div className="vpn-alert-field">
          <span className="vpn-alert-field-label">Status</span>
          <span className={`vpn-alert-field-value ${statusClass}`}>{statusText}</span>
        </div>
        <div className="vpn-alert-field">
          <span className="vpn-alert-field-label">Time</span>
          <span className="vpn-alert-field-value">{timeStr}</span>
        </div>
      </div>
      <div className="vpn-alert-footer">
        <span style={{ color: 'var(--amber)', fontWeight: 600, fontSize: '10px', display: 'flex', alignItems: 'center', gap: '4px' }}>
          👉 Click to review in Admin Console
        </span>
        <span className="vpn-alert-countdown">Auto-dismiss in {remaining}s</span>
      </div>
    </div>
  );
}
