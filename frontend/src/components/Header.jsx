import React, { useState, useEffect, useCallback, useRef } from 'react';

// Host-side mode-switcher agent (scripts/mode_switcher.py). It runs on the HOST,
// outside Docker, because switching modes restarts the whole stack (incl. this
// frontend). Start it with:  python scripts/mode_switcher.py
const SWITCHER_URL = `http://${window.location.hostname}:9001`;

function ModeSwitch() {
  const [mode, setMode] = useState('unknown');   // 'live-replay' | 'portal' | 'stopped' | 'unknown' | 'offline'
  const [switching, setSwitching] = useState(false);
  const pollRef = useRef(null);

  const poll = useCallback(async () => {
    try {
      const res = await fetch(`${SWITCHER_URL}/status`, { cache: 'no-store' });
      if (!res.ok) throw new Error('bad status');
      const data = await res.json();
      setMode(data.mode);
      setSwitching(Boolean(data.busy));
    } catch {
      setMode('offline');   // agent not running
    }
  }, []);

  useEffect(() => {
    poll();
    pollRef.current = setInterval(poll, 5000);
    return () => clearInterval(pollRef.current);
  }, [poll]);

  const switchTo = async (target) => {
    // target: 'live' or 'portal'
    const label = target === 'live' ? 'Live-Replay (full stack)' : 'Portal-Only';
    if (!window.confirm(
      `Switch to ${label}?\n\nThis restarts the entire Docker stack (down + up --build). ` +
      `The dashboard will disconnect for ~30-90s and reconnect when it's back.`
    )) return;

    setSwitching(true);
    try {
      const res = await fetch(`${SWITCHER_URL}/switch/${target}`, { method: 'POST' });
      if (res.status === 409) {
        alert('A switch is already in progress.');
        return;
      }
      if (!res.ok) throw new Error('switch failed');
      // Fire-and-forget: the stack (incl. this page) is now restarting.
    } catch {
      alert(
        'Could not reach the mode-switcher agent on :9001.\n\n' +
        'Start it on the host with:  python scripts/mode_switcher.py'
      );
      setSwitching(false);
    }
  };

  if (mode === 'offline') {
    return (
      <div className="mode-switch" title="Run: python scripts/mode_switcher.py">
        <span className="mode-switch-label">MODE</span>
        <span className="mode-pill offline">agent offline</span>
      </div>
    );
  }

  return (
    <div className="mode-switch">
      <span className="mode-switch-label">MODE</span>
      {switching ? (
        <span className="mode-pill switching">switching…</span>
      ) : (
        <>
          <button
            className={`mode-btn ${mode === 'live-replay' ? 'active' : ''}`}
            onClick={() => switchTo('live')}
            disabled={mode === 'live-replay'}
            title="docker-compose.yml — full stack with Zeek dataset streaming"
          >
            Live Replay
          </button>
          <button
            className={`mode-btn ${mode === 'portal' ? 'active' : ''}`}
            onClick={() => switchTo('portal')}
            disabled={mode === 'portal'}
            title="docker-compose.portal.yml — portal logins only"
          >
            Portal
          </button>
        </>
      )}
    </div>
  );
}

export default function Header({ activeTab, onTabChange, connected }) {
  const tabs = [
    { id: 'globe-section', label: 'Threat Globe', colorClass: 'globe' },
    { id: 'pipeline-section', label: 'Pipeline Flow', colorClass: 'pipeline' },
    { id: 'dashboard-section', label: 'Analytics', colorClass: 'dashboard' },
    { id: 'admin-section', label: 'Admin Console', colorClass: 'admin' },
    { id: 'adminer-section', label: 'Database', colorClass: 'database' },
    { id: 'kibana-section', label: 'Kibana Logs', colorClass: 'kibana' },
  ];

  return (
    <nav className="nav-header" id="nav-header">
      <div className="nav-logo">
        <div className="nav-logo-icon">🛡️</div>
        <div className="nav-logo-text">
          <h1>HPE</h1>
          <span>Cyber Command Center</span>
        </div>
      </div>

      <div className="nav-tabs">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => onTabChange(tab.id)}
          >
            <span className={`tab-dot ${tab.colorClass}`} />
            {tab.label}
          </button>
        ))}
      </div>

      <div className="nav-status">
        <ModeSwitch />
        <div className="status-indicator">
          <div className={`status-dot ${connected ? '' : 'warning'}`} />
          <span>{connected ? 'SYSTEM LIVE' : 'LOCAL SIMULATION'}</span>
        </div>
      </div>
    </nav>
  );
}
