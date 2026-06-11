import React from 'react';

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
        <div className="status-indicator">
          <div className={`status-dot ${connected ? '' : 'warning'}`} />
          <span>{connected ? 'SYSTEM LIVE' : 'LOCAL SIMULATION'}</span>
        </div>
      </div>
    </nav>
  );
}
