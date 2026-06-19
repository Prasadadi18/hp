import React, { useState, useEffect, useRef } from 'react';

const formatIpShort = (ip) => {
  if (!ip) return '--';
  if (ip.includes(':') && ip.length > 15) {
    const parts = ip.split(':');
    return `${parts[0]}:${parts[1]}:…`;
  }
  return ip;
};

const STAGES = [
  { name: 'Network / Apps', icon: '🌐' },
  { name: 'Zeek / Suricata', icon: '🛡️' },
  { name: 'Elastic Beats', icon: '📊' },
  { name: 'Apache Kafka', icon: '⚡' },
  { name: 'AI Engine', icon: '🧠' },
  { name: 'SOAR', icon: '🔄' },
  { name: 'Vault', icon: '🔐' },
  { name: 'Cred Rotation', icon: '🔑' },
  { name: 'Cred Distributed', icon: '📤' },
  { name: 'ELK / Grafana', icon: '📈' },
];

const STAGE_EXPLANATIONS = [
  "We continuously monitor network traffic across the enterprise. Raw data packets (PCAP) from routers and application logs are collected and converted into a standard format, providing the foundational telemetry stream for our security pipeline.",
  "Traffic passes through an Intrusion Detection System (IDS). Tools like Suricata and Zeek perform Deep Packet Inspection (DPI) to quickly scan for known malicious patterns and extract useful network metadata (like HTTP or DNS info).",
  "To keep data organized, we use log shippers like Filebeat. They collect raw logs from the IDS, clean them up into a standardized format called the Elastic Common Schema (ECS), and map IP addresses to geographic locations.",
  "To transport this massive amount of data smoothly, we use Apache Kafka as a high-throughput event streaming broker. It acts as a buffer, ensuring our AI Engine isn't overwhelmed during sudden spikes in network traffic.",
  "The core brain of the system. Our FastAPI microservice consumes the Kafka stream and engineers complex behavioral features in split-seconds. It relies on an AI ensemble (XGBoost, LightGBM, and Isolation Forest) to predict if an event is a novel threat.",
  "If the AI flags a threat, our SOAR (Security Orchestration, Automation, and Response) platform takes over. Rather than waiting for a human, it automatically triggers incident response playbooks—like isolating machines or initiating password resets.",
  "As part of the automated response, HashiCorp Vault is engaged to secure our infrastructure. Vault manages dynamic secrets; when a threat is detected, it receives an API command to immediately begin revoking compromised access.",
  "Vault executes a secure credential rotation. It instantly invalidates old, hijacked sessions and generates cryptographically secure, brand-new passwords and API keys for our databases and services, effectively locking the attacker out.",
  "Once new passwords are created, they must be distributed safely. The system automatically pushes these new Vault secrets to our servers and microservices using encrypted tunnels (TLS), restoring security without taking the system offline.",
  "Finally, every single event—safe traffic or neutralized threat—is permanently recorded. We index all data into an Elasticsearch database, allowing human analysts to search audit logs and view real-time visualizations on Kibana or Grafana."
];

export default function PipelineFlow({
  active,
  stageLatencies,
  vaultActive,
  vaultLines,
  eventsLog,
}) {
  const [selectedStage, setSelectedStage] = useState(null);
  
  // Track multiple simultaneous animations (id, connector index, color)
  const [activeAnimations, setActiveAnimations] = useState([]);
  
  // Track the last processed event to detect new events
  const lastProcessedEventRef = useRef(null);
  
  // Unique ID generator for each animation instance
  const animationIdCounter = useRef(0);
  
  // Track number of active animations to prevent performance issues
  const activeAnimationCountRef = useRef(0);
  
  // Maximum simultaneous animations to prevent browser performance issues
  const MAX_SIMULTANEOUS_ANIMATIONS = 20;

  // Start animation for every new event (ALLOW=green, MONITOR=yellow, BLOCK=blue, CRITICAL=red)
  useEffect(() => {
    if (!active || eventsLog.length === 0) return;

    const latestEvent = eventsLog[0];

    if (lastProcessedEventRef.current === latestEvent) return;
    lastProcessedEventRef.current = latestEvent;

    const action = latestEvent.threat_action || 'ALLOW';

    if (activeAnimationCountRef.current >= MAX_SIMULTANEOUS_ANIMATIONS) {
      console.warn(`[Pipeline] Skipping animation - max limit (${MAX_SIMULTANEOUS_ANIMATIONS}) reached`);
      return;
    }

    let color = 'green';
    if (action === 'MONITOR') color = 'yellow';
    else if (action === 'BLOCK') color = 'blue';
    else if (action === 'CRITICAL_ALERT') color = 'red';

    startAnimation(color);
  }, [eventsLog, active]);

  // Animate a colored point through all 9 connectors (10 stages = 9 arrows)
  const startAnimation = async (color) => {
    const animationId = animationIdCounter.current++;
    activeAnimationCountRef.current++;

    try {
      for (let i = 0; i < 9; i++) {
        setActiveAnimations(prev => [...prev.filter(a => a.id !== animationId), { id: animationId, connector: i, color }]);
        await new Promise(resolve => setTimeout(resolve, 150));
      }
    } finally {
      setActiveAnimations(prev => prev.filter(a => a.id !== animationId));
      activeAnimationCountRef.current--;
    }
  };

  if (!active) return null;

  return (
    <section className="section active" id="pipeline-section">
      <div className="section-title">Security Pipeline</div>
      <h2 className="section-heading">Full Enterprise Pipeline Flow</h2>
      <p style={{ color: 'var(--text-secondary)', maxWidth: '700px', marginBottom: 'var(--space-lg)', fontSize: '14px', lineHeight: '1.6' }}>
        Every threat event flows through a 10-stage enterprise security pipeline
        integrated with AI-powered anomaly detection.
        Only non-compliant events are shown — blue for block, yellow for monitor, red for critical alert.
      </p>

      {/* Pipeline Nodes Flowchart */}
      <div style={{ position: 'relative', width: '100%', overflowX: 'auto', overflowY: 'visible', padding: '20px 0' }}>
        <div className="pipeline-flow">
          {STAGES.map((stage, idx) => {
            const latency = stageLatencies[idx];

            return (
              <React.Fragment key={idx}>
                <div
                  className="pipeline-node"
                  onClick={() => setSelectedStage(idx)}
                  title={`${stage.name} - Click to view details`}
                >
                  <div className="node-icon-wrapper">
                    <span className="node-icon">{stage.icon}</span>
                  </div>
                  <span className="node-name">{stage.name}</span>
                  <span className="node-latency">
                    {(latency !== undefined && latency !== null && latency > 0) ? `${latency}ms` : '--ms'}
                  </span>
                </div>

                {idx < STAGES.length - 1 && (
                  <div className="pipeline-connector">
                    {activeAnimations
                      .filter(animation => animation.connector === idx)
                      .map(animation => (
                        <div
                          key={animation.id}
                          className={`data-packet packet-${animation.color}`}
                        />
                      ))
                    }
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Vault Credential Rotation Display */}
      {vaultActive && (
        <div id="vault-terminal" className="vault-terminal" style={{ display: 'block' }}>
          <div className="terminal-header">
            <span className="terminal-icon">🔐</span> HashiCorp Vault — Secure Rotation Protocol
          </div>
          <div className="terminal-body">
            {vaultLines.map((line, idx) => (
              <div key={idx} className={`terminal-line ${line.class || ''}`}>
                {line.text}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Stage Explanation Modal */}
      {selectedStage !== null && (
        <div id="stage-modal" className="stage-modal" onClick={() => setSelectedStage(null)}>
          <div className="stage-modal-content" onClick={e => e.stopPropagation()}>
            <button className="stage-modal-close" onClick={() => setSelectedStage(null)}>×</button>
            <div className="stage-modal-header">
              <span style={{ marginRight: '8px' }}>{STAGES[selectedStage].icon}</span>
              {STAGES[selectedStage].name}
            </div>
            <div className="stage-modal-body">{STAGE_EXPLANATIONS[selectedStage]}</div>
          </div>
        </div>
      )}

      {/* Event Logs — all processed events */}
      <div className="pipeline-event-log">
        {(() => {
          if (eventsLog.length === 0) {
            return (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px', padding: 'var(--space-lg)' }}>
                No events yet — press Launch Simulation to begin.
              </div>
            );
          }
          return eventsLog.map((event, idx) => {
            const action = event.threat_action || 'ALLOW';
            const badgeClass = action === 'ALLOW' ? 'allow'
              : action === 'MONITOR' ? 'monitor'
              : action === 'BLOCK' ? 'block'
              : 'critical';

            return (
              <div className="pipeline-event" key={idx}>
                <span className={`event-badge ${badgeClass}`}>{action.replace('_', ' ')}</span>
                <span className="event-user">{event.event_summary?.user || 'unknown'}</span>
                <span className="event-ip" title={event.event_summary?.source_ip || ''}>{formatIpShort(event.event_summary?.source_ip)}</span>
                <span className="event-process">
                  {(event.event_summary?.anomaly_type && event.event_summary?.anomaly_type !== 'None' && event.event_summary?.anomaly_type !== 'unknown')
                    ? event.event_summary?.anomaly_type
                    : (event.event_summary?.action || '--')}
                </span>
                <span className="event-score">{(event.threat_score * 100).toFixed(1)}%</span>
                <span className="event-time">
                  {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}
                </span>
              </div>
            );
          });
        })()}
      </div>

      <footer className="section-footer">
        HPE — AI-Powered Network Threat Detection Pipeline — Cyber Command Center
      </footer>
    </section>
  );
}
