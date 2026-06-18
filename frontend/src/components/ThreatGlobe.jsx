import React, { useEffect, useRef, useState, useCallback } from 'react';
import Globe from 'globe.gl';

const SERVER = { lat: 12.97, lng: 77.59, city: 'Bangalore' };
const COLORS = {
  safe: '#2ecc71',
  safeDim: 'rgba(46, 204, 113, 0.35)',
  threat: '#d63031',
  threatDim: 'rgba(214, 48, 49, 0.35)',
  cyan: '#0984e3',
  atmosphere: '#1a6aff',
};

export default function ThreatGlobe({ active, eventsProcessed, threatsIntercepted, threatPercent, arcs }) {
  const containerRef = useRef(null);
  const globeInstance = useRef(null);
  const arcsRef = useRef([]);
  const animFrameRef = useRef(null);
  const [selectedArc, setSelectedArc] = useState(null);

  // Initialize Globe once
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const w = container.offsetWidth || window.innerWidth;
    const h = container.offsetHeight || window.innerHeight;

    const globe = Globe()
      .width(w)
      .height(h)
      .globeImageUrl('https://unpkg.com/three-globe@2.31.1/example/img/earth-night.jpg')
      .bumpImageUrl('https://unpkg.com/three-globe@2.31.1/example/img/earth-topology.png')
      .backgroundImageUrl('')
      .backgroundColor('rgba(0,0,0,0)')
      .showAtmosphere(true)
      .atmosphereColor(COLORS.atmosphere)
      .atmosphereAltitude(0.25)

      // Arcs configuration — smooth animated dashes
      .arcsData([])
      .arcColor(d => d.is_threat ? [COLORS.threatDim, COLORS.threat] : [COLORS.safeDim, COLORS.safe])
      .arcStroke(d => d.is_threat ? 0.9 : 0.6)
      .arcDashLength(0.6)
      .arcDashGap(0.15)
      .arcDashAnimateTime(d => d.is_threat ? 1200 : 2500)
      .arcAltitudeAutoScale(0.4)
      .arcsTransitionDuration(600)
      .onArcHover(arc => {
        if (globeInstance.current) {
          globeInstance.current.controls().autoRotate = !arc;
        }
        document.body.style.cursor = arc ? 'pointer' : 'default';
      })
      .onArcClick(arc => {
        if (arc) setSelectedArc(arc);
      })

      // Points configuration
      .pointsData([{ lat: SERVER.lat, lng: SERVER.lng, is_server: true, label: 'HPE Core' }])
      .pointColor(d => d.is_server ? COLORS.cyan : (d.is_threat ? COLORS.threat : COLORS.safe))
      .pointAltitude(d => d.is_server ? 0.06 : 0.015)
      .pointRadius(d => d.is_server ? 0.7 : 0.25)
      .pointLabel(d => {
        if (d.is_server) {
          return `<div style="background: rgba(18, 18, 20, 0.95); border: 2px solid #eae5d9; padding: 8px; font-family: monospace; font-size: 11px; color: #eae5d9; pointer-events: none;">
            <strong style="color: #0984e3">${d.label}</strong><br/>
            Location: Bangalore, India<br/>
            Coords: 12.97°N, 77.59°E
          </div>`;
        }
        return `<div style="background: rgba(18, 18, 20, 0.95); border: 2px solid ${d.is_threat ? '#d63031' : '#2ecc71'}; padding: 8px; font-family: monospace; font-size: 11px; color: #eae5d9; pointer-events: none;">
          <strong style="color: ${d.is_threat ? '#d63031' : '#2ecc71'}">${d.is_threat ? '⚠ Threat Location' : '✓ Secure Client'}</strong><br/>
          User: <strong>${d.user || 'Unknown'}</strong><br/>
          Location: ${d.source_city || 'Unknown'}<br/>
          IP Coords: ${d.lat.toFixed(2)}°, ${d.lng.toFixed(2)}°
        </div>`;
      })
      .pointsMerge(false)
      .pointsTransitionDuration(400)

      // Rings configuration — pulse at server location
      .ringsData([{ lat: SERVER.lat, lng: SERVER.lng }])
      .ringColor(() => t => `rgba(9, 132, 227, ${Math.sqrt(1 - t)})`)
      .ringMaxRadius(3)
      .ringPropagationSpeed(2)
      .ringRepeatPeriod(1500)

      (container);

    // Set initial camera
    globe.pointOfView({ lat: 20, lng: 60, altitude: 2.5 }, 0);

    // Controls
    const controls = globe.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.5;
    controls.enableZoom = true;
    controls.enableDamping = true;
    controls.dampingFactor = 0.1;
    controls.rotateSpeed = 0.8;
    controls.minDistance = 150;
    controls.maxDistance = 500;

    // Transparent background
    const scene = globe.scene();
    if (scene) scene.background = null;

    // Improve renderer for smoother visuals
    const renderer = globe.renderer();
    if (renderer) {
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      renderer.setClearAlpha(0);
    }

    globeInstance.current = globe;

    // Resize handler
    const handleResize = () => {
      if (containerRef.current && globeInstance.current) {
        const cw = containerRef.current.offsetWidth;
        const ch = containerRef.current.offsetHeight;
        if (cw > 0 && ch > 0) {
          globeInstance.current.width(cw);
          globeInstance.current.height(ch);
        }
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      container.innerHTML = '';
      globeInstance.current = null;
    };
  }, []);

  // Smoothly update arc data using ref + requestAnimationFrame to batch updates
  useEffect(() => {
    arcsRef.current = arcs;

    if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);

    animFrameRef.current = requestAnimationFrame(() => {
      const globe = globeInstance.current;
      if (!globe) return;

      const currentArcs = arcsRef.current;

      // Update arcs
      globe.arcsData(currentArcs);

      // Compute point markers (Server + source points from arcs)
      const points = [{ lat: SERVER.lat, lng: SERVER.lng, is_server: true, label: 'HPE Core' }];
      currentArcs.forEach(arc => {
        points.push({
          lat: arc.startLat,
          lng: arc.startLng,
          is_threat: arc.is_threat,
          is_server: false,
          user: arc.user,
          source_city: arc.source_city,
        });
      });

      // Cap at 80 points for performance
      const trimmed = points.length > 80 ? [points[0], ...points.slice(-79)] : points;
      globe.pointsData(trimmed);

      // Flash ring on latest threat
      const latestArc = currentArcs[currentArcs.length - 1];
      if (latestArc && latestArc.is_threat) {
        globe.ringsData([
          { lat: SERVER.lat, lng: SERVER.lng },
          { lat: latestArc.startLat, lng: latestArc.startLng },
        ]);
        globe.ringColor(() => t => `rgba(214, 48, 49, ${Math.sqrt(1 - t)})`);
      }
    });

    // Reset ring color after threat flash
    const latestArc = arcs[arcs.length - 1];
    if (latestArc && latestArc.is_threat) {
      const timer = setTimeout(() => {
        if (globeInstance.current) {
          globeInstance.current.ringsData([{ lat: SERVER.lat, lng: SERVER.lng }]);
          globeInstance.current.ringColor(() => t => `rgba(9, 132, 227, ${Math.sqrt(1 - t)})`);
        }
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, [arcs]);

  // Handle active tab — resize the globe canvas to fill its container
  useEffect(() => {
    if (active && globeInstance.current && containerRef.current) {
      // Wait for the CSS display transition to complete before measuring
      const timers = [
        setTimeout(() => {
          if (globeInstance.current && containerRef.current) {
            const cw = containerRef.current.offsetWidth;
            const ch = containerRef.current.offsetHeight;
            if (cw > 0 && ch > 0) {
              globeInstance.current.width(cw);
              globeInstance.current.height(ch);
            }
          }
        }, 100),
        // Second pass for layout settling
        setTimeout(() => {
          if (globeInstance.current && containerRef.current) {
            const cw = containerRef.current.offsetWidth;
            const ch = containerRef.current.offsetHeight;
            if (cw > 0 && ch > 0) {
              globeInstance.current.width(cw);
              globeInstance.current.height(ch);
            }
          }
        }, 400),
      ];
      return () => timers.forEach(clearTimeout);
    }
  }, [active]);

  const threatLevelLabel = threatPercent > 10 ? 'CRITICAL' : threatPercent > 5 ? 'ELEVATED' : 'NOMINAL';
  const threatLevelClass = threatPercent > 10 ? 'danger' : threatPercent > 5 ? 'warning' : 'success';

  return (
    <section className={`section ${active ? 'active' : ''}`} id="globe-section" style={{ padding: 0, overflow: 'hidden' }}>
      <div ref={containerRef} id="globe-container" style={{ width: '100%', height: '100%' }} />

      {/* Connection Detail Modal */}
      {selectedArc && (
        <div id="arc-details-modal" className="arc-details-modal" style={{ display: 'block' }}>
          <button className="arc-modal-close" onClick={() => setSelectedArc(null)}>×</button>
          <div id="arc-details-content">
            <div className={`arc-detail-header ${selectedArc.is_threat ? 'danger' : 'success'}`}>
              {selectedArc.is_threat ? '⚠ THREAT INTERCEPTED' : '✓ SECURE CONNECTION'}
            </div>
            <div className="arc-detail-body">
              <div className="detail-row"><span>User:</span> <strong>{selectedArc.user || 'Unknown'}</strong></div>
              <div className="detail-row"><span>Path:</span> {selectedArc.source_city} → {selectedArc.dest_city}</div>
              <div className="detail-row"><span>Type:</span> {selectedArc.event_type || 'Unknown'}</div>
              {selectedArc.is_threat && (
                <div className="detail-row">
                  <span style={{ color: 'var(--red-stark)' }}>Score:</span> {(selectedArc.threat_score * 100).toFixed(1)}%
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* HUD overlays */}
      <div className="globe-hud globe-hud-top-left">
        <div className="hud-card">
          <div className="hud-label">Events Processed</div>
          <div className="hud-value">{eventsProcessed.toLocaleString()}</div>
          <div className="hud-sub">Live pipeline throughput</div>
        </div>
      </div>

      <div className="globe-hud globe-hud-top-right">
        <div className="hud-card">
          <div className="hud-label">Threats Intercepted</div>
          <div className="hud-value danger">{threatsIntercepted.toLocaleString()}</div>
          <div className="hud-sub">AI-detected anomalies</div>
        </div>
      </div>

      <div className="globe-hud globe-hud-bottom-left">
        <div className="hud-card">
          <div className="hud-label">Threat Level</div>
          <div className={`hud-value ${threatLevelClass}`}>{threatLevelLabel}</div>
          <div className="threat-level-bar">
            <div className="threat-level-fill" style={{ width: `${Math.min(threatPercent * 5, 100)}%` }} />
          </div>
        </div>
      </div>

      <div className="globe-hud globe-hud-bottom-right">
        <div className="hud-card">
          <div className="hud-label">Server Location</div>
          <div className="hud-value" style={{ fontSize: '16px', color: 'var(--cyan)' }}>Bangalore, IN</div>
          <div className="hud-sub">12.97°N, 77.59°E</div>
        </div>
      </div>
    </section>
  );
}
