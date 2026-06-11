/**
 * globe.js — 3D Earth visualization with Globe.GL
 * Wireframe/dot-pattern globe with real data arcs from the two-day sample dataset.
 */

import Globe from 'globe.gl';

let globe = null;
let arcsData = [];
let pointsData = [];
let animationFrame = null;

// Server location (Bangalore)
const SERVER = { lat: 12.97, lng: 77.59, city: 'Bangalore' };

// Color palette for WebGL
const COLORS = {
  safe: '#39FF14',
  safeDim: '#39FF1466', // 40% opacity hex
  threat: '#FF006E',
  threatDim: '#FF006E66',
  cyan: '#00F5FF',
  amber: '#FFB800',
  globe: '#0B0E14',
  atmosphere: '#00F5FF',
};

/**
 * Initialize the Globe.GL instance
 */
export function initGlobe(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return null;

  globe = Globe()
    // Globe appearance — dark wireframe style
    .globeImageUrl('https://unpkg.com/three-globe@2.31.1/example/img/earth-night.jpg')
    .bumpImageUrl('https://unpkg.com/three-globe@2.31.1/example/img/earth-topology.png')
    .backgroundImageUrl('https://unpkg.com/three-globe@2.31.1/example/img/night-sky.png')
    .showAtmosphere(true)
    .atmosphereColor(COLORS.atmosphere)
    .atmosphereAltitude(0.2)
    .hexPolygonsData([])
    .hexPolygonColor(() => '#00F5FF1A') // 10% opacity cyan
    .hexPolygonResolution(3)
    .hexPolygonMargin(0.3)

    // Arc layer for connections
    .arcsData([])
    .arcColor(d => d.is_threat ? [COLORS.threatDim, COLORS.threat] : [COLORS.safeDim, COLORS.safe])
    .arcStroke(d => d.is_threat ? 0.6 : 0.5) 
    .arcDashLength(d => d.is_threat ? 0.4 : 0.4)
    .arcDashGap(d => d.is_threat ? 0.2 : 0.2)
    .arcDashAnimateTime(d => d.is_threat ? 1500 : 3000)
    .arcAltitudeAutoScale(0.5)
    .onArcHover(arc => {
      globe.controls().autoRotate = !arc;
      document.body.style.cursor = arc ? 'pointer' : 'default';
    })
    .onArcClick(arc => {
      if (!arc) return;
      const modal = document.getElementById('arc-details-modal');
      const content = document.getElementById('arc-details-content');
      if (!modal || !content) return;
      
      content.innerHTML = `
        <div class="arc-detail-header ${arc.is_threat ? 'danger' : 'success'}">
          ${arc.is_threat ? '⚠ THREAT INTERCEPTED' : '✓ SECURE CONNECTION'}
        </div>
        <div class="arc-detail-body">
          <div class="detail-row"><span>User:</span> <strong>${arc.user || 'Unknown'}</strong></div>
          <div class="detail-row"><span>Path:</span> ${arc.source_city} → ${arc.dest_city}</div>
          <div class="detail-row"><span>Type:</span> ${arc.event_type || 'Unknown'}</div>
          ${arc.is_threat ? `<div class="detail-row"><span style="color:var(--magenta)">Score:</span> ${(arc.threat_score * 100).toFixed(1)}%</div>` : ''}
        </div>
      `;
      modal.style.display = 'block';
    })

    // Points layer for server and event locations
    .pointsData([])
    .pointColor(d => d.is_server ? COLORS.cyan : (d.is_threat ? COLORS.threat : COLORS.safe))
    .pointAltitude(d => d.is_server ? 0.08 : 0.02)
    .pointRadius(d => d.is_server ? 0.8 : 0.3)
    .pointsMerge(false)

    // Ring layer for server
    .ringsData([])
    .ringColor(() => t => `rgba(0, 245, 255, ${Math.sqrt(1 - t)})`)
    .ringMaxRadius(3)
    .ringPropagationSpeed(2)
    .ringRepeatPeriod(1500)

    (container);

  globe.pointOfView({ lat: 20, lng: 60, altitude: 2.5 }, 0);
  globe.controls().autoRotate = true;
  globe.controls().autoRotateSpeed = 0.3;
  globe.controls().enableZoom = true;
  globe.controls().minDistance = 150;
  globe.controls().maxDistance = 500;

  pointsData = [{ lat: SERVER.lat, lng: SERVER.lng, is_server: true, label: 'HPE Core' }];
  globe.pointsData(pointsData);
  globe.ringsData([{ lat: SERVER.lat, lng: SERVER.lng }]);

  const scene = globe.scene();
  if (scene) scene.background = null;

  window.addEventListener('resize', () => {
    globe.width(container.offsetWidth);
    globe.height(container.offsetHeight);
  });

  // Attach modal close handler
  const closeModal = document.getElementById('arc-modal-close');
  if (closeModal) {
    closeModal.addEventListener('click', () => {
      document.getElementById('arc-details-modal').style.display = 'none';
      globe.controls().autoRotate = true; // Resume rotation
    });
  }

  return globe;
}

/**
 * Add a connection arc to the globe
 */
export function addArc(eventData, predictionData) {
  if (!globe) return;

  const srcGeo = predictionData?.source_geo || eventData?.source_geo || {};
  const dstGeo = predictionData?.destination_geo || eventData?.destination_geo || {};
  const isThreat = predictionData?.is_threat || false;

  const arc = {
    startLat: srcGeo.lat || 0,
    startLng: srcGeo.lng || 0,
    endLat: dstGeo.lat || SERVER.lat,
    endLng: dstGeo.lng || SERVER.lng,
    is_threat: isThreat,
    user: eventData?.user || '',
    event_type: eventData?.event_type || '',
    source_city: srcGeo.city || 'Unknown',
    dest_city: dstGeo.city || 'Bangalore',
    threat_score: predictionData?.threat_score || 0,
  };

  arcsData.push(arc);

  // Keep max 80 arcs visible
  if (arcsData.length > 80) {
    arcsData = arcsData.slice(-80);
  }

  globe.arcsData([...arcsData]);

  // Add source point
  const srcPoint = {
    lat: srcGeo.lat || 0,
    lng: srcGeo.lng || 0,
    is_threat: isThreat,
    is_server: false,
  };
  pointsData.push(srcPoint);

  // Keep max 100 points
  if (pointsData.length > 100) {
    const serverPoint = pointsData[0]; // Preserve server point
    pointsData = [serverPoint, ...pointsData.slice(-99)];
  }

  globe.pointsData([...pointsData]);

  // Flash ring on threat
  if (isThreat) {
    const currentRings = globe.ringsData();
    currentRings.push({
      lat: srcGeo.lat || 0,
      lng: srcGeo.lng || 0,
    });
    globe.ringsData([...currentRings]);
    globe.ringColor(() => t => `rgba(255, 0, 110, ${Math.sqrt(1 - t)})`);

    // Remove threat ring after animation
    setTimeout(() => {
      const rings = globe.ringsData().filter((r, i) => i === 0);
      globe.ringsData(rings);
      globe.ringColor(() => t => `rgba(0, 245, 255, ${Math.sqrt(1 - t)})`);
    }, 3000);
  }
}

/**
 * Clear all arcs
 */
export function clearArcs() {
  arcsData = [];
  if (globe) globe.arcsData([]);
}

/**
 * Get globe instance
 */
export function getGlobe() {
  return globe;
}
