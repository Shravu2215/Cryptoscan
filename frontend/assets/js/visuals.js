/**
 * CryptoScan Visuals Engine
 * Generates and manages dynamic visual graphics (backgrounds, SVGs, charts)
 */

class CryptoVisualsEngine {
  constructor() {
    this.initGlobalBackgrounds();
  }

  /**
   * Initializes the cinematic background graphics on the app layout.
   */
  initGlobalBackgrounds() {
    const layout = document.querySelector('.app-layout');
    if (!layout) return;

    // Check for reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) return;

    // Create background layer container
    const bgLayer = document.createElement('div');
    bgLayer.className = 'visual-bg-layer';

    // Add animated grid
    const grid = document.createElement('div');
    grid.className = 'cyber-grid';
    bgLayer.appendChild(grid);

    // Add cinematic orbs
    const orbs = [
      { color: 'cyan', delay: '0s' },
      { color: 'violet', delay: '-5s' },
      { color: 'magenta', delay: '-10s' }
    ];

    orbs.forEach(orb => {
      const el = document.createElement('div');
      el.className = `glow-orb ${orb.color}`;
      bgLayer.appendChild(el);
    });

    // Add random floating particles
    for (let i = 0; i < 15; i++) {
      const particle = document.createElement('div');
      particle.className = 'particle';
      particle.style.left = `${Math.random() * 100}%`;
      particle.style.top = `${Math.random() * 100}%`;
      particle.style.width = `${Math.random() * 3 + 1}px`;
      particle.style.height = particle.style.width;
      particle.style.animationDelay = `${Math.random() * 8}s`;
      particle.style.animationDuration = `${Math.random() * 5 + 5}s`;
      bgLayer.appendChild(particle);
    }

    // Insert behind everything
    layout.insertBefore(bgLayer, layout.firstChild);
  }

  /**
   * Renders a mock SVG network visualization.
   * Useful for dashboard hero areas.
   * @param {string} containerId ID of the container element
   */
  renderSecurityNetwork(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const svg = `
      <svg width="100%" height="100%" viewBox="0 0 800 400" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="rgba(139, 92, 246, 0.4)" />
            <stop offset="100%" stop-color="transparent" />
          </radialGradient>
        </defs>
        
        <!-- Background Glow -->
        <circle cx="400" cy="200" r="150" fill="url(#glow)" />
        
        <!-- Edges -->
        <g class="edges">
          <line x1="200" y1="200" x2="400" y2="200" class="edge-line" />
          <line x1="400" y1="200" x2="600" y2="200" class="edge-line" />
          <line x1="400" y1="200" x2="400" y2="80" class="edge-line" />
          <line x1="400" y1="200" x2="400" y2="320" class="edge-line" />
          <line x1="200" y1="200" x2="400" y2="80" class="edge-line" />
          <line x1="600" y1="200" x2="400" y2="80" class="edge-line" />
        </g>
        
        <!-- Nodes -->
        <g class="nodes">
          <circle cx="400" cy="200" r="24" class="node-circle node-pulse" />
          <circle cx="200" cy="200" r="16" class="node-circle" />
          <circle cx="600" cy="200" r="16" class="node-circle" />
          <circle cx="400" cy="80" r="16" class="node-circle" />
          <circle cx="400" cy="320" r="16" class="node-circle" />
        </g>
      </svg>
    `;
    container.innerHTML = svg;
    container.classList.add('visual-container');
  }

  /**
   * Renders a blockchain anchoring flow visualization.
   * @param {string} containerId ID of the container element
   */
  renderBlockchainFlow(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    // Abstract blocks
    const svg = `
      <svg width="100%" height="100%" viewBox="0 0 600 200" preserveAspectRatio="xMidYMid meet">
        <!-- Connecting Line -->
        <line x1="100" y1="100" x2="500" y2="100" class="edge-line" />
        
        <!-- Blocks -->
        <g transform="translate(50, 60)">
          <rect width="80" height="80" rx="8" class="bc-block" />
          <text x="40" y="45" text-anchor="middle" class="bc-hash" fill="#cbd5e1">DATA</text>
        </g>
        
        <g transform="translate(260, 60)">
          <rect width="80" height="80" rx="8" class="bc-block" />
          <text x="40" y="45" text-anchor="middle" class="bc-hash" fill="#cbd5e1">HASH</text>
        </g>
        
        <g transform="translate(470, 60)">
          <rect width="80" height="80" rx="8" class="bc-block verified" />
          <text x="40" y="45" text-anchor="middle" class="bc-hash" fill="#10b981">BLOCK</text>
        </g>
      </svg>
    `;
    container.innerHTML = svg;
    container.classList.add('visual-container');
  }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
  window.Visuals = new CryptoVisualsEngine();
});
