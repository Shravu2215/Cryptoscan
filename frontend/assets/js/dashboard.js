/**
 * CryptoScan Dashboard Logic
 * Handles data binding, SVG chart rendering, and empty states.
 */

class CryptoDashboard {
  constructor() {
    this.init();
  }

  init() {
    this.render();
    window.addEventListener('cryptoscan_data_updated', () => this.render());
  }

  render() {
    const data = CryptoEngine.getData();
    const hasData = data.scans && data.scans.length > 0;

    const emptyState = document.getElementById('dash-empty-state');
    const content = document.getElementById('dash-content');

    if (!hasData) {
      if (content) content.style.display = 'none';
      if (emptyState) {
        emptyState.style.display = 'flex';
        this.renderEmptyIllustration(document.querySelector('.empty-illustration'));
      }
      return;
    }

    if (emptyState) emptyState.style.display = 'none';
    if (content) content.style.display = 'flex';

    // Calculate aggregations
    let totalFindings = 0;
    let critCount = 0;
    let highCount = 0;
    let medCount = 0;
    let lowCount = 0;
    let quantumVuln = 0;
    
    const algos = {};
    const events = [];

    // Group to find latest scan per repo
    const latestScansByRepo = {};
    data.scans.forEach(scan => {
      if (!latestScansByRepo[scan.repoId]) {
        latestScansByRepo[scan.repoId] = scan;
      }
      
      // Events should still show history of all scans
      events.push({
        type: 'scan_complete',
        repo: scan.repoName,
        time: scan.timestamp,
        findings: scan.findings ? scan.findings.length : 0
      });
    });

    const latestScans = Object.values(latestScansByRepo);

    latestScans.forEach(scan => {
      totalFindings += (scan.findings ? scan.findings.length : 0);
      critCount += (scan.criticalCount || 0);
      quantumVuln += (scan.quantumCount || 0);

      if (scan.findings) {
        scan.findings.forEach(f => {
          const sev = (f.severity || '').toLowerCase();
          if (sev === 'high') highCount++;
          if (sev === 'medium') medCount++;
          if (sev === 'low') lowCount++;

          const algo = f.algorithm || 'Unknown';
          algos[algo] = (algos[algo] || 0) + 1;
        });
      }
    });

    const latestScan = data.scans[0];
    const score = latestScan && latestScan.findings ? Math.max(0, 100 - (latestScan.criticalCount * 5) - (latestScan.findings.length)) : 100;

    // 1. Hero
    this.renderHeroScore(score);
    if (window.Visuals) {
      window.Visuals.renderSecurityNetwork('hero-network-container');
    }

    // 2. Metrics
    document.getElementById('m-scans').textContent = data.scans.length;
    document.getElementById('m-findings').textContent = totalFindings;
    document.getElementById('m-critical').textContent = critCount;
    document.getElementById('m-quantum').textContent = quantumVuln;

    // Determine status text
    const statusTitle = document.getElementById('hero-status-title');
    const statusDesc = document.getElementById('hero-status-desc');
    if (critCount > 0) {
      statusTitle.textContent = "Critical Risk Detected";
      statusTitle.style.color = "var(--status-danger)";
      statusDesc.textContent = `${critCount} critical cryptographic vulnerabilities require immediate remediation.`;
    } else if (quantumVuln > 0) {
      statusTitle.textContent = "Quantum Risk Warning";
      statusTitle.style.color = "var(--accent-magenta)";
      statusDesc.textContent = "Post-quantum vulnerable algorithms detected. Plan migration.";
    } else {
      statusTitle.textContent = "System Secure";
      statusTitle.style.color = "var(--status-success)";
      statusDesc.textContent = "No critical cryptographic vulnerabilities detected across active repositories.";
    }

    // 3. Charts
    this.renderTrendChart('chart-trend', data.scans);
    this.renderDonutChart('chart-donut', { crit: critCount, high: highCount, med: medCount, low: lowCount }, totalFindings);
    
    // Quantum Readiness (use real data)
    let totalAssets = data.scans.reduce((acc, s) => acc + (s.assetsFound || 0), 0);
    let percentage = 100;
    if (totalAssets > 0) {
      let qReady = Math.max(0, totalAssets - quantumVuln);
      percentage = (qReady / totalAssets) * 100;
    }
    this.renderQuantumChart('chart-quantum', percentage);
    
    this.renderAlgosChart('chart-algos', algos);

    // 4. Lists
    this.renderRecentScans('tb-recent-scans', data.scans);
    this.renderActivityTimeline('activity-timeline', events);
  }

  // =====================================================================
  // HERO SCORE (Radial gradient ring)
  // =====================================================================
  renderHeroScore(score) {
    const container = document.getElementById('hero-score-container');
    if (!container) return;
    
    const circumference = 2 * Math.PI * 50;
    const offset = circumference - (score / 100) * circumference;

    container.innerHTML = `
      <svg width="140" height="140" viewBox="0 0 120 120">
        <defs>
          <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="var(--accent-violet)" />
            <stop offset="50%" stop-color="var(--accent-cyan)" />
            <stop offset="100%" stop-color="var(--accent-pink)" />
          </linearGradient>
          <filter id="scoreGlow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>
        <circle cx="60" cy="60" r="50" fill="none" stroke="var(--border-subtle)" stroke-width="8" />
        <circle cx="60" cy="60" r="50" fill="none" stroke="url(#scoreGrad)" stroke-width="8" 
          stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" 
          stroke-linecap="round" transform="rotate(-90 60 60)" filter="url(#scoreGlow)"
          style="transition: stroke-dashoffset 1.5s ease-out;" />
        <text x="60" y="68" font-size="28" font-weight="700" fill="var(--text-primary)" text-anchor="middle">${score}</text>
        <text x="60" y="85" font-size="10" fill="var(--text-muted)" text-anchor="middle">/ 100</text>
      </svg>
    `;
  }

  // =====================================================================
  // FINDINGS TREND (Area Chart)
  // =====================================================================
  renderTrendChart(containerId, scans) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    // Sort scans by date oldest to newest
    const sorted = [...scans].reverse().slice(-14); // max 14 points
    let dataPoints = sorted.map(s => s.findings ? s.findings.length : 0);
    
    if (dataPoints.length === 1) {
      // Ensure we plot a flat line leading up to the single scan if there's no history
      dataPoints = [0, 0, 0, 0, dataPoints[0]]; 
    } else if (dataPoints.length === 0) {
      dataPoints = [0,0,0,0,0];
    }

    const max = Math.max(...dataPoints, 10);
    const w = container.clientWidth || 600;
    const h = 220;
    
    let pathD = `M 0 ${h} `;
    let lineD = '';
    
    dataPoints.forEach((val, i) => {
      const x = (i / (dataPoints.length - 1)) * w;
      const y = h - ((val / max) * (h - 40)) - 20; // 20px padding
      if (i === 0) {
        pathD += `L ${x} ${y} `;
        lineD += `M ${x} ${y} `;
      } else {
        pathD += `L ${x} ${y} `;
        lineD += `L ${x} ${y} `;
      }
    });
    
    pathD += `L ${w} ${h} Z`;

    container.innerHTML = `
      <svg width="100%" height="100%" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
        <defs>
          <linearGradient id="trendArea" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="rgba(34, 211, 238, 0.3)" />
            <stop offset="100%" stop-color="rgba(34, 211, 238, 0.0)" />
          </linearGradient>
        </defs>
        <!-- Grid lines -->
        <line x1="0" y1="20" x2="${w}" y2="20" stroke="var(--border-subtle)" stroke-width="1" stroke-dasharray="4" />
        <line x1="0" y1="${h/2 + 10}" x2="${w}" y2="${h/2 + 10}" stroke="var(--border-subtle)" stroke-width="1" stroke-dasharray="4" />
        <line x1="0" y1="${h-1}" x2="${w}" y2="${h-1}" stroke="var(--border-subtle)" stroke-width="1" />
        
        <path d="${pathD}" fill="url(#trendArea)" />
        <path d="${lineD}" fill="none" stroke="var(--accent-cyan)" stroke-width="3" style="filter: drop-shadow(0 4px 6px rgba(34,211,238,0.4))" />
        
        ${dataPoints.map((val, i) => {
          const x = (i / (dataPoints.length - 1)) * w;
          const y = h - ((val / max) * (h - 40)) - 20;
          return `<circle cx="${x}" cy="${y}" r="4" fill="var(--bg-main)" stroke="var(--accent-cyan)" stroke-width="2" />`;
        }).join('')}
      </svg>
    `;
  }

  // =====================================================================
  // RISK DISTRIBUTION (Donut)
  // =====================================================================
  renderDonutChart(containerId, risks, total) {
    const container = document.getElementById(containerId);
    const legend = document.getElementById('donut-legend');
    if (!container || !legend) return;

    if (total === 0) {
      container.innerHTML = `<div class="empty-msg" style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-muted)">No Risks Detected</div>`;
      legend.innerHTML = '';
      return;
    }

    const r = 80;
    const circ = 2 * Math.PI * r;
    const center = 110;
    let offset = 0;

    const segments = [
      { id: 'crit', val: risks.crit, color: 'var(--status-danger)', label: 'Critical' },
      { id: 'high', val: risks.high, color: 'var(--status-warning)', label: 'High' },
      { id: 'med', val: risks.med, color: 'var(--status-info)', label: 'Medium' },
      { id: 'low', val: risks.low, color: 'var(--text-muted)', label: 'Low' }
    ];

    let svgCircles = '';
    let legendHtml = '';

    segments.forEach(seg => {
      if (seg.val > 0) {
        const strokeDasharray = `${(seg.val / total) * circ} ${circ}`;
        const strokeDashoffset = -offset;
        offset += (seg.val / total) * circ;

        svgCircles += `<circle cx="${center}" cy="${center}" r="${r}" fill="none" stroke="${seg.color}" stroke-width="20" stroke-dasharray="${strokeDasharray}" stroke-dashoffset="${strokeDashoffset}" transform="rotate(-90 ${center} ${center})" style="transition: all 1s ease" />`;
        
        legendHtml += `
          <div class="legend-item">
            <div class="legend-dot" style="background: ${seg.color}"></div>
            <span style="flex:1">${seg.label}</span>
            <span style="font-weight:600;color:var(--text-primary)">${seg.val}</span>
          </div>
        `;
      }
    });

    container.innerHTML = `
      <svg width="100%" height="220" viewBox="0 0 220 220">
        <circle cx="${center}" cy="${center}" r="${r}" fill="none" stroke="var(--border-subtle)" stroke-width="20" />
        ${svgCircles}
        <text x="${center}" y="${center + 5}" font-size="28" font-weight="700" fill="var(--text-primary)" text-anchor="middle">${total}</text>
        <text x="${center}" y="${center + 25}" font-size="11" fill="var(--text-muted)" text-anchor="middle">Total Findings</text>
      </svg>
    `;
    legend.innerHTML = legendHtml;
  }

  // =====================================================================
  // QUANTUM READINESS (Radial)
  // =====================================================================
  renderQuantumChart(containerId, percentage) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const r = 70;
    const circ = 2 * Math.PI * r;
    const offset = circ - (percentage / 100) * circ;

    container.innerHTML = `
      <svg width="100%" height="220" viewBox="0 0 220 220">
        <defs>
          <radialGradient id="qGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="rgba(236, 72, 153, 0.3)" />
            <stop offset="100%" stop-color="transparent" />
          </radialGradient>
        </defs>
        <circle cx="110" cy="110" r="90" fill="url(#qGlow)" />
        <circle cx="110" cy="110" r="${r}" fill="none" stroke="var(--border-subtle)" stroke-width="12" />
        <circle cx="110" cy="110" r="${r}" fill="none" stroke="var(--accent-magenta)" stroke-width="12" 
          stroke-dasharray="${circ}" stroke-dashoffset="${offset}" 
          stroke-linecap="round" transform="rotate(-90 110 110)" 
          style="filter: drop-shadow(0 0 10px rgba(236,72,153,0.5)); transition: stroke-dashoffset 1.5s ease-out;" />
        
        <text x="110" y="115" font-size="32" font-weight="700" fill="var(--text-primary)" text-anchor="middle">${Math.round(percentage)}%</text>
        <text x="110" y="135" font-size="11" fill="var(--accent-magenta)" text-anchor="middle">Ready</text>
      </svg>
    `;
  }

  // =====================================================================
  // CRYPTO ALGORITHMS (Bars)
  // =====================================================================
  renderAlgosChart(containerId, algos) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const keys = Object.keys(algos).sort((a,b) => algos[b] - algos[a]).slice(0, 5);
    if (keys.length === 0) {
      container.innerHTML = `<div class="empty-msg" style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-muted)">No Algorithms Detected</div>`;
      return;
    }

    const max = Math.max(...Object.values(algos));
    let html = `<div style="display:flex; flex-direction:column; gap:16px; padding: 20px 0;">`;
    
    keys.forEach((key, i) => {
      const val = algos[key];
      const pct = (val / max) * 100;
      // Alternate colors
      const color = i % 2 === 0 ? 'var(--accent-cyan)' : 'var(--accent-violet)';
      
      html += `
        <div style="display:flex; flex-direction:column; gap:6px;">
          <div style="display:flex; justify-content:space-between; font-size:12px; font-weight:600; color:var(--text-secondary)">
            <span>${key}</span>
            <span>${val} usages</span>
          </div>
          <div style="width:100%; height:8px; background:var(--border-subtle); border-radius:4px; overflow:hidden;">
            <div style="height:100%; width:${pct}%; background:${color}; border-radius:4px; box-shadow: 0 0 10px ${color}"></div>
          </div>
        </div>
      `;
    });
    
    html += `</div>`;
    container.innerHTML = html;
  }

  // =====================================================================
  // RECENT SCANS TABLE
  // =====================================================================
  renderRecentScans(tbodyId, scans) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;

    if (scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No scans available</td></tr>`;
      return;
    }

    tbody.innerHTML = scans.slice(0, 5).map(s => {
      const findingsCount = s.findings ? s.findings.length : 0;
      const critCount = s.criticalCount || 0;
      let badge = `<span class="badge badge-info">Secure</span>`;
      if (critCount > 0) badge = `<span class="badge badge-danger">Critical</span>`;
      else if (findingsCount > 0) badge = `<span class="badge badge-warning">Issues Found</span>`;

      return `
        <tr>
          <td>
            <div class="repo-name-cell">
              <div class="repo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg></div>
              ${s.repoName}
            </div>
          </td>
          <td style="color:var(--text-muted)">${s.timestamp.split(',')[0]}</td>
          <td class="font-mono">${findingsCount}</td>
          <td>${badge}</td>
          <td><span class="badge badge-success">Completed</span></td>
        </tr>
      `;
    }).join('');
  }

  // =====================================================================
  // ACTIVITY TIMELINE
  // =====================================================================
  renderActivityTimeline(containerId, events) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (events.length === 0) {
      container.innerHTML = `<div class="empty-msg" style="color:var(--text-muted)">No activity yet</div>`;
      return;
    }

    container.innerHTML = events.slice(0, 5).map((ev, i) => {
      const dotClass = ev.findings > 0 ? 'pink' : 'cyan';
      return `
        <div class="tl-item">
          <div class="tl-dot ${dotClass}"></div>
          <div class="tl-time">${ev.time}</div>
          <div class="tl-desc">Scan Completed: ${ev.repo}</div>
          <div class="tl-sub">${ev.findings} cryptographic assets mapped.</div>
        </div>
      `;
    }).join('');
  }

  // =====================================================================
  // EMPTY STATE ILLUSTRATION (SVG)
  // =====================================================================
  renderEmptyIllustration(container) {
    if (!container) return;
    container.innerHTML = `
      <svg width="100%" height="100%" viewBox="0 0 240 240">
        <defs>
          <radialGradient id="emptyGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="rgba(139, 92, 246, 0.2)" />
            <stop offset="100%" stop-color="transparent" />
          </radialGradient>
        </defs>
        <circle cx="120" cy="120" r="100" fill="url(#emptyGlow)" />
        <path d="M70 120 L120 70 L170 120 L120 170 Z" fill="none" stroke="var(--accent-violet)" stroke-width="2" stroke-dasharray="4" style="animation: dashFlow 10s linear infinite;" />
        <circle cx="120" cy="120" r="20" fill="var(--bg-surface-active)" stroke="var(--accent-cyan)" stroke-width="3" style="filter: drop-shadow(0 0 10px rgba(34,211,238,0.5))" />
        <circle cx="70" cy="120" r="8" fill="var(--accent-pink)" />
        <circle cx="170" cy="120" r="8" fill="var(--accent-pink)" />
        <circle cx="120" cy="70" r="8" fill="var(--accent-cyan)" />
        <circle cx="120" cy="170" r="8" fill="var(--accent-cyan)" />
      </svg>
    `;
  }
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  window.Dashboard = new CryptoDashboard();
});
