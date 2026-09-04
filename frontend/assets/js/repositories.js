/**
 * Repositories Page Logic
 */

class RepositoriesPage {
  constructor() {
    this.allScans = [];
    this.repositories = [];
    this.repos = [];
    this.currentFilter = 'ALL';
    this.searchQuery = '';
    
    this.init();
  }

  init() {
    // 1. Load data from CryptoEngine
    const data = CryptoEngine ? CryptoEngine.getData() : { repositories: [], scans: [] };
    this.allScans = data.scans || [];
    this.repositories = data.repositories || [];

    // 2. Determine latest scan per repository
    const latestByRepo = {};
    this.allScans.forEach(scan => {
      const repoId = scan.repoId;
      if (!latestByRepo[repoId] || new Date(scan.timestamp) > new Date(latestByRepo[repoId].timestamp)) {
        latestByRepo[repoId] = scan;
      }
    });

    // 3. Build repo list with aggregated metrics
    this.repos = this.repositories.map(repo => {
      const latestScan = latestByRepo[repo.id];
      const metrics = latestScan ? this.calculateScoreAndRisk(latestScan) : { score: 100, risk: 'HEALTHY', counts: { critical:0, high:0, medium:0, low:0 }, quantumReadyPct: 100, lastScan: '' };
      return {
        ...repo,
        score: metrics.score,
        risk: metrics.risk,
        counts: metrics.counts,
        quantumReadyPct: metrics.quantumReadyPct || 100,
        lastScan: latestScan ? new Date(latestScan.timestamp).toLocaleDateString() : ''
      };
    });

    // 4. Attach listeners
    this.attachListeners();

    // 5. Render
    this.renderMetrics();
    this.renderGrid();
  }

  attachListeners() {
    const searchInput = document.getElementById('repo-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase();
        this.renderGrid();
      });
    }

    const filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        filterBtns.forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
        this.currentFilter = e.target.dataset.filter;
        this.renderGrid();
      });
    });
  }

  calculateScoreAndRisk(scan) {
    if (!scan || !scan.findings) return { score: 100, risk: 'HEALTHY' };
    
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    scan.findings.forEach(f => {
      const sev = (f.severity || '').toLowerCase();
      if (sev === 'critical') critical++;
      else if (sev === 'high') high++;
      else if (sev === 'medium') medium++;
      else low++;
    });

    let deduction = (critical * 20) + (high * 10) + (medium * 5) + (low * 2);
    if (scan.quantumCount > 0) deduction += 15;

    let score = 100 - deduction;
    if (score < 0) score = 0;

    let risk = 'HEALTHY';
    if (critical > 0) risk = 'CRITICAL';
    else if (high > 0 || medium > 0 || scan.quantumCount > 0) risk = 'ATTENTION';

    return { score, risk, counts: { critical, high, medium, low } };
  }

  renderMetrics() {
    let total = this.repos.length;
    let healthy = 0;
    let attention = 0;
    let critical = 0;

    this.repos.forEach(repo => {
      const risk = repo.risk;
      if (risk === 'HEALTHY') healthy++;
      else if (risk === 'ATTENTION') attention++;
      else if (risk === 'CRITICAL') critical++;
    });

    document.getElementById('metric-total').textContent = total;
    document.getElementById('metric-healthy').textContent = healthy;
    document.getElementById('metric-attention').textContent = attention;
    document.getElementById('metric-critical').textContent = critical;
  }

  renderScoreRing(score) {
    const radius = 28;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;
    
    let color = 'var(--status-success)';
    if (score < 50) color = 'var(--status-danger)';
    else if (score < 85) color = 'var(--status-warning)';

    return `
      <svg viewBox="0 0 64 64" width="64" height="64">
        <circle cx="32" cy="32" r="${radius}" fill="none" stroke="var(--border-subtle)" stroke-width="4" />
        <circle cx="32" cy="32" r="${radius}" fill="none" stroke="${color}" stroke-width="4" 
          stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" 
          stroke-linecap="round" transform="rotate(-90 32 32)"
          style="transition: stroke-dashoffset 1s ease-out;" />
        <text x="32" y="36" font-size="16" font-weight="700" fill="var(--text-primary)" text-anchor="middle">${score}</text>
      </svg>
    `;
  }

  renderGrid() {
    const grid = document.getElementById('repo-grid');
    const emptyState = document.getElementById('repo-empty-state');
    
    // Show empty state if no repositories exist
    if (this.repos.length === 0) {
      grid.style.display = 'none';
      emptyState.style.display = 'flex';
      return;
    }

    // Apply search and filter
    const filtered = this.repos.filter(repo => {
      const matchSearch = repo.name.toLowerCase().includes(this.searchQuery);
      let matchFilter = true;
      if (this.currentFilter !== 'ALL') {
        const repoStatus = repo.risk || 'HEALTHY';
        if (repoStatus !== this.currentFilter) matchFilter = false;
      }
      return matchSearch && matchFilter;
    });

    if (filtered.length === 0) {
      grid.style.display = 'block';
      grid.innerHTML = `<div style="padding: 40px; text-align: center; color: var(--text-muted); width: 100%; grid-column: 1 / -1;">No repositories match your filters.</div>`;
      emptyState.style.display = 'none';
      return;
    }

    emptyState.style.display = 'none';
    grid.style.display = 'grid';
    grid.innerHTML = '';

    filtered.forEach(repo => {
      const score = repo.score || 100;
      const counts = repo.counts || { critical: 0, high: 0, medium: 0, low: 0 };
      const qPct = repo.quantumReadyPct || 100;

      const card = document.createElement('div');
      card.className = 'repo-card';
      
      card.innerHTML = `
        <div class="rc-top">
          <div class="rc-info">
            <div class="rc-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
            </div>
            <div class="rc-text">
              <div class="rc-name">${repo.name}</div>
              <div class="rc-source">GitHub / Workspace</div>
            </div>
          </div>
          <div class="rc-score-container">
            ${this.renderScoreRing(score)}
          </div>
        </div>

        <div class="rc-findings">
          <div class="finding-badge fb-crit"><span class="count">${counts.critical}</span><span class="lbl">Critical</span></div>
          <div class="finding-badge fb-high"><span class="count">${counts.high}</span><span class="lbl">High</span></div>
          <div class="finding-badge fb-med"><span class="count">${counts.medium}</span><span class="lbl">Medium</span></div>
          <div class="finding-badge fb-low"><span class="count">${counts.low}</span><span class="lbl">Low</span></div>
        </div>

        <div class="rc-meta">
          <div class="meta-item"><span class="meta-lbl">Quantum Readiness</span><span class="meta-val ${qPct === 100 ? 'quantum-ready' : ''}">${qPct}%</span></div>
          <div class="meta-item" style="text-align: right;"><span class="meta-lbl">Last Scan</span><span class="meta-val">${repo.lastScan || ''}</span></div>
        </div>

        <div class="rc-actions">
          <a href="findings.html?repo=${encodeURIComponent(repo.name)}" class="btn-rc-primary">View Repository</a>
          <a href="scan.html" class="btn-rc-secondary">Scan Again</a>
        </div>
      `;
      
      grid.appendChild(card);
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.RepositoriesPageInstance = new RepositoriesPage();
});
