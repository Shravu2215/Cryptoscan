class AppSidebar extends HTMLElement {
  connectedCallback() {
    const currentPath = window.location.pathname.split('/').pop() || 'dashboard.html';
    
    this.innerHTML = `
      <aside class="sb">
        <div class="sb-brand">
          <div class="sb-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"></path>
            </svg>
          </div>
          <div class="sb-name">Crypto<span>Scan</span></div>
        </div>
        <nav class="sb-nav">
          <a href="dashboard.html" class="nav-item ${currentPath === 'dashboard.html' ? 'active' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
            Dashboard
          </a>
          <a href="scan.html" class="nav-item ${currentPath === 'scan.html' ? 'active' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            Scan & Repositories
          </a>
          <a href="cbom.html" class="nav-item ${currentPath === 'cbom.html' ? 'active' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
            CBOM Inventory
          </a>
          <a href="findings.html" class="nav-item ${currentPath === 'findings.html' ? 'active' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
            Security Findings
          </a>
          <a href="risk-migration.html" class="nav-item ${currentPath === 'risk-migration.html' ? 'active' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
            Risk & Migration
          </a>
          
          <div class="sb-nav-divider"></div>
          <div style="padding: 0 12px 8px; font-size: 10px; font-weight: 700; color: var(--text-s); text-transform: uppercase; letter-spacing: 0.5px;">Integrity</div>
          
          <a href="verification.html" class="nav-item ${currentPath === 'verification.html' ? 'active' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            Verify Integrity
          </a>
        </nav>
      </aside>
    `;
  }
}
customElements.define('app-sidebar', AppSidebar);
