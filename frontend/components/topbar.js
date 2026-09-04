class AppTopbar extends HTMLElement {
  connectedCallback() {
    const titles = {
      'dashboard.html': { title: 'Dashboard', sub: 'Overview of your security posture' },
      'cbom.html': { title: 'CBOM Inventory', sub: 'Cryptographic Bill of Materials' },
      'findings.html': { title: 'Security Findings', sub: 'Vulnerabilities and warnings' },
      'risk-migration.html': { title: 'Risk & Migration', sub: 'Post-quantum readiness' },
      'scan.html': { title: 'Scan Repository', sub: 'Analyze a new codebase' },
      'verification.html': { title: 'Verify Integrity', sub: 'Cryptographic verification of scans' }
    };
    
    const currentPath = window.location.pathname.split('/').pop() || 'dashboard.html';
    const pageInfo = titles[currentPath] || { title: 'CryptoScan', sub: 'Security platform' };

    this.innerHTML = `
      <header class="topbar">
        <div class="tb-left">
          <div class="tb-title">${pageInfo.title}</div>
          <div class="tb-sub">${pageInfo.sub}</div>
        </div>
        <div class="tb-right">
          <button class="btn-sec" onclick="window.location.href='scan.html'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:16px;height:16px"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            New Scan
          </button>
          
          <div class="profile-avatar-wrap" id="profile-wrap">
            <button class="profile-avatar" id="profile-btn" onclick="toggleProfileMenu()">
              <span class="profile-initials" id="user-initials">U</span>
            </button>
            
            <div class="profile-dropdown" id="profile-menu">
              <div class="pd-header">
                <div class="pd-avatar"><span id="pd-initials">U</span></div>
                <div class="pd-info">
                  <div class="pd-name" id="pd-name">User Name</div>
                  <div class="pd-email" id="pd-email">user@example.com</div>
                </div>
              </div>
              <div class="pd-divider"></div>
              <a href="profile.html" class="pd-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                My Profile
              </a>
              <a href="settings.html" class="pd-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                Settings
              </a>
              <div class="pd-divider"></div>
              <div class="pd-item pd-logout" onclick="logout()">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                Sign Out
              </div>
            </div>
          </div>
        </div>
      </header>
    `;

    // Populate user info if available
    setTimeout(() => {
      if (typeof window.CryptoEngine !== 'undefined') {
        const u = window.CryptoEngine.getUser();
        if (u) {
          const init = u.name ? u.name.charAt(0).toUpperCase() : 'U';
          const nameEl = document.getElementById('pd-name');
          const emailEl = document.getElementById('pd-email');
          const init1 = document.getElementById('user-initials');
          const init2 = document.getElementById('pd-initials');
          if (nameEl) nameEl.textContent = u.name;
          if (emailEl) emailEl.textContent = u.email;
          if (init1) init1.textContent = init;
          if (init2) init2.textContent = init;
        }
      }
    }, 100);
  }
}
customElements.define('app-topbar', AppTopbar);

function toggleProfileMenu() {
  const menu = document.getElementById('profile-menu');
  if (menu) {
    menu.classList.toggle('open');
  }
}

// Close menu when clicking outside
document.addEventListener('click', (e) => {
  const wrap = document.getElementById('profile-wrap');
  if (wrap && !wrap.contains(e.target)) {
    const menu = document.getElementById('profile-menu');
    if (menu) menu.classList.remove('open');
  }
});

function logout() {
  localStorage.removeItem('cs_auth_token');
  window.location.href = 'login.html';
}
