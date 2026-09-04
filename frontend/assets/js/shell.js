/**
 * CryptoScan Global Shell
 * Injects the global sidebar and topbar into authenticated pages,
 * handles responsive sidebar toggling, and initializes user data.
 */

class AppShell {
  constructor() {
    this.init();
  }

  init() {
    // Determine current page to set active nav item
    const path = window.location.pathname;
    const page = path.split('/').pop() || 'dashboard.html';
    
    // Inject CSS
    if (!document.querySelector('link[href*="global.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'assets/css/global.css';
      document.head.prepend(link);
    }
    if (!document.querySelector('link[href*="visuals.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'assets/css/visuals.css';
      document.head.appendChild(link);
    }

    // Inject Visuals JS
    if (!document.querySelector('script[src*="visuals.js"]')) {
      const script = document.createElement('script');
      script.src = 'assets/js/visuals.js';
      document.body.appendChild(script);
    }

    this.renderSidebar(page);
    this.renderTopbar(page);
    this.bindEvents();
    this.loadUserData();
  }

  renderSidebar(currentPage) {
    const sidebar = document.getElementById('app-sidebar');
    if (!sidebar) return;

    const navItems = [
      { group: 'Overview', items: [
        { name: 'Dashboard', url: 'dashboard.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/>' }
      ]},
      { group: 'Analysis', items: [
        { name: 'Repositories', url: 'repositories.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>' },
        { name: 'Scan', url: 'scan.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/>' },
        { name: 'Findings', url: 'findings.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>' },
        { name: 'CBOM', url: 'cbom.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>' }
      ]},
      { group: 'Security', items: [
        { name: 'Risk & Migration', url: 'risk-migration.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>' },
        { name: 'Verification', url: 'verification.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>' }
      ]},
      { group: 'System', items: [
        { name: 'Profile', url: 'profile.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>' },
        { name: 'Settings', url: 'settings.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>' }
      ]}
    ];

    let navHtml = '';
    navItems.forEach(group => {
      navHtml += `<div class="sb-nav-group"><div class="sb-nav-group-title">${group.group}</div>`;
      group.items.forEach(item => {
        const isActive = currentPage === item.url ? 'active' : '';
        navHtml += `
          <a href="${item.url}" class="sb-nav-item ${isActive}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">${item.icon}</svg>
            <span class="sb-label">${item.name}</span>
          </a>
        `;
      });
      navHtml += `</div>`;
    });

    sidebar.innerHTML = `
      <div class="sb-header">
        <a href="dashboard.html" class="sb-brand">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
          <span class="sb-brand-name">CryptoScan</span>
        </a>
      </div>
      <nav class="sb-content">
        ${navHtml}
      </nav>
      <div class="sb-footer">
        <div class="sb-system-status">
          <div class="indicator"></div>
          <span class="status-text">System Operational</span>
        </div>
        <div class="sb-user">
          <div class="sb-user-avatar" id="sb-user-avatar">U</div>
          <div class="sb-user-info">
            <div class="sb-user-name" id="sb-user-name">User</div>
            <div class="sb-user-role">Security Analyst</div>
          </div>
        </div>
      </div>
    `;
  }

  renderTopbar(currentPage) {
    const topbar = document.getElementById('app-topbar');
    if (!topbar) return;

    // Get page title for breadcrumb
    const titles = {
      'dashboard.html': 'Dashboard',
      'repositories.html': 'Repositories',
      'scan.html': 'Scan Repository',
      'findings.html': 'Findings',
      'cbom.html': 'CBOM',
      'risk-migration.html': 'Risk & Migration',
      'verification.html': 'Verification',
      'profile.html': 'Profile',
      'settings.html': 'Settings'
    };
    const title = titles[currentPage] || 'Overview';

    topbar.innerHTML = `
      <div class="tb-left">
        <button class="mobile-menu-trigger" id="mobile-menu-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h16"/>
          </svg>
        </button>
        <div class="tb-breadcrumbs">
          <span>CryptoScan</span>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/></svg>
          <span class="current">${title}</span>
        </div>
      </div>
      <div class="tb-right">
        <button class="search-trigger">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
          <span>Search</span>
          <kbd>⌘ K</kbd>
        </button>
        <button class="icon-btn" title="Notifications">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
        </button>
        <div style="position: relative;">
          <button class="icon-btn" id="tb-user-btn" title="Account Settings">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l9-5-9-5-9 5 9 5z"/><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14z"/><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l9-5-9-5-9 5 9 5zm0 0l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14zm-4 6v-7.5l4-2.222"/></svg>
          </button>
        </div>
      </div>
    `;
  }

  bindEvents() {
    // Mobile Sidebar Toggle
    const mobileBtn = document.getElementById('mobile-menu-btn');
    if (mobileBtn) {
      mobileBtn.addEventListener('click', () => {
        document.body.classList.toggle('sidebar-open');
      });
    }

    // Topbar user menu toggle (logout)
    const userBtn = document.getElementById('tb-user-btn');
    if (userBtn) {
      userBtn.addEventListener('click', () => {
        if (confirm('Are you sure you want to log out?')) {
          if (window.Auth && window.Auth.logout) {
            window.Auth.logout();
          } else {
            localStorage.removeItem('cs_token');
            localStorage.removeItem('cs_user');
            window.location.href = 'login.html';
          }
        }
      });
    }
  }

  loadUserData() {
    try {
      const u = JSON.parse(localStorage.getItem('cs_user'));
      if (u) {
        const name = u.name || (u.email ? u.email.split('@')[0] : 'User');
        const initial = name.charAt(0).toUpperCase();
        
        const avatarEl = document.getElementById('sb-user-avatar');
        const nameEl = document.getElementById('sb-user-name');
        
        if (avatarEl) avatarEl.textContent = initial;
        if (nameEl) nameEl.textContent = name;
      }
    } catch (e) {
      console.warn('Failed to load user data for shell', e);
    }
  }
}

// Initialize shell on DOM load
document.addEventListener('DOMContentLoaded', () => {
  new AppShell();
});
