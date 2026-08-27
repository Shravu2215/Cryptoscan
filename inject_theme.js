const fs = require('fs');
const glob = require('fs').readdirSync('c:/Users/Shravani/Downloads/Cryptoscan-main/frontend').filter(f => f.endsWith('.html'));

const lightModeCss = `
    :root.light-mode {
      --bg-main: #f8fafc;
      --bg-sidebar: #ffffff;
      --bg-card: #ffffff;
      --bg-card-hover: #f1f5f9;
      --border-color: #e2e8f0;
      --border-light: #e2e8f0;

      --text-h: #0f172a;
      --text-b: #334155;
      --text-m: #475569;
      --text-s: #64748b;
    }
`;

const toggleBtnHtml = `
        <button class="theme-toggle" id="theme-btn" title="Toggle Theme" style="background:transparent;border:none;color:var(--text-m);cursor:pointer;display:flex;align-items:center;justify-content:center;padding:8px;border-radius:var(--r-sm);transition:all 0.2s;margin-right:16px;">
          <svg id="theme-icon-moon" style="width:20px;height:20px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"></path></svg>
          <svg id="theme-icon-sun" style="width:20px;height:20px;display:none;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
        </button>
`;

for (const file of glob) {
  const fp = 'c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/' + file;
  let content = fs.readFileSync(fp, 'utf8');

  // Inject light mode CSS
  if (!content.includes(':root.light-mode')) {
    content = content.replace(/(:root\s*\{[^}]*\})/, '$1' + lightModeCss);
  }

  // Inject Theme Toggle Button before profile button
  if (!content.includes('id="theme-btn"')) {
    content = content.replace(/<button class="profile-avatar" id="profile-btn"/, toggleBtnHtml + '        <button class="profile-avatar" id="profile-btn"');
  }

  // Also append logic for early theme application to avoid flicker (inline in head)
  if (!content.includes('initTheme')) {
    const earlyScript = `
  <script>
    function initTheme() {
      if (localStorage.getItem('cs_theme') === 'light') {
        document.documentElement.classList.add('light-mode');
      }
    }
    initTheme();
  </script>`;
    content = content.replace(/<\/title>/, '</title>' + earlyScript);
  }

  fs.writeFileSync(fp, content, 'utf8');
}

// Add toggle logic to engine.js
let engineFp = 'c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/engine.js';
let engineContent = fs.readFileSync(engineFp, 'utf8');
if (!engineContent.includes('// Theme Toggle Logic')) {
  engineContent += `

// Theme Toggle Logic
window.addEventListener('DOMContentLoaded', () => {
  const tBtn = document.getElementById('theme-btn');
  const iconMoon = document.getElementById('theme-icon-moon');
  const iconSun = document.getElementById('theme-icon-sun');
  
  function updateThemeUI() {
    const isLight = document.documentElement.classList.contains('light-mode');
    if (iconMoon && iconSun) {
      iconMoon.style.display = isLight ? 'none' : 'block';
      iconSun.style.display = isLight ? 'block' : 'none';
    }
  }

  if (tBtn) {
    updateThemeUI();
    tBtn.addEventListener('click', () => {
      document.documentElement.classList.toggle('light-mode');
      const isLight = document.documentElement.classList.contains('light-mode');
      localStorage.setItem('cs_theme', isLight ? 'light' : 'dark');
      updateThemeUI();
    });
  }
});
`;
  fs.writeFileSync(engineFp, engineContent, 'utf8');
}

console.log('Successfully injected Light Mode logic!');
