const fs = require('fs');
const path = require('path');

const darkThemeStr = `  /* Dark theme variables */
  --bg-main: #0b0f19;
  --bg-sidebar: #0b0f19;
  --bg-card: #111827;
  --bg-card-hover: #1f2937;
  --border-color: #1f2937;
  --border-light: #1f2937;
  
  --text-h: #f8fafc; /* Headers text */
  --text-b: #cbd5e1; /* Body text */
  --text-m: #94a3b8; /* Muted text */
  --text-s: #64748b; /* Subtle text */
  
  /* State Colors */
  --green: #10b981; /* Secure/Verified */
  --green-bg: rgba(16, 185, 129, 0.1);
  --red: #ef4444; /* Critical */
  --red-bg: rgba(239, 68, 68, 0.1);
  --amber: #f59e0b; /* High */
  --amber-bg: rgba(245, 158, 11, 0.1);
  --yellow: #eab308; /* Medium */
  --yellow-bg: rgba(234, 179, 8, 0.1);
  --gray: #94a3b8; /* Low */
  --gray-bg: rgba(148, 163, 184, 0.1);
  
  --purple: #8b5cf6; /* Quantum */
  --purple-bg: rgba(139, 92, 246, 0.1);`;

const profileDarkStr = `.profile-dropdown {
  position: absolute; top: calc(100% + 8px); right: 0;
  width: 260px; background: var(--bg-card);
  border: 1px solid var(--border-color); border-radius: 14px;
  box-shadow: 0 12px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.05) inset;
  opacity: 0; visibility: hidden;
  transform: translateY(-6px) scale(0.97);
  transition: all .2s ease;
  z-index: 999;
  overflow: hidden;
}
.profile-dropdown.open {
  opacity: 1; visibility: visible;
  transform: translateY(0) scale(1);
}
.pd-header {
  display: flex; align-items: center; gap: 12px;
  padding: 16px;
}
.pd-avatar {
  width: 40px; height: 40px; border-radius: 50%;
  background: linear-gradient(135deg, #047857, #10b981);
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}
.pd-avatar span {
  font-size: 15px; font-weight: 700; color: white;
  font-family: 'Inter', sans-serif;
}
.pd-info { overflow: hidden; }
.pd-name {
  font-size: 14px; font-weight: 600; color: var(--text-h);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.pd-email {
  font-size: 12px; color: var(--text-m); margin-top: 2px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.pd-divider { height: 1px; background: var(--border-color); margin: 0; }
.pd-item {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 16px;
  font-size: 13px; font-weight: 500; color: var(--text-b);
  text-decoration: none; transition: all .15s ease;
  cursor: pointer;
}
.pd-item svg { width: 16px; height: 16px; flex-shrink: 0; stroke-width: 1.5; }
.pd-item:hover { background: var(--bg-card-hover); color: var(--green); }
.pd-logout { color: var(--red); }
.pd-logout:hover { background: var(--red-bg); color: #f87171; }`;

const frontendPath = 'c:/Users/Shravani/Downloads/Cryptoscan_patched/Cryptoscan/frontend';
const files = fs.readdirSync(frontendPath).filter(f => f.endsWith('.html'));

let changed = 0;
for (const file of files) {
  const filePath = path.join(frontendPath, file);
  let content = fs.readFileSync(filePath, 'utf8');
  
  let updated = false;
  
  // Replace variables
  const rootVarsRegex = /\/\* Light theme variables \*\/[\s\S]*?--purple-bg:[^;]+;/;
  if (rootVarsRegex.test(content)) {
    content = content.replace(rootVarsRegex, darkThemeStr);
    updated = true;
  }
  
  // Replace profile dropdown
  const profileRegex = /\.profile-dropdown \{[\s\S]*?\.pd-logout:hover \{[^}]+\}/;
  if (profileRegex.test(content)) {
    content = content.replace(profileRegex, profileDarkStr);
    updated = true;
  }
  
  if (updated) {
    fs.writeFileSync(filePath, content, 'utf8');
    changed++;
    console.log('Updated ' + file);
  }
}
console.log('Total files updated: ' + changed);
