const fs = require('fs');
const path = require('path');

const pages = [
  'dashboard.html',
  'repositories.html',
  'scan.html',
  'findings.html',
  'cbom.html',
  'risk-migration.html',
  'verification.html',
  'profile.html',
  'settings.html'
];

const dir = path.join(__dirname, 'frontend');

for (const file of pages) {
  const p = path.join(dir, file);
  let content = fs.readFileSync(p, 'utf8');

  // 1. Inject global.css right before </head>
  if (!content.includes('global.css')) {
    content = content.replace('</head>', '  <link rel="stylesheet" href="assets/css/global.css">\n</head>');
  }

  // 2. Wrap body
  if (!content.includes('<div class="app-layout">')) {
    content = content.replace('<body>', '<body>\n<div class="app-layout">');
  }

  // 3. Replace Sidebar
  content = content.replace(/<aside class="sb">[\s\S]*?<\/aside>/, '<aside class="app-sidebar" id="app-sidebar"></aside>');

  // 4. Remove Header (we'll inject it inside app-main)
  content = content.replace(/<header class="topbar">[\s\S]*?<\/header>/, '');

  // 5. Replace <main class="main">
  content = content.replace(/<main class="main">/, '<div class="app-main">\n  <header class="app-topbar" id="app-topbar"></header>\n  <main class="app-page-container">');

  // 6. Close containers at the end
  if (!content.includes('</main>\n</div>')) {
    content = content.replace(/<\/main>/, '</main>\n</div>');
  }

  // 7. Close app-layout and inject shell.js
  if (!content.includes('assets/js/shell.js')) {
    content = content.replace(/<\/body>/, '</div>\n<script src="assets/js/shell.js"></script>\n</body>');
  }

  fs.writeFileSync(p, content, 'utf8');
  console.log(`Migrated ${file}`);
}
