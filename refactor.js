const fs = require('fs');
const path = require('path');

const files = [
  'dashboard.html',
  'scan.html',
  'cbom.html',
  'findings.html',
  'risk-migration.html',
  'verification.html',
  'profile.html',
  'settings.html',
  'repositories.html'
];

const componentsHTML = `
<script src="components/sidebar.js"></script>
<script src="components/topbar.js"></script>
</body>`;

for (const file of files) {
  const filePath = path.join(__dirname, 'frontend', file);
  if (!fs.existsSync(filePath)) continue;

  let content = fs.readFileSync(filePath, 'utf-8');

  // 1. Remove embedded styles (assuming main block)
  content = content.replace(/<style>[\s\S]*?<\/style>/g, '');
  
  // 2. Add link to global CSS in head if missing
  if (!content.includes('assets/css/global.css')) {
    content = content.replace('</head>', '  <link rel="stylesheet" href="assets/css/global.css">\n</head>');
  }

  // 3. Replace aside and header with components
  content = content.replace(/<aside[^>]*class="sb"[^>]*>[\s\S]*?<\/aside>/, '<app-sidebar></app-sidebar>');
  // Sometimes it's class="app-sidebar"
  content = content.replace(/<aside[^>]*id="app-sidebar"[^>]*>[\s\S]*?<\/aside>/, '<app-sidebar></app-sidebar>');
  
  content = content.replace(/<header[^>]*class="topbar"[^>]*>[\s\S]*?<\/header>/, '<app-topbar></app-topbar>');
  // Sometimes it's class="app-topbar"
  content = content.replace(/<header[^>]*id="app-topbar"[^>]*>[\s\S]*?<\/header>/, '<app-topbar></app-topbar>');

  // 4. Inject component scripts before body closing
  if (!content.includes('components/sidebar.js')) {
    content = content.replace('</body>', componentsHTML);
  }

  // Fix main container if needed
  content = content.replace(/<div class="main">/, '<div class="app-main">');
  if (!content.includes('class="app-layout"')) {
    // Wrap body content in app-layout
    content = content.replace(/<body>\s*/, '<body>\n<div class="app-layout">\n');
    content = content.replace(/<\/body>/, '\n</div>\n</body>');
  }

  fs.writeFileSync(filePath, content, 'utf-8');
  console.log(`Refactored ${file}`);
}
