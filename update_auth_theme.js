const fs = require('fs');
const path = require('path');

const authDarkVars = `:root {
  --green: #10b981;
  --green-light: #34d399;
  --green-bg: rgba(16, 185, 129, 0.1);
  --green-glow: rgba(16, 185, 129, 0.25);
  --red: #ef4444;
  --red-bg: rgba(239, 68, 68, 0.1);
  --amber: #f59e0b;
  --text-h: #f8fafc;
  --text-b: #cbd5e1;
  --text-m: #94a3b8;
  --text-s: #64748b;
  --border: #1f2937;
  --border-focus: #10b981;
  --bg: #0b0f19;
  --card: #111827;
  --t: .2s ease;
}`;

const filesToUpdate = ['index.html', 'login.html', 'signup.html'];

function updateAuthTheme(baseDir) {
  let changed = 0;
  for (const file of filesToUpdate) {
    const filePath = path.join(baseDir, file);
    if (!fs.existsSync(filePath)) continue;
    
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Replace variables
    const rootVarsRegex = /:root\s*\{[\s\S]*?--t: \.2s ease;\s*\}/;
    if (rootVarsRegex.test(content)) {
      content = content.replace(rootVarsRegex, authDarkVars);
      fs.writeFileSync(filePath, content, 'utf8');
      changed++;
      console.log('Updated ' + file + ' in ' + baseDir);
    }
  }
  return changed;
}

updateAuthTheme('c:/Users/Shravani/Downloads/Cryptoscan-main/frontend');
updateAuthTheme('c:/Users/Shravani/Downloads/Cryptoscan_patched/Cryptoscan/frontend');
