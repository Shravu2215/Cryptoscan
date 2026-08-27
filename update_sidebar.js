const fs = require('fs');
const path = require('path');

const profileLinkHtml = `    <a class="nav-item" href="profile.html">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
      Profile
    </a>
  </nav>`;

function updateDirectory(dirPath) {
    const files = fs.readdirSync(dirPath);
    for (const file of files) {
        if (!file.endsWith('.html') || file === 'profile.html') continue;
        const filePath = path.join(dirPath, file);
        let content = fs.readFileSync(filePath, 'utf8');
        
        if (content.includes('href="settings.html"') && !content.includes('href="profile.html"')) {
            content = content.replace("</nav>", profileLinkHtml);
            fs.writeFileSync(filePath, content, 'utf8');
            console.log('Updated ' + file + ' in ' + dirPath);
        }
    }
}

updateDirectory('c:/Users/Shravani/Downloads/Cryptoscan-main/frontend');
updateDirectory('c:/Users/Shravani/Downloads/Cryptoscan_patched/Cryptoscan/frontend');
