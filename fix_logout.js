const fs = require('fs');
const glob = require('fs').readdirSync('c:/Users/Shravani/Downloads/Cryptoscan-main/frontend').filter(f => f.endsWith('.html'));

for (const file of glob) {
  const fp = 'c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/' + file;
  let content = fs.readFileSync(fp, 'utf8');
  content = content.replace(/href=\"#\" onclick=\"event\.preventDefault\(\); Auth\.logout\(\);\"/g, "href=\"javascript:void(0)\" onclick=\"if(typeof Auth !== 'undefined'){Auth.logout();}else{localStorage.clear();window.location.href='login.html';}\"");
  fs.writeFileSync(fp, content, 'utf8');
}

// Remove mock data from profile.html
const pFp = 'c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/profile.html';
let pContent = fs.readFileSync(pFp, 'utf8');
pContent = pContent.replace(/>User Name</g, '></');
pContent = pContent.replace(/>Security Analyst</g, '></');
pContent = pContent.replace(/>user@example\.com</g, '></');
fs.writeFileSync(pFp, pContent, 'utf8');

console.log('Fixed logout links and removed mock data');
