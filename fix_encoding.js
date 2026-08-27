const fs = require('fs');

const files = [
  'c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/dashboard.html',
  'c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/profile.html',
  'c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/settings.html'
];

for (const file of files) {
  if (fs.existsSync(file)) {
    let content = fs.readFileSync(file, 'utf8');
    
    // Fix BOM if it was encoded as text
    content = content.replace(/Ã¯Â»Â¿/g, ''); 
    content = content.replace(/Ã¯Â»Â¿/g, '');
    
    // Fix UTF-8 bytes that were interpreted as Windows-1252 and saved as UTF-8
    content = content.replace(/Ã¢â‚¬â€œ/g, '—'); // em dash
    content = content.replace(/Ã¢â‚¬Å“/g, '“'); // left double quote
    content = content.replace(/Ã¢â‚¬Â/g, '”'); // right double quote (sometimes Â)
    content = content.replace(/Ã¢â‚¬â„¢/g, '’'); // right single quote
    content = content.replace(/Ã¢â‚¬Ëœ/g, '‘'); // left single quote
    content = content.replace(/Ã‚Â©/g, '©'); // copyright
    content = content.replace(/Ã¢â€ž¢/g, '™'); // trademark
    content = content.replace(/Ã¢â‚¬â€/g, '—'); // alternative em dash encoding
    content = content.replace(/Ã¢â‚¬/g, ''); // leftover corrupted chunks
    
    // Actually, to be very precise for the empty-val spans:
    content = content.replace(/<span class="empty-val">.*?<\/span>/g, '<span class="empty-val">—</span>');

    // Remove BOM at the very beginning if it exists
    if (content.charCodeAt(0) === 0xFEFF) {
      content = content.slice(1);
    }
    
    fs.writeFileSync(file, content, 'utf8');
    console.log('Fixed:', file);
  }
}
