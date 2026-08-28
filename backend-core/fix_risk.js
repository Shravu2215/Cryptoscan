const fs = require('fs');
const path = 'c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/risk-migration.html';
let html = fs.readFileSync(path, 'utf8');

// Direct regex replacement of the old merged priority block (handles any line ending)
const oldBlock = /migrationCandidates = Object\.values\(candidateMap\)\.map\(c => \{[\s\S]*?\/\/ Calculate Priority[\s\S]*?let priority = 3;\s*if \(c\.severity === 'CRITICAL' \|\| c\.quantumVulnerable\) priority = 1;\s*else if \(c\.severity === 'HIGH'\) priority = 2;\s*return \{\s*\.\.\.c,\s*fileCount: c\.affectedFiles\.size,\s*priority: priority\s*\};\s*\}\);\s*\/\/ Sort by priority[\s\S]*?migrationCandidates\.sort\([\s\S]*?\}\);/;

const match = html.match(oldBlock);
if (!match) {
  console.error('Could not find old priority block via regex');
  process.exit(1);
}
console.log('Found old block, length:', match[0].length);

const newBlock = `migrationCandidates = Object.values(candidateMap).map(c => {
    // ── Classical Risk Priority (driven purely by severity) ──────────────────
    // P1 = CRITICAL, P2 = HIGH, P3 = MEDIUM / LOW / anything else
    let classicalPriority = 3;
    if (c.severity === 'CRITICAL') classicalPriority = 1;
    else if (c.severity === 'HIGH') classicalPriority = 2;

    // ── Quantum Migration Priority (driven purely by quantum exposure + algo class) ──
    // Asymmetric algorithms (RSA, ECC, DSA, DH) are broken by Shor's algorithm —
    // they get Q1 if quantum-vulnerable. Hash/symmetric weakened by Grover → Q2.
    let quantumPriority = 3;
    if (c.quantumVulnerable) {
      const a = c.algorithm.toLowerCase();
      const isAsymmetric = /rsa|ec|ecdsa|ecdh|ecc|dsa|dh\\b|elgamal|diffie/.test(a);
      quantumPriority = isAsymmetric ? 1 : 2;
    }

    return {
      ...c,
      fileCount: c.affectedFiles.size,
      classicalPriority: classicalPriority,
      quantumPriority: quantumPriority,
      // Legacy 'priority' = classicalPriority so timeline/drawer still work
      priority: classicalPriority
    };
  });

  // Sort classical list: by classicalPriority (1 first), then file count
  migrationCandidates.sort((a,b) => {
    if (a.classicalPriority !== b.classicalPriority) return a.classicalPriority - b.classicalPriority;
    return b.fileCount - a.fileCount;
  });

  // Separate quantum list: quantum-vulnerable only, sorted by quantumPriority
  const quantumCandidates = migrationCandidates.filter(c => c.quantumVulnerable)
    .slice()
    .sort((a,b) => {
      if (a.quantumPriority !== b.quantumPriority) return a.quantumPriority - b.quantumPriority;
      return b.fileCount - a.fileCount;
    });`;

html = html.replace(oldBlock, newBlock);

// Verify the OR is gone
const stillHasOr = html.includes("c.severity === 'CRITICAL' || c.quantumVulnerable");
console.log('Old OR logic removed:', !stillHasOr);
console.log('classicalPriority present:', html.includes('classicalPriority'));
console.log('quantumCandidates present:', html.includes('quantumCandidates'));

fs.writeFileSync(path, html, 'utf8');
console.log('Saved.');
