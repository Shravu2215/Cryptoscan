const fs = require('fs');
const html = fs.readFileSync('c:/Users/Shravani/Downloads/Cryptoscan-main/frontend/risk-migration.html', 'utf8');
const checks = [
  ['classicalPriority', 'classicalPriority field'],
  ['quantumPriority', 'quantumPriority field'],
  ['quantumCandidates', 'quantumCandidates variable'],
  ['recommendations-list-classical', 'Classical section HTML'],
  ['recommendations-list-quantum', 'Quantum section HTML'],
  ['qp1-count', 'Quantum P1 count badge'],
  ['qp2-count', 'Quantum P2 count badge'],
  ['makeRecCard', 'makeRecCard helper fn'],
  ['Q1 — Asymmetric', 'Q1 label'],
  ['Q2 — Hash/Sym', 'Q2 label'],
  ['Shor-Broken', 'Shor-Broken label'],
  ['Grover-Weakened', 'Grover-Weakened label'],
  ['Classical Risk Priority', 'Classical sidebar header'],
  ['Quantum Migration Priority', 'Quantum sidebar header'],
  ['Classical Risk — Migration Recommendations', 'Classical section title'],
  ['Quantum Migration — Priority Queue', 'Quantum section title'],
];
let allOk = true;
for (const [token, label] of checks) {
  const found = html.includes(token);
  console.log((found ? '✅' : '❌'), label);
  if (!found) allOk = false;
}
const hasOldOr = html.includes("c.severity === 'CRITICAL' || c.quantumVulnerable");
console.log(hasOldOr ? '❌ OLD OR LOGIC STILL PRESENT' : '✅ Old merged OR logic removed');
if (hasOldOr) allOk = false;
console.log('\nFinal sanity check:', allOk ? 'PASSED ✅' : 'FAILED ❌');
