/**
 * Loads the sample scanner output into a running instance of the service
 * via the ingest endpoint, so you can immediately try:
 *   GET /scan/demo_scan_1/findings
 *   GET /scan/demo_scan_1/cbom
 *
 * Usage: npm start (in one terminal), then npm run seed (in another).
 */
const path = require('path');
const fs = require('fs');

const BASE_URL = process.env.BASE_URL || 'http://localhost:4003';
const SCAN_ID = process.env.SCAN_ID || 'demo_scan_1';

async function main() {
  const samplePath = path.join(__dirname, '..', '..', 'data', 'samples', 'scanner-output.sample.json');
  const payload = JSON.parse(fs.readFileSync(samplePath, 'utf8'));

  const res = await fetch(`${BASE_URL}/internal/scan/${SCAN_ID}/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const body = await res.json();
  if (!res.ok) {
    console.error('Seed failed:', body);
    process.exit(1);
  }
  console.log(`Seeded scan "${SCAN_ID}":`, body);
  console.log(`Try:  curl ${BASE_URL}/scan/${SCAN_ID}/findings`);
  console.log(`Try:  curl ${BASE_URL}/scan/${SCAN_ID}/cbom`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
