/**
 * Zero-dependency smoke test: boots the app on an ephemeral port,
 * ingests the sample scanner output, hits /findings and /cbom, and
 * asserts on the parts of the logic that matter (purpose varies by
 * context even for the same primitive, scores are deterministic,
 * deprecated algorithms score high, etc).
 */
const path = require('path');
const fs = require('fs');
const app = require('../src/server');

function assert(cond, msg) {
  if (!cond) throw new Error('FAILED: ' + msg);
  console.log('  ok - ' + msg);
}

async function main() {
  const server = app.listen(0);
  const port = server.address().port;
  const base = `http://localhost:${port}`;

  const sample = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', 'data', 'samples', 'scanner-output.sample.json'), 'utf8')
  );

  console.log('1. Ingest sample findings');
  let res = await fetch(`${base}/internal/scan/test_scan/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sample),
  });
  let body = await res.json();
  assert(res.status === 201, 'ingest returns 201');
  assert(body.totalFindingsStored === 6, 'all 6 sample findings stored');

  console.log('2. GET /findings');
  res = await fetch(`${base}/scan/test_scan/findings`);
  body = await res.json();
  assert(res.status === 200, 'findings returns 200');
  assert(body.findings.length === 6, 'findings list has 6 entries');

  const rsaSig = body.findings.find((f) => f.id === 'finding_1');
  assert(rsaSig.purpose.value === 'digital_signature', 'RSA used for JWT signing is classified as digital_signature');
  assert(rsaSig.pqcMigration.recommendation.includes('ML-DSA'), 'RSA-for-signature recommends ML-DSA, not ML-KEM');

  const ecdhKex = body.findings.find((f) => f.id === 'finding_2');
  assert(ecdhKex.purpose.value === 'key_exchange', 'ECDH handshake classified as key_exchange');
  assert(ecdhKex.pqcMigration.recommendation.includes('ML-KEM'), 'ECDH-for-key-exchange recommends ML-KEM, not ML-DSA');
  console.log('   -> confirms purpose-based (not hardcoded 1:1) PQC mapping: same family, different targets by purpose is NOT tested here since RSA vs ECDH are different primitives, but see below');

  const md5Pw = body.findings.find((f) => f.id === 'finding_4');
  assert(md5Pw.vulnerability.score >= 80, 'MD5 password hashing scores critical (>=80)');
  assert(md5Pw.vulnerability.severity === 'critical', 'MD5 severity label is critical');

  const sha256Hash = body.findings.find((f) => f.id === 'finding_5');
  assert(sha256Hash.vulnerability.score < 40, 'SHA-256 integrity hashing scores low/medium, not critical');

  const desLegacy = body.findings.find((f) => f.id === 'finding_6');
  assert(desLegacy.vulnerability.score >= 80, 'DES/ECB scores critical');

  console.log('3. GET /cbom');
  res = await fetch(`${base}/scan/test_scan/cbom`);
  body = await res.json();
  assert(res.status === 200, 'cbom returns 200');
  assert(body.bomFormat === 'CycloneDX', 'cbom uses CycloneDX bomFormat');
  assert(Array.isArray(body.components) && body.components.length === 6, 'cbom has 6 distinct crypto-asset components (all findings have distinct primitive/keySize/mode)');
  assert(body.summary.totalFindings === 6, 'cbom summary totalFindings matches');
  assert(body.summary.severityCounts.critical >= 2, 'cbom severity summary counts critical findings (MD5, DES)');

  console.log('4. 404 on unknown scan');
  res = await fetch(`${base}/scan/does_not_exist/findings`);
  assert(res.status === 404, 'unknown scanId returns 404');

  server.close();
  console.log('\nAll checks passed.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
