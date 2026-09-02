const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { buildCbom } = require('./src/services/cbomGenerator');
const { anchorScan } = require('../blockchain-module/scripts/anchor');
const { verifyScan } = require('../blockchain-module/scripts/verify');

async function test() {
  const scan = await prisma.scan.findFirst();
  if(!scan) return console.log('no scan');
  let dbFindings = await prisma.finding.findMany({ where: { scanId: scan.id }, orderBy: { id: 'asc' } });
  const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      algorithm: f.algorithm,
      severity: f.severity,
      quantumStatus: f.quantumStatus,
      usage: f.usage,
      recommendation: f.recommendation
  }));
  const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, createdAt: scan.createdAt, rawFindings });
  const contentBuffer = Buffer.from(JSON.stringify(cbom));
  
  try {
    console.log('Anchoring...');
    const anchorResult = await anchorScan(scan.id, contentBuffer);
    console.log('Anchor result:', anchorResult);
    
    console.log('Verifying...');
    const verifyResult = await verifyScan(scan.id, contentBuffer, anchorResult.signature);
    console.log('Verify result:', verifyResult);
  } catch (err) {
    console.error('ERROR:', err);
  }
}
test();
