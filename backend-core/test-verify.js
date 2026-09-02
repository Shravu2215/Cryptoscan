const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { buildCbom } = require('./src/services/cbomGenerator');

async function run() {
  const scan = await prisma.scan.findFirst();
  if (!scan) return console.log('no scan');
  
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
  
  try {
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, createdAt: scan.createdAt, rawFindings });
    console.log('CBOM OK');
    const contentBuffer = Buffer.from(JSON.stringify(cbom));
    console.log('Buffer OK');
    
    const { verifyScan } = require('../blockchain-module/scripts/verify');
    const verifyResult = await verifyScan(scan.id, contentBuffer, null);
    console.log(verifyResult);
  } catch (err) {
    console.error('ERROR:', err);
  }
}
run();
