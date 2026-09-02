const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { buildCbom } = require('./src/services/cbomGenerator');

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
  console.log(JSON.stringify(cbom, null, 2));
}
test();
