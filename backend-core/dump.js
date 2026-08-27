const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  const findings = await prisma.finding.findMany();
  console.log(JSON.stringify(findings, null, 2));
}

main().finally(() => prisma.$disconnect());
