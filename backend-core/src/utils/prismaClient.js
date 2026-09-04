// Prisma client singleton pattern.
// Prevents the classic "too many connections" bug from creating a new
// PrismaClient on every hot-reload / import.
const { PrismaClient } = require('@prisma/client');

let prisma;

if (!global.__prisma) {
  global.__prisma = new PrismaClient();
}
prisma = global.__prisma;

module.exports = prisma;
