'use strict';
const crypto = require('crypto');
const prisma = require('../utils/prismaClient');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value, Object.keys(value).sort());
async function appendAuditLog(data) {
  const previous = await prisma.auditLog.findFirst({ orderBy: [{ createdAt: 'desc' }, { id: 'desc' }] });
  const record = { ...data, userId: data.userId || null, requestHash: data.requestHash || null, previousHash: previous?.entryHash || null };
  return prisma.auditLog.create({ data: { ...record, entryHash: hash(canonical(record)) } });
}
function auditMiddleware(req, res, next) {
  res.on('finish', () => {
    if (req.method === 'GET' || req.path === '/health' || res.statusCode >= 500) return;
    const body = { ...req.body }; delete body.password; delete body.token; delete body.accessToken;
    appendAuditLog({ userId: req.user?.id, action: `${req.method} ${req.path}`, method: req.method, path: req.path, statusCode: res.statusCode, requestHash: hash(canonical(body)) }).catch(err => console.error('Audit log write failed:', err.message));
  });
  next();
}
module.exports = { appendAuditLog, auditMiddleware };
