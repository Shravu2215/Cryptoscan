const jwt = require('jsonwebtoken');
const prisma = require('../utils/prismaClient');
const ROLES = Object.freeze({ ADMIN: 'Admin', SECURITY_TEAM: 'Security Team', DEVELOPER: 'Developer', AUDITOR: 'Auditor' });

async function requireAuth(req, res, next) {
// --- Original Auth Logic (Disconnected) ---
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await prisma.user.findUnique({ where: { id: payload.id }, select: { id: true, email: true, role: true } });
    if (!user) return res.status(401).json({ error: 'User no longer exists' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => allowedRoles.includes(req.user?.role)
    ? next()
    : res.status(403).json({ error: 'Your role is not permitted to perform this action' });
}

module.exports = { requireAuth, requireRole, ROLES };
