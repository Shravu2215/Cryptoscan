const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function requireAuth(req, res, next) {
  // TEMP: Bypass authentication for trial scanning
  try {
    let dummy = await prisma.user.findFirst({ where: { email: 'trial@example.com' } });
    if (!dummy) {
      dummy = await prisma.user.create({
        data: {
          email: 'trial@example.com',
          name: 'Trial User',
          provider: 'local'
        }
      });
    }
    req.user = dummy;
    return next();
  } catch (err) {
    console.error('Trial auth error:', err);
    return res.status(500).json({ error: 'Auth bypass failed' });
  }

  // --- Original Auth Logic (Disconnected) ---
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { id, email }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { requireAuth };
