const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('../utils/prismaClient');

const router = express.Router();

// POST /auth/signup
// Not in the original API contract but needed to create users before login works.
// Deliberately does NOT accept a "role" field from the client — avoids the
// role self-assignment vulnerability we hit in AssetFlow/GlobeTrotter.
router.post('/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email, password: hashed, name },
    });

    return res.status(201).json({
      id: user.id,
      email: user.email,
      name: user.name,
    });
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    return res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GitHub OAuth
router.get('/github', (req, res) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  const redirectUri = process.env.GITHUB_CALLBACK_URL;
  if (!clientId || !redirectUri) {
    return res.status(500).json({ error: 'GitHub OAuth not configured' });
  }
  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=user:email`;
  res.redirect(githubAuthUrl);
});

router.get('/github/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.redirect(`${process.env.FRONTEND_URL}/?error=NoCodeProvided`);

    const clientId = process.env.GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code })
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error) return res.redirect(`${process.env.FRONTEND_URL}/?error=GitHubAuthFailed`);
    
    const accessToken = tokenData.access_token;
    const userRes = await fetch('https://api.github.com/user', { headers: { 'Authorization': `Bearer ${accessToken}` } });
    const githubUser = await userRes.json();

    const emailsRes = await fetch('https://api.github.com/user/emails', { headers: { 'Authorization': `Bearer ${accessToken}` } });
    const emails = await emailsRes.json();
    const primaryEmail = emails.find(e => e.primary)?.email || emails[0]?.email;
    if (!primaryEmail) return res.redirect(`${process.env.FRONTEND_URL}/?error=NoEmailProvidedByGitHub`);

    let user = await prisma.user.findUnique({ where: { email: primaryEmail } });
    if (user) {
      if (!user.providerId) {
        user = await prisma.user.update({
          where: { id: user.id },
          data: { provider: 'github', providerId: String(githubUser.id), avatar: githubUser.avatar_url }
        });
      }
    } else {
      user = await prisma.user.create({
        data: {
          email: primaryEmail,
          name: githubUser.name || githubUser.login,
          provider: 'github',
          providerId: String(githubUser.id),
          avatar: githubUser.avatar_url
        }
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 });
    res.redirect(`${process.env.FRONTEND_URL}/dashboard.html`);
  } catch (err) {
    console.error(err);
    res.redirect(`${process.env.FRONTEND_URL}/?error=ServerError`);
  }
});

module.exports = router;
