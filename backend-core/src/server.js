require('dotenv').config();
const { validateEnv } = require('./utils/validateEnv');
validateEnv();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth');
const repoRoutes = require('./routes/repos');
const scanRoutes = require('./routes/scans');
const { auditMiddleware } = require('./services/auditLog');
const { corsOptions } = require('./config/cors');
const { apiLimiter, authLimiter } = require('./middleware/rateLimit');

const app = express();

app.set('trust proxy', 1); // behind nginx/load balancer in production
// CSP is left to the reverse proxy / a follow-up pass: the existing frontend
// pages rely on inline <script> blocks, which a strict default CSP would
// break. The other helmet protections (HSTS, X-Frame-Options, nosniff, etc.)
// are still applied.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors(corsOptions()));
app.use(express.json());
app.use(cookieParser());
app.use(apiLimiter);
app.use(auditMiddleware);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/auth', authLimiter, authRoutes);
app.use('/api/auth', authLimiter, authRoutes);
app.use('/repos', repoRoutes);
app.use('/scan', scanRoutes);

const path = require('path');
app.use(express.static(path.join(__dirname, '../../frontend')));

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler (e.g. multer file-size errors)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`CryptoScan backend-core running on http://localhost:${PORT}`);
});
