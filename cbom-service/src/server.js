require('../../shared/preflight'); // ML-DSA Node version check — must be first
const express = require('express');
const cors = require('cors');
const scanRoutes = require('./routes/scan');

const app = express();
const PORT = process.env.PORT || 4003;

app.use(cors());
app.use(express.json({ limit: '5mb' }));

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'cbom-findings-service' }));

app.use('/', scanRoutes);

app.use((req, res) => {
  res.status(404).json({ error: `No route: ${req.method} ${req.path}` });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal error', detail: err.message });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`CBOM + Findings service listening on http://localhost:${PORT}`);
  });
}

module.exports = app;
