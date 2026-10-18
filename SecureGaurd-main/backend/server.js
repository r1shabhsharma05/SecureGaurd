const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');

dotenv.config();

const { validateEnv } = require('./config/env');

// Fail fast on missing secrets/config — never run half-configured.
// NOTE: this MUST run before the route requires below. routes/integration.js
// -> utils/cryptoUtils.js reads process.env.JWT_SECRET at require time, so a
// missing JWT_SECRET would otherwise crash with a cryptic TypeError before
// this clear error ever fires.
validateEnv();

const authRoutes = require('./routes/auth');
const repoRoutes = require('./routes/repos');
const scanRoutes = require('./routes/scans');
const vulnRoutes = require('./routes/vulnerabilities');
const integrationRoutes = require('./routes/integration');
const aiRoutes = require('./routes/ai');
const classifierRoutes = require('./routes/classifier');
const complianceRoutes = require('./routes/compliance');
const orgRoutes = require('./routes/organizations');
const invitationRoutes = require('./routes/invitations');
const billingWebhookRoutes = require('./routes/billingWebhook');
const billingRoutes = require('./routes/billing');
const sbomRoutes = require('./routes/sboms');
const prisma = require('./prismaClient');
const { getAllowedOrigins } = require('./config/cors');

const app = express();

const allowedOrigins = getAllowedOrigins();
app.set('trust proxy', 1);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy: Origin not allowed'));
    }
  },
  credentials: true
}));

// Mount Webhook route BEFORE express.json parser so raw signature verification works
app.use('/api/billing/webhook', billingWebhookRoutes);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/repos', repoRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/vulnerabilities', vulnRoutes);
app.use('/api/integration', integrationRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/classifier', classifierRoutes);
app.use('/api/compliance', complianceRoutes);
app.use('/api/organizations', orgRoutes);
app.use('/api/invitations', invitationRoutes);
app.use('/api/billing', billingRoutes);
app.use('/api/sboms', sbomRoutes);

// Test PostgreSQL connection
prisma.$connect()
  .then(() => console.log('PostgreSQL database successfully connected via Prisma'))
  .catch((err) => console.error('Database connection error:', err));

const PORT = process.env.PORT || 5000;

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
