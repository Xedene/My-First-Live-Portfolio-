const express = require('express');
const reconRoutes = require('../routes/recon');

const app = express();

app.use(express.json());

// API routes
app.use('/api/recon', reconRoutes);

// Export for Vercel — do NOT call app.listen()
// Vercel handles the server lifecycle via serverless functions.
// Static files in /public are served automatically by Vercel CDN.
module.exports = app;
