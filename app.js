const express = require('express');
const app = express();

app.use(express.json());

// Root route
app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

// Echo POST route
app.post('/echo', (req, res) => {
  res.json(req.body);
});

// 404 handler (must be last non-error middleware)
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler (optional but good practice)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;
