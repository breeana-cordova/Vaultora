const express = require('express');
const app = express();

app.use(express.json());

// Root route
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Vaultora API is running' });
});

// Echo route
app.post('/echo', (req, res) => {
  res.status(200).json({ youSent: req.body });
});

// Simulate error
app.get('/error', (req, res) => {
  throw new Error('Simulated server failure');
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;
