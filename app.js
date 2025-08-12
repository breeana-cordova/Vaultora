const express = require('express');
const app = express();

app.use(express.json());

// Example working route
app.get('/', (req, res) => {
  res.json({ message: 'Vaultora API is running' });
});

// Example POST echo route
app.post('/echo', (req, res) => {
  res.json({ youSent: req.body });
});

// Simulated 500 error route
app.get('/error', (req, res, next) => {
  next(new Error('Simulated server failure'));
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// 500 handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;
