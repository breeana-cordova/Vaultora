const express = require('express');
const app = express();

app.use(express.json());

// Health check route
app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

// Echo route
app.post('/echo', (req, res) => {
  res.json({
    receivedData: req.body,
    note: 'Here is the data you sent us!'
  });
});

module.exports = app;
