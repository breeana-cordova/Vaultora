const express = require('express');
const app = express();

app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/echo', (req, res) => {
  res.json({
    receivedData: req.body,
    note: 'Here is the data you sent us!'
  });
});

module.exports = app;
