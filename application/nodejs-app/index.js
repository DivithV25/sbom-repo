// Node.js Application Entry Point
const express = require('express');
const axios = require('axios');
const _ = require('lodash');

const app = express();
const PORT = 3000;

app.use(express.json());

app.get('/', (req, res) => {
  res.json({ 
    message: 'PRISM Scanner - Node.js App',
    version: '1.0.0'
  });
});

app.get('/api/data', async (req, res) => {
  try {
    const response = await axios.get('https://api.example.com/data');
    const processed = _.defaults(response.data, { default: 'value' });
    res.json(processed);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
