const express = require('express');
const path = require('path');
const app = express();

console.log(`[app] PID: ${process.pid}`);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

app.listen(8080, () => console.log('Server on :8080'));