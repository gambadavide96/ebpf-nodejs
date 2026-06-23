const express = require('express');
const path = require('path');
const fs = require('fs').promises;

const app = express();
console.log(`[app] PID: ${process.pid}`);

const LOG_FILE = path.join(__dirname, 'access.log');

app.get('/', async (req, res) => {
    const line = `[${new Date().toISOString()}] ${req.method} ${req.url} 200\n`;
    await fs.appendFile(LOG_FILE, line);

    res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

app.listen(8080, () => console.log('Server on :8080'));