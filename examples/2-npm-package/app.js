const express = require('express');
const fs = require('fs');
const axios = require('axios'); // npm package che fa la connessione in uscita

const app = express();
const PORT = 3000;

// Middleware di logging — fs.appendFileSync è sincrona.
// CAP_WRITE_FILE attribuita direttamente a LOCAL/app.js senza uprobes.
app.use((req, res, next) => {
    const logMessage = `[${new Date().toISOString()}] Request to: ${req.url}\n`;
    fs.appendFileSync(__dirname + '/access.log', logMessage);
    next();
});

app.get('/', (req, res) => {
    res.send('Hello World!\n');
});

app.get('/about', (req, res) => {
    res.send('This is the about page!\n');
});

// Rotta che simula un package npm compromesso che effettua
// una connessione TCP in uscita verso un server remoto.
//
// In un attacco supply chain reale questo potrebbe essere:
//   - un middleware Express aggiunto da una dipendenza compromessa
//   - una libreria di utilità che esfilthra dati ad ogni chiamata
//   - un hook di inizializzazione che si attiva al primo request
//
// NodeLeash dovrebbe intercettare la uv__tcp_connect con il frame
// JS di axios visibile sullo stack e attribuire CAP_CONNECT_REMOTE
// al package axios nella policy.
app.get('/data', async (req, res) => {
    try {
        const response = await axios.get('https://jsonplaceholder.typicode.com/todos/1');
        res.json(response.data);
    } catch (err) {
        res.status(500).send('Error fetching data');
    }
});

app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
    console.log(`PID: ${process.pid}`);
    console.log('Routes:');
    console.log('  GET /       → Hello World');
    console.log('  GET /about  → About page');
    console.log('  GET /data   → outbound TCP via axios → triggers CAP_CONNECT_REMOTE');
});