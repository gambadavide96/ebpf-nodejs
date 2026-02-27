// server.js
const express = require('express');
const logger = require('./logger');
const { fetchExternalData, calculateFibonacci } = require('./workload');

const app = express();
const PORT = 3000;

// Middleware globale per loggare ogni richiesta in ingresso
app.use((req, res, next) => {
    logger.info({ message: 'Richiesta ricevuta', method: req.method, url: req.url });
    next();
});

// Rotta 1: Risposta rapida (traffico base HTTP)
app.get('/', (req, res) => {
    res.send('Benvenuto nell\'app di test con Express!\n');
});

// Rotta 2: Carico CPU
app.get('/compute', (req, res) => {
    const num = 30; // Numero sufficientemente alto per impegnare un po' la CPU
    logger.info({ message: 'Inizio calcolo intensivo', input: num });
    
    const result = calculateFibonacci(num);
    
    logger.info({ message: 'Calcolo completato', result });
    res.json({ operation: 'fibonacci', input: num, result });
});

// Rotta 3: Traffico di rete in uscita (Outbound Network)
app.get('/external', async (req, res) => {
    try {
        logger.info({ message: 'Inizio chiamata HTTP in uscita verso API esterna' });
        
        const data = await fetchExternalData();
        
        logger.info({ message: 'Chiamata HTTP in uscita completata con successo' });
        res.json({ message: 'Dati recuperati', data });
    } catch (error) {
        logger.error({ message: 'Errore nella chiamata esterna', error: error.message });
        res.status(500).json({ error: 'Errore interno di rete' });
    }
});

app.listen(PORT, () => {
    logger.info({ message: 'Server avviato', port: PORT, pid: process.pid });
    console.log(`Server Express in ascolto sulla porta ${PORT} (PID: ${process.pid})`);
});