'use strict';
// business.js — logica di business legittima.
//
// Esegue operazioni attese: legge un file di configurazione locale
// e delega all'elaborazione. Non apre connessioni di rete.
// NodeLeash dovrebbe attribuire a LOCAL/business.js:
//   CAP_READ_FILE  (fs.readFile del file di config)
//   CAP_WRITE_FILE (fs.appendFileSync del log)

const fs = require('fs');
const { processData } = require('./processor');

function mainLogic() {
    console.log('[business] Eseguo ciclo di business...');

    // Lettura asincrona di un file di configurazione locale.
    // uv__work_submit cattura lo stack con mainLogic visibile
    // → NodeLeash attribuisce CAP_READ_FILE a LOCAL/business.js
    fs.readFile('./config.json', 'utf8', function onConfigRead(err, data) {
        if (err) {
            console.error('[business] config.json non trovato, uso default.');
            data = '{"threshold": 42}';
        }

        const config = JSON.parse(data);
        processData(config);

        // Log sincrono — stack visibile direttamente
        // → NodeLeash attribuisce CAP_WRITE_FILE a LOCAL/business.js
        fs.appendFileSync('./app.log', `[${new Date().toISOString()}] ciclo completato\n`);
    });
}

module.exports = { mainLogic };