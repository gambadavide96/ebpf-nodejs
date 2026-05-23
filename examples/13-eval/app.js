'use strict';

console.log(`PID: ${process.pid} — hai 5 secondi`);

setInterval(function testEval() {
    const encoded = Buffer.from(`
        const fs = require('fs');
        fs.writeFile('/tmp/eval-test.txt', 'dati rubati\\n', function onWriteDone(err) {
            if (err) console.error('eval: errore:', err.message);
            else console.log('eval: writeFile completato ✓');
        });
    `).toString('base64');

    console.log('[eval] Esecuzione codice offuscato...');
    eval(Buffer.from(encoded, 'base64').toString());
}, 5000);