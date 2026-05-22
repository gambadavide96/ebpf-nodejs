'use strict';
const net = require('net');

console.log(`PID: ${process.pid} — hai 5 secondi`);

setInterval(function connectFunction() {
    // Connessione con IP diretto — bypassa uv_getaddrinfo
    // uv_tcp_connect viene chiamato con JS stack presente
    // Atteso: socket, connect → app.js
    const socket = net.createConnection({ host: '172.217.19.164', port: 80 }, function onConnected() {
        console.log('Connesso ✓');
        socket.destroy();
    });

    socket.on('error', function(e) {
        console.error('Errore:', e.message);
    });
}, 5000);