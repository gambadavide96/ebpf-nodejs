'use strict';
const net = require('net');

console.log(`PID: ${process.pid} — hai 5 secondi`);

setInterval(function testDNSConnect() {
    // Usa hostname direttamente — Node.js chiama uv_getaddrinfo internamente
    // Atteso: socket, connect → app.js via async stack (Category 2a)
    const socket = net.createConnection({ host: 'google.com', port: 80 }, function onConnected() {
        console.log('Connesso ✓');
        socket.destroy();
    });

    socket.on('error', function(e) {
        console.error('Errore:', e.message);
    });
}, 5000);