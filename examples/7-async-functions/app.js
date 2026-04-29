const net = require('net');

// Quando arriva una connessione, accept4() viene chiamata
// con onConnection sullo stack — frame utente visibile.
// fd_owner_map salva il contesto di onConnection per il nuovo fd.
function onConnection(socket) {
    console.log('[onConnection] Client connesso');

    // Questa read è GARANTITA asincrona:
    // i dati arrivano dopo che onConnection è già tornata.
    // fd_owner_map recupera il contesto salvato da accept4()
    // e attribuisce questa read a LOCAL/app.js.
    socket.on('data', function onData(data) {
        console.log(`[onData] Ricevuto: ${data.toString().trim()}`);
        socket.end();
    });
}

const server = net.createServer(onConnection);

server.listen(9000, '127.0.0.1', () => {
    console.log(`PID: ${process.pid}`);
    console.log('Server in ascolto\n');
});

// Client semplice che si connette ogni 3 secondi
setInterval(() => {
    const client = net.createConnection({ port: 9000 }, () => {
        client.write('hello\n');
    });
}, 3000);