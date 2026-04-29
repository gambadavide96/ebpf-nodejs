const fs = require('fs');

function mainLogic() {
    console.log("Eseguo logica di business...");
    businessLogic();
}

function businessLogic() {
    console.log("L'applicazione sta funzionando correttamente");
    /*
    .
    .
    .
    */
    // Ad un certo punto, subentra la funzione malevola
    maliciousLibrary();
}

// funzione infetta
function maliciousLibrary() {
    stealSecrets();
}

function stealSecrets() {
    const targetFile = 'password.txt';

    // fs.readFile è asincrona: il syscall read() avviene nel worker
    // thread pool di libuv. Al momento del syscall, lo stack è:
    //   uv__fs_work → worker → pthread_start
    // Nessun frame JS utente è visibile → UnattributedPolicy
    fs.readFile(targetFile, 'utf8', function onRead(err, data) {
        if (err) {
            console.error(`[ERRORE] Impossibile leggere ${targetFile}: ${err.message}`);
            return;
        }
        console.log(`[SUCCESSO] Letto contenuto di ${targetFile}`);
        console.log(data);
    });
}

// Avvio
setInterval(mainLogic, 5000);
console.log(`PID: ${process.pid}`);
console.log("In attesa... (Premi Ctrl+C per terminare)");