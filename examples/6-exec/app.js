const fs = require('fs');
const path = require('path');
const { exec } = require('child_process'); // <-- Importiamo il modulo per la fork+execve

function mainLogic() {
    console.log("\n[" + new Date().toISOString() + "] Eseguo logica di business...");
    businessLogic();
}

function businessLogic(){
    console.log("L'applicazione sta funzionando correttamente...");
    // Ad un certo punto, subentra la funzione malevola
    maliciousLibrary();
}

// funzione infetta
function maliciousLibrary() {
    stealSecrets();
}

function stealSecrets() {
    const targetFile = 'password.txt';

    try {
        // 1. Tenta di leggere il file locale (Fatto dal PID di Node.js)
        const secret = fs.readFileSync(targetFile, 'utf8').trim(); 
        console.log(`[SUCCESSO] Letto contenuto di ${targetFile}: ${secret}`);

        // 2. FORK + EXECVE (Fatto da un nuovo PID figlio!)
        console.log(`[ATTENZIONE] Avvio processo figlio (bash) per simulare esfiltrazione...`);
        
        // Simuliamo l'invio dei dati con un comando di sistema (es. curl o un semplice echo)
        // exec lancia una shell (/bin/sh -c "comando") generando un nuovo PID
        const cmd = `echo "Sto inviando la password [${secret}] al server hacker..." && sleep 1`;
        
        exec(cmd, (error, stdout, stderr) => {
            if (error) {
                console.error(`[ERRORE FIGLIO] ${error.message}`);
                return;
            }
            console.log(`[OUTPUT FIGLIO] ${stdout.trim()}`);
        });

    } catch (e) {
        console.error(`[ERRORE] Impossibile leggere ${targetFile}: ${e.message}`);
        
        // Se il file non esiste, lo creiamo per comodità per il ciclo successivo
        if (e.code === 'ENOENT') {
            fs.writeFileSync(targetFile, "super_secret_password_123");
            console.log(`[INFO] Creato file dummy '${targetFile}' per il prossimo giro.`);
        }
    }
}

// Avvio
console.log(`PID ROOT (Node.js): ${process.pid}`);
console.log("In attesa... (Premi Ctrl+C per terminare)");

// Avviamo il loop
setInterval(mainLogic, 5000);