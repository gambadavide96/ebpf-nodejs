const fs = require('fs');
const { spawn } = require('child_process'); // Importiamo il modulo per creare processi

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

    // Per comodità del test, il padre crea il file se non esiste, 
    // ma NON lo legge.
    if (!fs.existsSync(targetFile)) {
        fs.writeFileSync(targetFile, "super_secret_password_123");
        console.log(`[INFO] Creato file dummy '${targetFile}'.`);
    }

    console.log(`[ATTENZIONE] Il Padre delega la lettura a un PROCESSO FIGLIO...`);

    // Questo è il codice JS che verrà eseguito ESCLUSIVAMENTE dal processo figlio
    // Il figlio legge il file, stampa il risultato e poi "si addormenta"
    // invece di morire subito, permettendo al tracer di leggere la sua memoria
    const childScript = `
        const fs = require('fs');
        
        setTimeout(() => {
            try {
                const data = fs.readFileSync('${targetFile}', 'utf8');
                console.log('File letto con successo dal PID ' + process.pid + ' -> Valore: ' + data);
                
                // TENIAMO IN VITA IL PROCESSO FIGLIO!
                console.log("Il figlio rimarrà vivo per farsi profilare...");
                setInterval(() => {}, 1000); // Loop vuoto infinito
                
            } catch(e) {
                console.error('Errore nel figlio:', e.message);
            }
        }, 500); // Il classico ritardo iniziale per creare la mappa
    `;

    // Creiamo il processo figlio passando l'eseguibile di node e il nostro script in linea
    const child = spawn(process.execPath, ['-e', childScript]);

    // Leggiamo cosa stampa il figlio (tramite pipe IPC)
    child.stdout.on('data', (data) => {
        console.log(`[OUTPUT FIGLIO] ${data.toString().trim()}`);
    });

    child.stderr.on('data', (data) => {
        console.error(`[ERRORE FIGLIO] ${data.toString().trim()}`);
    });
}

// Avvio
console.log(`PID ROOT (Node.js): ${process.pid}`);
console.log("In attesa... (Premi Ctrl+C per terminare)");

// Avviamo il loop
setInterval(mainLogic, 5000);