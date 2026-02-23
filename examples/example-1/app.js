const fs = require('fs');
const path = require('path');

function mainLogic() {
    console.log("Eseguo logica di business...");
    businessLogic();
}

function businessLogic(){
    console.log("L'applicazione sta funzionando correttamente")
    /*
    .
    .
    .
    */

    //Ad un certo punto, subentra la funzione malevola
    maliciousLibrary();

}

// funzione infetta
function maliciousLibrary() {

    stealSecrets();
}

function stealSecrets() {
    
    const targetFile = 'password.txt';

    try {
        // Tenta di leggere il file locale
        const secret = fs.readFileSync(targetFile, 'utf8'); 
        console.log(`[SUCCESSO] Letto contenuto di ${targetFile}`);
        console.log(secret); 
    } catch (e) {
        console.error(`[ERRORE] Impossibile leggere ${targetFile}: ${e.message}`);
    }
}

// Avvio
setInterval(mainLogic, 5000);
console.log(`PID: ${process.pid}`);
console.log("In attesa... (Premi Ctrl+C per terminare)");