const addon = require('./build/Debug/addon');

console.log("🚀 Applicazione Node.js avviata.");
console.log("PID:", process.pid);

setInterval(() => {
    console.log("[JS] Chiamo la funzione C++ per la WRITE...");
    const rispWrite = addon.eseguiWrite();
    console.log(`[JS] Risposta: ${rispWrite}\n`);

    // Aspettiamo 3 secondi prima di lanciare la seconda syscall
    setTimeout(() => {
        console.log("[JS] Chiamo la funzione C++ per la OPEN...");
        const rispOpen = addon.eseguiOpen();
        console.log(`[JS] Risposta: ${rispOpen}\n`);
    }, 3000);

}, 5000);