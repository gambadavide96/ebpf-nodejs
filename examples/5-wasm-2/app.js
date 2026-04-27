const fs = require('fs');

console.log(`PID: ${process.pid}`);

// 1. Definiamo l'oggetto di importazione
const importObject = {
    env: {
        // Questa è la funzione esterna che Wasm potrà chiamare
        write_on_stdout: (valore) => {
            const messaggio = `[JS invocato da Wasm] Il valore calcolato è: ${valore}\n`;
            // Forziamo una SYSCALL WRITE diretta su file descriptor 1 (stdout)
            fs.writeSync(1, messaggio);
        }
    }
};

// 2. Carichiamo il modulo Wasm
const wasmBuffer = fs.readFileSync('./logger.wasm');

WebAssembly.instantiate(wasmBuffer, importObject).then(wasmModule => {
    console.log(" Modulo Wasm caricato. Avvio ciclo...");
    
    setInterval(() => {
        // 3. JS chiama Wasm
        console.log("-> Entro in Wasm...");
        wasmModule.instance.exports.do_multiplication(5,3);
        console.log("<- Uscito da Wasm.");
    }, 5000);
});