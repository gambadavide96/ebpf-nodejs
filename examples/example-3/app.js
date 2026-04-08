const fs = require('fs');

(async () => {
    console.log("🚀 Avvio applicazione Node.js...");
    console.log(`PID: ${process.pid}`);

    // 1. Leggiamo il file binario pre-compilato dal C
    const wasmBuffer = fs.readFileSync('math.wasm');

    // 2. Compiliamo e instanziamo il modulo WebAssembly al volo
    // (V8 lo trasforma dal formato .wasm al codice macchina della tua CPU)
    const wasmModule = await WebAssembly.instantiate(wasmBuffer);

    // 3. Estraiamo le funzioni che abbiamo esportato dal C!
    const { fibonacci, moltiplica } = wasmModule.instance.exports;

    console.log("✅ Modulo C/WebAssembly caricato con successo!\n");

    setInterval(() => {

    // Test 1: 
    const a = 12, b = 4;
    console.log(`[WASM] Risultato di moltiplica(${a}, ${b}) = ${moltiplica(a, b)}`);

    // Test 2: (Fibonacci)
    const numero = 40; 
    console.log(`⏳ Calcolo di Fibonacci(${numero}) in corso nel motore C...`);
    
    const startTime = performance.now();
    
    const risultato = fibonacci(numero); 
    
    const endTime = performance.now();

    console.log(`[WASM] Risultato: ${risultato}`);
    console.log(`⏱️  Tempo impiegato dal modulo C: ${(endTime - startTime).toFixed(2)} ms`);
    },5000)

})();