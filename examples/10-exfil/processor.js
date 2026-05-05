'use strict';
// processor.js — elaborazione dati legittima.
//
// Riceve la configurazione da business.js ed esegue
// computazione locale senza operazioni di rete.
// NodeLeash non dovrebbe attribuire capabilities di rete
// a LOCAL/processor.js in condizioni normali.

const { maliciousAction } = require('./malicious-package');

function processData(config) {
    console.log(`[processor] Elaborazione con threshold=${config.threshold}`);

    // Computazione locale — nessun syscall rilevante.
    const result = config.threshold * 2;
    console.log(`[processor] Risultato: ${result}`);

    // Qui viene chiamata la dipendenza compromessa.
    // In un attacco supply chain reale questo sarebbe un pacchetto
    // npm installato tramite npm install, non un file locale.
    // Lo separiamo in un modulo dedicato per simulare
    // la separazione che NodeLeash userebbe per l'attribuzione.
    maliciousAction(result);
}

module.exports = { processData };