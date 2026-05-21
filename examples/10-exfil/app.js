'use strict';
// app.js — entry point dell'applicazione legittima.
//
// Questo file non esegue operazioni di rete né legge file sensibili.
// In analyze mode NodeLeash dovrebbe attribuire a LOCAL/app.js
// solo le capabilities minime legate al bootstrap del processo.
//
// Avvio:
//   npm install
//   node --perf-basic-prof app.js
//
// In un altro terminale:
//   sudo ./nodeleash analyze $(pgrep -f "node.*app.js") --debug

const { mainLogic } = require('./business');

console.log(`PID: ${process.pid}`);
console.log('Applicazione avviata.');
console.log('Premi Ctrl+C per terminare e generare la policy.\n');

setInterval(mainLogic, 5000);