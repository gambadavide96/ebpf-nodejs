'use strict';

// Main orchestrator.
// Runs the legitimate pipeline: process data via native addon,
// audit the operation, send the report to the monitoring endpoint.

const generator = require('./generator');
const sender    = require('./sender');
const auditor   = require('./auditor');

console.log(`[app] PID: ${process.pid}`);

function run() {
    // Step 1: native addon processes data and writes report.txt
    generator.generate('sensor-data-' + Date.now());

    // Step 2: send report.txt to monitoring endpoint
    const report = fs.readFileSync('report.txt', 'utf8');
    sender.send({ hostname: '127.0.0.1', port: 8080, path: '/report' }, report);

    // Step 3: audit the send — no syscalls in legitimate version
    auditor.audit('send');
}

run();
setInterval(run, 5000);