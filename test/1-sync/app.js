'use strict';

// Main orchestrator.
// Loads processor and validator, runs the pipeline on a data file.

const fs        = require('fs');
const processor = require('./processor');
const validator = require('./validator');

console.log(`[app] PID: ${process.pid}`);

// Create sample data file on first run
if (!fs.existsSync('data.txt')) {
    fs.writeFileSync('data.txt', 'user=admin\nrole=superuser\nsecret=abc123\nthis line has no equals sign');
}

function run() {

    // Verify data file exists and is non-empty before processing
    const stat = fs.statSync('data.txt');
    if (stat.size === 0) return;

    const raw    = processor.read('data.txt');
    const result = processor.process(raw);
    processor.write('output.txt', result);

    const ok = validator.validate(result);
    console.log(`[app] pipeline done, valid=${ok}`);
}

run();
setInterval(run, 5000);