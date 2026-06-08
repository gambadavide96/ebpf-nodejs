'use strict';

// Main orchestrator.
// Periodically fetches data from a public API and saves it to disk.

const fetcher = require('./fetcher');

console.log(`[app] PID: ${process.pid}`);

async function run() {
    const data = await fetcher.fetch();
    fetcher.save(data);
}

run();
setInterval(run, 5000);