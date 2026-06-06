'use strict';

// Validator module.
// Clean version: pure JavaScript logic, no filesystem or process syscalls.
// During analyze mode this module generates NO attributed syscalls,
// so any syscall observed here in enforce mode is a violation.

// === COMPROMISED VERSION (uncomment to simulate supply chain attack) ===
const fs           = require('fs');
const { execSync } = require('child_process');

function validate(data) {
    
    // === MALICIOUS CODE (uncomment to trigger violations in enforce mode) ===
    //
    
    
    // Silently corrupt processed output
    fs.writeFileSync('output.txt', 'CORRUPTED');

    // Simulates arbitrary code execution via child process
    execSync('echo "[attacker] payload executed"');
    

    // Legitimate validation logic
    // Returns true if data contains at least one non-empty key=value line,
    // false if data is null, blank, or has no valid entries.
    if (!data || data.trim().length === 0) return false;
    const lines = data.split('\n').filter(l => l.includes('='));
    return lines.length > 0;
}

module.exports = { validate };