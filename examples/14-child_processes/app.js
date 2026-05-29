const { exec, spawn, execSync } = require('child_process');
 
console.log(`PID: ${process.pid}`);
console.log('Waiting 20 seconds before spawning child processes...');
 
// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1 — exec() async
// Expected: clone3 + execve attributed to execChild → app.js
// ─────────────────────────────────────────────────────────────────────────────
function execChild() {
    console.log('[scenario 1] exec async...');
    exec('echo hello_from_exec', function onExecDone(err, stdout) {
        if (err) {
            console.log(`[scenario 1] error: ${err.message}`);
        } else {
            console.log(`[scenario 1] exec output: ${stdout.trim()}`);
        }
    });
}

function spawnChild() {
    console.log('[scenario 2] spawn async...');
    const child = spawn('echo', ['hello_from_spawn']);
    child.on('close', function onSpawnDone(code) {
        console.log(`[scenario 2] spawn exited with code: ${code}`);
    });
}

setInterval(function startTests() {
    spawnChild();

}, 5000);