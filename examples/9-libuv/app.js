'use strict';

/**
 * NodeLeash Attribution Test Suite
 *
 * Prerequisiti:
 *   npm install axios fs-extra bcrypt
 *
 * Avvio:
 *   node --perf-basic-prof app.js
 *
 * In un altro terminale:
 *   sudo ./nodeleash analyze $(pgrep -f "node.*app.js") --debug
 *
 * Ogni test è separato da una pausa di STEP_DELAY ms per rendere
 * leggibile l'output di NodeLeash --debug.
 *
 * Attributzione attesa per ciascun test:
 *
 *  TEST 1  readFileSync            → LOCAL (sincrono, JS frame sullo stack)
 *  TEST 2  fs.promises.readFile    → LOCAL via uretprobe thread-pool
 *  TEST 3  fs-extra.readFile       → fs-extra via uretprobe thread-pool
 *  TEST 4  dns.lookup              → LOCAL via uretprobe thread-pool (getaddrinfo)
 *  TEST 5  axios HTTP → localhost  → axios via fd_attribution_map (rete)
 *  TEST 6  fs.readFile in          → [UNATTRIBUTED] — timer callback,
 *          setTimeout callback       nessun JS frame sullo stack
 *  TEST 7  Promise chain           → [UNATTRIBUTED] — microtask V8,
 *                                    fuori dalla copertura di libuv
 *  TEST 8  bcrypt.hash             → bcrypt via uretprobe thread-pool
 *                                    (native addon + worker thread)
 *  TEST 9  Operazioni concorrenti  → ciascuna attribuita separatamente
 */

const fs   = require('fs');
const fsp  = fs.promises;
const dns  = require('dns').promises;
const http = require('http');
const path = require('path');

const STEP_DELAY = 2000;   // pausa tra un test e il successivo (ms)
const TEST_FILE  = '/tmp/nodeleash_test_' + process.pid + '.txt';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ─────────────────────────────────────────────────────────────────────────────
// Utility: stampa separatore visibile nell'output di NodeLeash --debug
// ─────────────────────────────────────────────────────────────────────────────
async function section(id, title, expected) {
    const sep = '─'.repeat(60);
    console.log(`\n${sep}`);
    console.log(`  TEST ${id}: ${title}`);
    console.log(`  Atteso: ${expected}`);
    console.log(sep);
    await sleep(STEP_DELAY);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1 — Lettura sincrona
//
// fs.readFileSync è sincrono: al momento di openat()/read() il JS frame
// di questa funzione È presente sullo stack nativo.
// NodeLeash non ha bisogno di uprobes: l'attribuzione avviene direttamente
// tramite il meccanismo base (stack walk + Blazesym).
//
// Atteso: CAP_READ_FILE → LOCAL/app.js
// ─────────────────────────────────────────────────────────────────────────────
async function test1_syncRead() {
    await section(1, 'readFileSync', 'CAP_READ_FILE → LOCAL (sincrono)');

    fs.writeFileSync(TEST_FILE, 'dati di test NodeLeash\n');
    const data = fs.readFileSync(TEST_FILE, 'utf8');
    console.log('  result:', data.trim());
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2 — Lettura asincrona via fs.promises (thread pool, codice locale)
//
// fs.promises.readFile delega a libuv il thread pool.
// Al momento di uv__work_submit il JS frame locale è sullo stack.
// L'uprobe cattura il contesto → uv__fs_work lo trasferisce al worker TID.
// L'uretprobe su uv__fs_work fa il cleanup dopo tutti i syscall del work item.
//
// Atteso: CAP_READ_FILE → LOCAL/app.js (via uprobe thread-pool)
// ─────────────────────────────────────────────────────────────────────────────
async function test2_asyncReadLocal() {
    await section(2, 'fs.promises.readFile (locale)',
        'CAP_READ_FILE → LOCAL (thread pool, uprobe)');

    const data = await fsp.readFile(TEST_FILE, 'utf8');
    console.log('  result:', data.trim());
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3 — Lettura asincrona via fs-extra (thread pool, pacchetto npm)
//
// fs-extra chiama graceful-fs che chiama fs internamente.
// Al momento di uv__work_submit il frame JS più vicino al syscall appartiene
// a node_modules/fs-extra → attribuito a fs-extra.
//
// Atteso: CAP_READ_FILE → fs-extra (via uprobe thread-pool)
// ─────────────────────────────────────────────────────────────────────────────
async function test3_asyncReadFsExtra() {
    await section(3, 'fs-extra.readFile (pacchetto npm)',
        'CAP_READ_FILE → fs-extra (thread pool, uprobe)');

    try {
        const fsExtra = require('fs-extra');
        const data = await fsExtra.readFile(TEST_FILE, 'utf8');
        console.log('  result:', data.trim());
    } catch (e) {
        console.log('  fs-extra non disponibile — npm install fs-extra');
        // fallback: mostra comunque un'operazione asincrona locale
        const data = await fsp.readFile(TEST_FILE, 'utf8');
        console.log('  fallback readFile:', data.trim());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 4 — DNS lookup (thread pool via uv__getaddrinfo_work)
//
// dns.promises.lookup usa il thread pool con uv__getaddrinfo_work.
// L'uprobe su uv__getaddrinfo_work trasferisce il contesto al worker TID.
// Nota: solo il primo syscall di getaddrinfo (es. socket() per il resolver)
// viene attribuito; i successivi recv()/send() della query DNS rientrano in
// UnattributedPolicy.
//
// Atteso: CAP_CONNECT_REMOTE/CAP_READ_SYSTEM_STATE → LOCAL (via uprobe getaddrinfo)
// ─────────────────────────────────────────────────────────────────────────────
async function test4_dnsLookup() {
    await section(4, 'dns.promises.lookup',
        'syscall getaddrinfo → LOCAL (uprobe uv__getaddrinfo_work)');

    try {
        const result = await dns.lookup('localhost');
        console.log('  result:', result.address);
    } catch (e) {
        console.log('  dns.lookup error (accettabile):', e.message);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 5 — Richiesta HTTP via axios (attributzione fd-based)
//
// Questo test avvia un server HTTP locale e poi lo interroga via axios,
// evitando la necessità di rete esterna.
//
// Flusso atteso:
//   axios.get() → socket() con JS frame di axios sullo stack
//     → pending_socket_map[tid] = stack_id  (trace_sys_enter)
//     → fd_attribution_map[new_fd] = stack_id (trace_sys_exit, fd noto)
//   connect()   → attribuito (sincrono, JS frame presente)
//   send()      → attribuito via fd_attribution_map[fd] (JS frame assente)
//   recv()      → attribuito via fd_attribution_map[fd] (JS frame assente)
//
// Atteso: CAP_CONNECT_REMOTE/CAP_SEND_DATA/CAP_RECEIVE_DATA → axios
// ─────────────────────────────────────────────────────────────────────────────
async function test5_axiosHTTP() {
    await section(5, 'axios HTTP → localhost (fd-based network attribution)',
        'CAP_CONNECT_REMOTE/SEND/RECEIVE → axios (fd_attribution_map)');

    // Avvia un server locale temporaneo
    const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
        const axios = require('axios');
        const res = await axios.get(`http://127.0.0.1:${port}/`, { timeout: 3000 });
        console.log('  HTTP status:', res.status, '— body:', res.data.trim());
    } catch (e) {
        console.log('  axios non disponibile — npm install axios');
        // fallback: http nativo
        await new Promise((resolve, reject) => {
            http.get(`http://127.0.0.1:${port}/`, (res) => {
                console.log('  HTTP (nativo) status:', res.statusCode);
                res.resume();
                res.on('end', resolve);
            }).on('error', reject);
        });
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 6 — Lettura in callback setTimeout [CASO UNATTRIBUTED]
//
// setTimeout schedula la callback nell'event loop.
// Quando libuv esegue uv__run_timers(), nessun JS frame del chiamante
// originale è presente sullo stack nativo.
// Il contesto non viene catturato da nessun uprobe né da fd_attribution_map.
//
// Atteso: CAP_READ_FILE → [unattributed] → UnattributedPolicy
// ─────────────────────────────────────────────────────────────────────────────
async function test6_timerCallback() {
    await section(6, 'readFile dentro setTimeout [CASO UNATTRIBUTED]',
        'CAP_READ_FILE → [unattributed] — timer callback senza JS frame');

    await new Promise((resolve) => {
        setTimeout(() => {
            // Questa callback è eseguita da uv__run_timers —
            // lo stack nativo non contiene frame JS del chiamante originale.
            fsp.readFile(TEST_FILE, 'utf8')
                .then(data => {
                    console.log('  timer read:', data.trim());
                    resolve();
                })
                .catch(resolve);
        }, 100);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 7 — Catena di Promise [CASO UNATTRIBUTED]
//
// Le microtask Promise sono gestite dalla coda V8, non da libuv.
// Non esistono uprobes applicabili e fd_attribution_map non aiuta
// perché non ci sono nuovi socket.
//
// Atteso: tutte le readFile nella catena → [unattributed]
// ─────────────────────────────────────────────────────────────────────────────
async function test7_promiseChain() {
    await section(7, 'Catena Promise .then() [CASO UNATTRIBUTED]',
        'CAP_READ_FILE → [unattributed] — microtask V8, fuori da libuv');

    await Promise.resolve()
        .then(() => fsp.readFile(TEST_FILE, 'utf8'))
        .then(data => fsp.writeFile(TEST_FILE + '.copy', data + '\n[copia]'))
        .then(() => fsp.readFile(TEST_FILE + '.copy', 'utf8'))
        .then(data => console.log('  promise chain result:', data.split('\n')[0]));
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 8 — bcrypt (native addon + thread pool)
//
// bcrypt usa un addon nativo (.node) che esegue operazioni crypto
// nel thread pool di libuv. L'uprobe su uv__work_submit cattura il
// frame JS di bcrypt; il worker thread viene attributito via tid_stack_map.
// I frame nativi dell'addon sono rilevati da NodeLeash tramite il
// suffisso .node nel Module field di Blazesym.
//
// Atteso: CAP_MEMORY / operazioni crypto → bcrypt
// ─────────────────────────────────────────────────────────────────────────────
async function test8_bcrypt() {
    await section(8, 'bcrypt.hash (native addon + thread pool)',
        'crypto syscalls → bcrypt (addon .node + uprobe thread-pool)');

    try {
        const bcrypt = require('bcrypt');
        const hash = await bcrypt.hash('nodeleash_test_password', 8);
        const ok   = await bcrypt.compare('nodeleash_test_password', hash);
        console.log('  hash verificato:', ok);
    } catch (e) {
        console.log('  bcrypt non disponibile — npm install bcrypt');
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 9 — Operazioni concorrenti
//
// Lancia più operazioni async in parallelo per verificare che l'attribuzione
// non si "mescoli" tra operazioni diverse sullo stesso thread pool.
// Ogni work item ha il proprio stack_id in uv_work_map → nessuna collisione.
//
// Atteso: ciascuna readFile attribuita separatamente al proprio initiator
// ─────────────────────────────────────────────────────────────────────────────
async function test9_concurrentOps() {
    await section(9, 'Operazioni concorrenti sul thread pool',
        'Ogni operazione attribuita separatamente (no mixing di contesto)');

    const ops = [
        fsp.readFile(TEST_FILE, 'utf8'),
        fsp.readFile('/etc/hostname', 'utf8').catch(() => 'n/a'),
        fsp.readFile('/etc/os-release', 'utf8')
              .then(d => d.split('\n')[0]).catch(() => 'n/a'),
        dns.lookup('localhost').then(r => r.address).catch(() => 'n/a'),
    ];

    const results = await Promise.all(ops);
    console.log('  risultati concorrenti:');
    results.forEach((r, i) => console.log(`    [${i}] ${String(r).split('\n')[0].trim()}`));
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────
async function main() {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║         NodeLeash Attribution Test Suite                 ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');
    console.log('  PID:', process.pid);
    console.log('  Avvia NodeLeash con:');
    console.log(`  sudo ./nodeleash analyze ${process.pid} --debug`);
    console.log('');
    console.log('  I test iniziano tra 10 secondi...');
    await sleep(11000);

    await test1_syncRead();
    await test2_asyncReadLocal();
    await test3_asyncReadFsExtra();
    await test4_dnsLookup();
    await test5_axiosHTTP();
    await test6_timerCallback();
    await test7_promiseChain();
    await test8_bcrypt();
    await test9_concurrentOps();

    // Cleanup
    await sleep(STEP_DELAY);
    try { fs.unlinkSync(TEST_FILE); } catch (_) {}
    try { fs.unlinkSync(TEST_FILE + '.copy'); } catch (_) {}

    console.log('\n╔══════════════════════════════════════════════════════════╗');
    console.log('║  ✅ Tutti i test completati.                              ║');
    console.log('║  Ferma NodeLeash con Ctrl+C per vedere il policy summary. ║');
    console.log('╚══════════════════════════════════════════════════════════╝\n');

    // Mantieni il processo vivo per permettere a NodeLeash di ricevere Ctrl+C
    await sleep(5000);
}

main().catch(console.error);