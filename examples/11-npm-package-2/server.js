'use strict';

/**
 * NodeLeash — Server di test per attribuzione capabilities
 *
 * Avvio:
 *   npm install
 *   node --perf-basic-prof server.js
 *
 * NodeLeash:
 *   sudo ./nodeleash analyze $(pgrep -f "node.*server.js") --debug
 *
 * Trigger routes con curl (ogni route attiva un set di capabilities):
 *   curl http://localhost:3001/files
 *   curl http://localhost:3001/outbound
 *   curl http://localhost:3001/crypto
 *   curl http://localhost:3001/dns
 *   curl http://localhost:3001/db
 *   curl http://localhost:3001/all
 *
 * Attribuzioni attese per package:
 *
 *   express           → CAP_LISTEN_LOCAL (bind/listen al boot)
 *                       CAP_RECEIVE_DATA (ogni richiesta in entrata)
 *                       CAP_WRITE_FILE   (res.send → write sul socket)
 *
 *   fs-extra          → CAP_READ_FILE, CAP_WRITE_FILE
 *                       (operazioni async via thread pool)
 *
 *   axios /           → CAP_CONNECT_REMOTE (socket + connect sincrono)
 *   follow-redirects  → CAP_SEND_DATA, CAP_RECEIVE_DATA
 *                       (send/recv via fd_attribution_map)
 *
 *   bcrypt            → CAP_THREAD (clone per worker thread)
 *                       CAP_MEMORY_MANIPULATION (mmap da addon nativo)
 *
 *   lowdb             → CAP_READ_FILE, CAP_WRITE_FILE
 *                       (persistenza JSON su disco)
 *
 *   LOCAL/server.js   → CAP_READ_SYSTEM_STATE (clock_gettime, getpid)
 *                       (solo bootstrap e console.log)
 */

const express = require('express');
const fsExtra = require('fs-extra');
const axios   = require('axios');
const bcrypt  = require('bcrypt');
const dns     = require('dns').promises;
const path    = require('path');
const os      = require('os');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');

const app  = express();
const PORT = 3001;
const DATA = path.join(__dirname, 'data');
const DB   = path.join(DATA, 'db.json');

app.use(express.json());

// ─────────────────────────────────────────────────────────────────────────────
// Inizializzazione — crea la directory dati se non esiste
// ─────────────────────────────────────────────────────────────────────────────
fsExtra.ensureDirSync(DATA);

// ─────────────────────────────────────────────────────────────────────────────
// GET /files
//
// Operazioni su filesystem via fs-extra (thread pool, Category A).
// Al momento di uv__work_submit lo stack contiene frame di fs-extra
// → NodeLeash attribuisce CAP_READ_FILE e CAP_WRITE_FILE a fs-extra
// ─────────────────────────────────────────────────────────────────────────────
app.get('/files', async (req, res) => {
    const file = path.join(DATA, 'test.txt');

    // Scrittura asincrona — thread pool via fs-extra
    await fsExtra.outputFile(file, `NodeLeash test\n${new Date().toISOString()}\n`);

    // Lettura asincrona — thread pool via fs-extra
    const content = await fsExtra.readFile(file, 'utf8');

    // Copia file — due operazioni nel thread pool (read + write)
    await fsExtra.copy(file, file + '.bak');

    // Lettura directory — thread pool
    const entries = await fsExtra.readdir(DATA);

    res.json({
        written : file,
        content : content.trim(),
        entries,
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /outbound
//
// Richiesta HTTP in uscita via axios → follow-redirects (dependency interna).
// socket() viene catturato in pending_socket_map al momento della chiamata
// sincrona (JS frame di axios visibile) e promosso in fd_attribution_map
// dal trace_sys_exit. Le successive send()/recv() vengono attribuite a
// follow-redirects via fd_attribution_map.
//
// Atteso:
//   CAP_CONNECT_REMOTE → axios o follow-redirects
//   CAP_SEND_DATA      → follow-redirects (via fd_attribution_map)
//   CAP_RECEIVE_DATA   → follow-redirects (via fd_attribution_map)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/outbound', async (req, res) => {
    try {
        // GET verso API pubblica
        const resp = await axios.get(
            'https://jsonplaceholder.typicode.com/todos/1',
            { timeout: 5000 }
        );

        // POST con payload
        const post = await axios.post(
            'https://jsonplaceholder.typicode.com/posts',
            { title: 'nodeleash', body: 'test', userId: 1 },
            { timeout: 5000 }
        );

        res.json({
            get_status  : resp.status,
            get_data    : resp.data,
            post_status : post.status,
        });
    } catch (e) {
        res.status(502).json({ error: e.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /crypto
//
// Operazioni crittografiche via bcrypt (native addon + thread pool).
// bcrypt usa un addon .node che esegue nel thread pool di libuv.
// NodeLeash vede:
//   - il frame del .node file via Module suffix detection
//   - il thread pool attribution via uv__work_submit
//
// Atteso:
//   CAP_THREAD             → bcrypt (clone per worker thread)
//   CAP_MEMORY_MANIPULATION→ bcrypt (mmap da OpenSSL/addon)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/crypto', async (req, res) => {
    const secret = 'nodeleash-test-' + Date.now();

    // Hash — eseguito nel thread pool via addon nativo
    const hash = await bcrypt.hash(secret, 10);

    // Verifica — altra operazione nel thread pool
    const valid = await bcrypt.compare(secret, hash);
    const wrong = await bcrypt.compare('wrong-password', hash);

    res.json({ hash, valid, wrong });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /dns
//
// Risoluzione DNS via dns.promises (thread pool, uv__getaddrinfo_work).
// NodeLeash cattura lo stack al momento di uv__work_submit con il frame
// di questo handler visibile.
//
// Atteso:
//   Syscalls di getaddrinfo attribuiti a LOCAL/server.js
// ─────────────────────────────────────────────────────────────────────────────
app.get('/dns', async (req, res) => {
    const hosts = ['google.com', 'github.com', 'example.com'];

    const results = await Promise.all(
        hosts.map(h =>
            dns.lookup(h)
               .then(r => ({ host: h, address: r.address }))
               .catch(e => ({ host: h, error: e.message }))
        )
    );

    res.json({ results });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /db
//
// Persistenza JSON via lowdb (legge e scrive un file JSON).
// lowdb usa fs internamente — le operazioni passano per il thread pool.
//
// Atteso:
//   CAP_READ_FILE  → lowdb
//   CAP_WRITE_FILE → lowdb
// ─────────────────────────────────────────────────────────────────────────────
app.get('/db', async (req, res) => {
    const adapter = new JSONFile(DB);
    const db = new Low(adapter, { entries: [] });

    await db.read();

    db.data.entries.push({
        ts    : Date.now(),
        pid   : process.pid,
        value : Math.random(),
    });

    // Scrivi su disco
    await db.write();

    // Rileggi per confermare
    const db2 = new Low(new JSONFile(DB), {});
    await db2.read();

    res.json({
        written_entries : db.data.entries.length,
        last_entry      : db.data.entries.at(-1),
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /all
//
// Trigger simultaneo di tutte le capability in una sola richiesta.
// Utile per osservare la policy completa dopo pochi cicli.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/all', async (req, res) => {
    const results = {};

    // File
    const f = path.join(DATA, 'all_test.txt');
    await fsExtra.outputFile(f, 'all-test');
    results.file = await fsExtra.readFile(f, 'utf8');

    // Rete uscente
    try {
        const r = await axios.get(
            'https://jsonplaceholder.typicode.com/todos/1',
            { timeout: 4000 }
        );
        results.outbound = r.status;
    } catch (e) {
        results.outbound_error = e.message;
    }

    // Crypto
    results.hash = await bcrypt.hash('all-test', 8);

    // DNS
    results.dns = await dns.lookup('example.com')
                           .then(r => r.address)
                           .catch(() => 'failed');

    // DB
    const db = new Low(new JSONFile(DB), { entries: [] });
    await db.read();
    db.data.entries.push({ ts: Date.now(), route: '/all' });
    await db.write();
    results.db_entries = db.data.entries.length;

    res.json(results);
});

// ─────────────────────────────────────────────────────────────────────────────
// Avvio server
// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║         NodeLeash Capability Attribution Server          ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`  PID  : ${process.pid}`);
    console.log(`  Porta: ${PORT}`);
    console.log('');
    console.log('  Avvia NodeLeash con:');
    console.log(`  sudo ./nodeleash analyze ${process.pid} --debug`);
    console.log('');
    console.log('  Poi esegui le route con curl:');
    console.log(`  curl http://localhost:${PORT}/files`);
    console.log(`  curl http://localhost:${PORT}/outbound`);
    console.log(`  curl http://localhost:${PORT}/crypto`);
    console.log(`  curl http://localhost:${PORT}/dns`);
    console.log(`  curl http://localhost:${PORT}/db`);
    console.log(`  curl http://localhost:${PORT}/all`);
    console.log('');
    console.log('  Ogni route va chiamata almeno 2 volte per permettere');
    console.log('  a V8 di JIT-compilare le funzioni dei pacchetti npm.');
});