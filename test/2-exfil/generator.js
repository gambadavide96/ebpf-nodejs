'use strict';

// Generator module.
// Delegates data processing and file writing entirely to the native addon.
// The addon writes report.txt directly via C++ file I/O — syscalls are
// attributed to the addon package with call path [app.js → processor.js → addon].

const addon = require('./build/Debug/binding.node');

// Processes input via native addon which writes result to report.txt.
function generate(input) {
    const ok = addon.processData(input, 'report.txt');
    if (!ok) throw new Error('addon processing failed');
}

module.exports = { generate };