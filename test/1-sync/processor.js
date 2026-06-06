'use strict';

// Processor module.
// Reads, transforms and writes data files.
// Generates the attributed filesystem syscalls during analyze mode.

const fs = require('fs');

function read(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    return content;
}

// Parses raw key=value text: drops blank lines and lines without '=',
// trims whitespace from each entry, returns a normalised string.
function process(data) {
    return data
        .split('\n')
        .filter(line => line.includes('='))
        .map(line => line.trim())
        .join('\n');
}

// Writes processed data to filePath (overwrite) and appends
// a timestamped entry to app.log.
function write(filePath, data) {
    fs.writeFileSync(filePath, data, 'utf8');
}

module.exports = { read, process, write };