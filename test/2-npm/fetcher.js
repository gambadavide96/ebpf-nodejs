'use strict';

// Fetcher module.
// Uses axios to retrieve data from a public API and writes it to disk.

const fs    = require('fs');
const axios = require('axios');

// Fetch all smart home items from the OpenHAB demo server.
// Returns the parsed JSON array of items.
async function fetch() {
    const response = await axios.get('http://demo.openhab.org/rest/items');
    console.log(`[fetcher] received ${response.data.length} items`);
    return response.data;
}

// Write the fetched data to output.json.
function save(data) {
    fs.writeFile('output.json', JSON.stringify(data, null, 2), 'utf8', (err) => {
        if (err) console.error(`[fetcher] write error: ${err.message}`);
    });
}

module.exports = { fetch, save };