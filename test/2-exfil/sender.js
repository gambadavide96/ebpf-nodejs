'use strict';

// Sender module.
// Sends data to an HTTP endpoint using an HTTP POST request.
// The request is initiated from the application code, while the underlying
// TCP socket creation and connection are handled internally by Node.js
// through the http/net stack.

const http = require('http');

// Sends body to the given URL via HTTP POST.
// url: { hostname, port, path }
// body: string content to send
function send(url, body) {
    // Define the parameters of the HTTP request.
    const options = {
        hostname: url.hostname,
        port:     url.port,
        path:     url.path,
        method:   'POST',
        headers:  {
            'Content-Type':   'text/plain',
            'Content-Length': Buffer.byteLength(body)
        }
    };

    // Create the HTTP request and register the response callback.
    const req = http.request(options, function onResponse(res) {
        // Discard the response body.
        res.resume();
    });

    // Ignore connection or request errors for this test case.
    req.on('error', function onError() {});

    // Write the request body to the HTTP request stream.
    // At a lower level, Node.js will send this data through the TCP socket.
    req.write(body);

    // Finalize the request and flush any buffered data.
    req.end();
}

module.exports = { send };