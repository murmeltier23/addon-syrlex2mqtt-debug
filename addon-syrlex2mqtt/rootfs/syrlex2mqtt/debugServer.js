// debugServer.js
const http = require('http');
const https = require('https');
const fs = require('fs');

const PORT_HTTP = 80;
const PORT_HTTPS = 443;

// Fake Zertifikate (werden schon im Add-on generiert)
const options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.cert')
};

// Handler für alle Requests
function handleRequest(req, res) {
  console.log(`➡️  ${req.method} ${req.url}`);
  let body = '';
  req.on('data', chunk => { body += chunk.toString(); });
  req.on('end', () => {
    if (body.length > 0) console.log('📦 Body:', body);
    res.writeHead(200, { 'Content-Type': 'text/xml' });
    res.end('<?xml version="1.0" encoding="utf-8"?><sc version="1.0"><d></d></sc>');
  });
}

// Server starten
http.createServer(handleRequest).listen(PORT_HTTP, () => {
  console.log(`🌐 Debug HTTP Server läuft auf Port ${PORT_HTTP}`);
});
https.createServer(options, handleRequest).listen(PORT_HTTPS, () => {
  console.log(`🔒 Debug HTTPS Server läuft auf Port ${PORT_HTTPS}`);
});
