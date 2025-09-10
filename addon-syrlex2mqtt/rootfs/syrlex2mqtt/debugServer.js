// debugServer.js
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT_HTTP = 80;
const PORT_HTTPS = 443;

// Zertifikate ausschließlich aus dem gleichen Verzeichnis wie dieses Script
const KEY_PATH = path.join(__dirname, 'server.key');
const CERT_PATH = path.join(__dirname, 'server.cert');

function prettyLogHeaders(headers) {
  try { return JSON.stringify(headers, null, 2); } catch (e) { return String(headers); }
}

function handleRequest(req, res) {
  const localPort = req.socket && req.socket.localPort ? req.socket.localPort : 'unknown';
  console.log("📥 Incoming Request:");
  console.log("  LocalPort:  ", localPort);
  console.log("  RemoteAddr: ", req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : 'unknown');
  console.log("  Method:     ", req.method);
  console.log("  URL:        ", req.url);
  console.log("  Host:       ", req.headers.host || '');
  console.log("  User-Agent: ", req.headers['user-agent'] || '');
  console.log("  Headers:    ", prettyLogHeaders(req.headers));

  let body = '';
  req.on('data', chunk => { body += chunk.toString(); });
  req.on('end', () => {
    if (body && body.length > 0) {
      console.log(`  Body (${body.length} bytes):`);
      console.log(body);
    } else {
      console.log("  Body: {}");
    }

    // Spezielle Antwort für GetBasicCommands (Cloud-like)
    if (req.url && req.url.toLowerCase().includes("getbasiccommands")) {
      console.log("📝 Sending fake GetBasicCommands XML response...");
      const xml = `<?xml version="1.0" encoding="utf-8"?>
<sc version="1.0">
  <d>
    <c n="getSRN" v=""/>
    <c n="getVER" v=""/>
    <c n="getFIR" v=""/>
    <c n="getTYP" v=""/>
    <c n="getCNA" v=""/>
    <c n="getIPA" v=""/>
  </d>
</sc>`;
      res.writeHead(200, { "Content-Type": "text/xml; charset=utf-8" });
      res.end(xml);
      return;
    }

    // Default-Antwort (verhindert Hänger)
    res.writeHead(200, { "Content-Type": "text/xml; charset=utf-8" });
    res.end(`<?xml version="1.0" encoding="utf-8"?><sc version="1.0"><d></d></sc>`);
  });
}

// HTTP-Server immer starten
http.createServer(handleRequest).listen(PORT_HTTP, () => {
  console.log(`🌐 Debug HTTP Server läuft auf Port ${PORT_HTTP}`);
});

// HTTPS-Server nur starten, wenn die Certs im selben Ordner vorhanden sind
try {
  const key = fs.readFileSync(KEY_PATH);
  const cert = fs.readFileSync(CERT_PATH);
  https.createServer({ key, cert }, (req, res) => handleRequest(req, res))
       .listen(PORT_HTTPS, () => {
         console.log(`🔒 Debug HTTPS Server läuft auf Port ${PORT_HTTPS}`);
         console.log(`🔐 Zertifikate geladen von: ${KEY_PATH} & ${CERT_PATH}`);
       });
} catch (err) {
  console.log(`🔒 HTTPS-Server NICHT gestartet: Zertifikate nicht gefunden unter ${KEY_PATH} / ${CERT_PATH}`);
  // kein Throw — HTTP bleibt aktiv
}
