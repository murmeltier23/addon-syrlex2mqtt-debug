const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');

// Ports
const syrHttpPort = 80;
const syrHttpsPort = 443;

// SSL-Dateien laden (oder Dummy erstellen)
let credentials;
try {
  const key = fs.readFileSync(__dirname + '/server.key');
  const cert = fs.readFileSync(__dirname + '/server.cert');
  credentials = { key: key, cert: cert };
} catch (err) {
  console.warn("⚠️ Keine Zertifikate gefunden – HTTPS startet evtl. nicht!");
  credentials = { key: '', cert: '' };
}

const app = express();

// Parser für Text/XML/JSON
app.use(express.text({ type: ['application/xml', 'text/xml', 'application/soap+xml', 'text/*'] }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Logger für alle Requests
app.all('*', (req, res) => {
  console.log("📥 Incoming Request:");
  console.log("  Method:", req.method);
  console.log("  URL   :", req.originalUrl);
  console.log("  Host  :", req.hostname);
  console.log("  Headers:", JSON.stringify(req.headers, null, 2));
  console.log("  Body  :", req.body);

  // Einfacher Dummy-Response (damit Gerät nicht hängen bleibt)
  const responseXml = '<?xml version="1.0" encoding="utf-8"?><sc version="1.0"><d></d></sc>';
  res.set('Content-Type', 'text/xml; charset=utf-8');
  res.send(responseXml);
});

// HTTP starten
http.createServer(app).listen(syrHttpPort, () => {
  console.log(`🌐 Debug HTTP Server läuft auf Port ${syrHttpPort}`);
});

// HTTPS starten (falls Zertifikate da sind)
if (credentials.key && credentials.cert) {
  https.createServer(credentials, app).listen(syrHttpsPort, () => {
    console.log(`🔒 Debug HTTPS Server läuft auf Port ${syrHttpsPort}`);
  });
} else {
  console.log("⚠️ HTTPS wurde nicht gestartet (fehlende Zertifikate)");
}
