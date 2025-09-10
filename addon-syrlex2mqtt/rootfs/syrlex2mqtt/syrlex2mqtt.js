#!/usr/bin/env node
// SPDX-License-Identifier: MIT
"use strict";

const mqtt = require("async-mqtt");
const fs = require('fs');
const express = require('express');
const xml = require('xml2js');
const https = require('https');
const http = require('http');

if(!process.env.MQTT_SERVER || !process.env.MQTT_USER || !process.env.MQTT_PASSWORD) {
  logInfo("Please set variables MQTT_SERVER, MQTT_USER and MQTT_PASSWORD");
  process.exit(1);
}

// mqtt configuration
const brokerUrl = process.env.MQTT_SERVER;
const username = process.env.MQTT_USER;
const password = process.env.MQTT_PASSWORD;

const verboseLogging = process.env.VERBOSE_LOGGING && ((process.env.VERBOSE_LOGGING == "1") || (process.env.VERBOSE_LOGGING.toUpperCase() == "TRUE"));
const additionalProperties = (process.env.ADDITIONAL_PROPERTIES == undefined || process.env.ADDITIONAL_PROPERTIES == "") ? [] : process.env.ADDITIONAL_PROPERTIES.split(",").map(s => s.trim());

// syr connect configuration
const syrHttpPort = (process.env.HTTP_PORT == undefined || process.env.HTTP_PORT == "") ? 80 : process.env.HTTP_PORT;
const syrHttpsPort = (process.env.HTTPS_PORT == undefined || process.env.HTTPS_PORT == "") ? 443 : process.env.HTTPS_PORT;

// https certificates (liegen im gleichen Ordner wie diese Datei)
var key = fs.readFileSync(__dirname + '/server.key');
var cert = fs.readFileSync(__dirname + '/server.cert');

var credentials = { key: key, cert: cert };

const xmlStart = '<?xml version="1.0" encoding="utf-8"?><sc version="1.0"><d>';
const xmlEnd = '</d></sc>';
const basicC = ["getSRN", "getVER", "getFIR", "getTYP", "getCNA", "getIPA"];
const leakageDetectionC = ["getAB", "getCEL"];
const allC = [
  "getSRN", "getVER", "getFIR", "getTYP", "getCNA", "getIPA",
  "getSV1", "getRPD", "getFLO", "getLAR", "getTOR", "getRG1", "getCS1", "getRES", "getSS1", "getSV1", "getSTA", "getCOF", "getRTH", "getRTM", "getRPW",
  ...leakageDetectionC,
  ...additionalProperties.map(p => "get" + p)
];

var httpServer;
var httpsServer;
var devicesMap = new Map();

function logInfo(msg) {
	console.log("[" + new Date().toISOString() + "] " + msg);
}

function logVerbose(msg) {
  if(verboseLogging) {
	  console.log("[" + new Date().toISOString() + "] " + msg);
  }
}

// ⬇️ nur Änderung hier: Middleware erweitert, um Port/Protokoll zu loggen
async function initWebServer() {
	const app = express();

	httpServer = http.createServer(app).listen(syrHttpPort, () => {
    logInfo(`HTTP Server läuft auf Port ${syrHttpPort}`);
  });
	httpsServer = https.createServer(credentials, app).listen(syrHttpsPort, () => {
    logInfo(`HTTPS Server läuft auf Port ${syrHttpsPort}`);
  });

	// für parsing application/x-www-form-urlencoded
	app.use(express.urlencoded({extended: true}));

	app.use((req, res, next) => {
    const proto = req.secure ? "HTTPS" : "HTTP";
    const port = req.socket.localPort;
		logVerbose(`[${proto}:${port}] Request für ${req.hostname}${req.url}` + ((req.body.xml == undefined) ? "" : ("\n" + req.body.xml)));
		next();
	});
	
	app.post('/WebServices/SyrConnectLimexWebService.asmx/GetBasicCommands', (req, res) => {
		basicCommands(req, res);
	});
	app.post('/GetBasicCommands', (req, res) => {
	 	basicCommands(req, res);
	});
	
	app.post('/WebServices/SyrConnectLimexWebService.asmx/GetAllCommands', (req, res) => {
		allCommands(req, res);
	});
	app.post('/GetAllCommands', (req, res) => {
		allCommands(req, res);
	});
	
	return app;
}
