#!/usr/bin/env node
// SPDX-License-Identifier: MIT
"use strict";

const mqtt = require("async-mqtt");
const fs = require('fs');
const express = require('express');
const xml = require('xml2js');
const https = require('https')
const http = require('http')

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
const syrHttpPort = (process.env.HTTP_PORT == undefined || process.env.HTTP_PORT == "") ? 80 : process.env.HTTP_PORT
const syrHttpsPort = (process.env.HTTPS_PORT == undefined || process.env.HTTPS_PORT == "") ? 443 : process.env.HTTPS_PORT;

// https certificates
var key = fs.readFileSync(__dirname + '/server.key');
var cert = fs.readFileSync(__dirname + '/server.cert');

var credentials = {
  key: key,
  cert: cert,
};

const xmlStart = '<?xml version="1.0" encoding="utf-8"?><sc version="1.0"><d>';
const xmlEnd = '</d></sc>';
const basicC = ["getSRN", "getVER", "getFIR", "getTYP", "getCNA", "getIPA"];
const leakageDetectionC = ["getAB", "getCEL"];
const allC = [ "getSRN", "getVER", "getFIR", "getTYP", "getCNA", "getIPA",
               "getSV1", "getRPD", "getFLO", "getLAR", "getTOR", "getRG1", "getCS1", "getRES", "getSS1", "getSV1", "getSTA", "getCOF", "getRTH", "getRTM", "getRPW",
               ...leakageDetectionC,  // adding the leakage detection commands here also for those devices that do not support them as it does no harm
               ...additionalProperties.map(p => "get" + p)];

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

function formatTimestamp(timestamp) {
  const date = new Date(timestamp*1000);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  const offset = -date.getTimezoneOffset();
  const offsetHours = String(Math.floor(offset / 60)).padStart(2, "0");
  const offsetMinutes = String(offset % 60).padStart(2, "0");
  const offsetStr = `${offset >= 0 ? "+" : "-"}${offsetHours}:${offsetMinutes}`;
  return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}${offsetStr}`;
}

function removeNullProperties(obj) {
  var remainingProps = Object.keys(obj);
  for(const prop of remainingProps) {
    if(obj[prop] == null) {
      delete obj[prop];
    }
  }
}

function popcount(n) {
  // see https://stackoverflow.com/questions/43122082/efficiently-count-the-number-of-bits-in-an-integer-in-javascript
  n = n - ((n >> 1) & 0x55555555)
  n = (n & 0x33333333) + ((n >> 2) & 0x33333333)
  return ((n + (n >> 4) & 0xF0F0F0F) * 0x1010101) >> 24
}

function reverse7MaskBits(n) {
  // reverse the lowest 7 bits (ignore the others)
  var n7 = n & 0x7F;
  var reverseString = n7.toString(2).padStart(7,'0').split('').reverse().join('');
  return parseInt(reverseString, 2);
}

function fromRegenerationWeekDaysMask(num) {
  if(num == 0) {
    return "(None)";
  }

  var bFullname = (popcount(num) <= 2);

  var res = "";
  if(num & 0x01) {
    res += ((res.length > 0) ? ", " : "") + (bFullname ? "Monday" : "Mon");
  }
  if(num & 0x02) {
    res += ((res.length > 0) ? ", " : "") + (bFullname ? "Tuesday" : "Tue");
  }
  if(num & 0x04) {
    res += ((res.length > 0) ? ", " : "") + (bFullname ? "Wednesday" : "Wed");
  }
  if(num & 0x08) {
    res += ((res.length > 0) ? ", " : "") + (bFullname ? "Thursday" : "Thu");
  }
  if(num & 0x10) {
    res += ((res.length > 0) ? ", " : "") + (bFullname ? "Friday" : "Fri");
  }
  if(num & 0x20) {
    res += ((res.length > 0) ? ", " : "") + (bFullname ? "Saturday" : "Sat");
  }
  if(num & 0x40) {
    res += ((res.length > 0) ? ", " : "") + (bFullname ? "Sunday" : "Sun");
  }

  var idx = res.lastIndexOf(", ");
  if (idx>=0) {
    res = res.substring(0,idx) + " & " + res.substring(idx+2);
  }
  return "Every " + res;
}

function toRegenerationWeekDaysMask(str) {
	var res = 0;
  var matches = str.match(/(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/g);
  if(matches == null) {
  	return res;
  }
  for(var m of matches) {
    switch (m) {
      case 'Mon': res |= 0x01; break;
      case 'Tue': res |= 0x02; break;
      case 'Wed': res |= 0x04; break;
      case 'Thu': res |= 0x08; break;
      case 'Fri': res |= 0x10; break;
      case 'Sat': res |= 0x20; break;
      case 'Sun': res |= 0x40; break;
    }
  }
  return res;
}

function calculateRegenerationWeekDaysOptions() {
  // spent some extra effort here to get a "sensible" order
  // "(None)", all entries with only one week day, all entries with two week days, all entries with three week days, ... => popcount
  // Inside each "bucket" Monday comes before Tuesday, before Wednesday, ... => count downwards, reverse7MaskBits

  var res = ["(None)"];
  for(var numOnes = 1; numOnes <= 7; numOnes++)
  {
    for(var i = 0x7F; i > 0; i--) {
      if(popcount(i) == numOnes) {
        res.push(fromRegenerationWeekDaysMask(reverse7MaskBits(i)));
      }
    }
  }
  return res;
}

function generateAvailability(identifier) {
  var availability_topic = 'syr/' + identifier + '/availability';
  var availability = [
    {topic: 'syr/syrlex2mqtt/state'},
    {topic: availability_topic}
  ];
  return availability;
}

function generateMQTTDevice(model, snr, sw_version, url) {
  var mqttDevice = {
    identifiers: [ snr ],
    mf: "Syr",
    name: model,
    model: model,
    sw: sw_version,
    cu: url,

    identifier() {
      return (this.model + this.identifiers[0]).toLowerCase();
    }
  };

  return mqttDevice;
}

async function sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, sensorname, humanreadable_name, device_class, entity_category, unit_of_measurement, icon = 'mdi:water') {
  var topic = 'homeassistant/sensor/syr_watersoftening/' + mqttDevice.identifier() + '_' + sensorname + '/config';
  var payload = {
        name: humanreadable_name,
        device_class: device_class,
        entity_category: entity_category,
        unit_of_measurement: unit_of_measurement,
        icon: icon,
        state_topic: 'syr/' + mqttDevice.identifier() + '/state',
        availability: generateAvailability(mqttDevice.identifier()),
        value_template: '{{ value_json.'+ sensorname +'}}',
        unique_id: mqttDevice.identifier() + "_" + sensorname,
        device: mqttDevice
      };
  removeNullProperties(payload);
  await mqttclient.publish(topic, JSON.stringify(payload), {retain: true})
}

async function sendMQTTBinarySensorDiscoveryMessage(mqttclient, mqttDevice, sensorname, humanreadable_name, device_class, entity_category) {
  var topic = 'homeassistant/binary_sensor/syr_watersoftening/' + mqttDevice.identifier() + '_' + sensorname + '/config';
  var payload = {
        name: humanreadable_name,
        device_class: device_class,
        entity_category: entity_category,
        state_topic: 'syr/' + mqttDevice.identifier() + '/state',
        availability: generateAvailability(mqttDevice.identifier()),
        value_template: '{{ value_json.'+ sensorname +'}}',
        unique_id: mqttDevice.identifier() + "_" + sensorname,
        device: mqttDevice
      };
  removeNullProperties(payload);
  await mqttclient.publish(topic, JSON.stringify(payload), {retain: true})
}


async function sendMQTTNumberDiscoveryMessage(mqttclient, mqttDevice, numbername, humanreadable_name, device_class, entity_category, unit_of_measurement, minimum, maximum, icon = 'mdi:water') {
  var topic = 'homeassistant/number/syr_watersoftening/' + mqttDevice.identifier() + '_' + numbername + '/config';
  var payload = {
        name: humanreadable_name,
        device_class: device_class,
        entity_category: entity_category,
        unit_of_measurement: unit_of_measurement,
        icon: icon,
        state_topic: 'syr/' + mqttDevice.identifier() + '/state',
        command_topic: 'syr/' + mqttDevice.identifier() + '/set_' + numbername,
        availability: generateAvailability(mqttDevice.identifier()),
        value_template: '{{ value_json.'+ numbername +'}}',
        unique_id: mqttDevice.identifier() + "_" + numbername,
        min: minimum,
        max: maximum,
        mode: 'box',
        device: mqttDevice
      };
  removeNullProperties(payload);
  await mqttclient.publish(topic, JSON.stringify(payload), {retain: true})
}

async function sendMQTTSelectDiscoveryMessage(mqttclient, mqttDevice, selectname, humanreadable_name, device_class, entity_category, options, icon = 'mdi:water') {
  var topic = 'homeassistant/select/syr_watersoftening/' + mqttDevice.identifier() + '_' + selectname + '/config';
  var payload = {
        name: humanreadable_name,
        device_class: device_class,
        entity_category: entity_category,
        options: options,
        icon: icon,
        state_topic: 'syr/' + mqttDevice.identifier() + '/state',
        command_topic: 'syr/' + mqttDevice.identifier() + '/set_' + selectname,
        availability: generateAvailability(mqttDevice.identifier()),
        value_template: '{{ value_json.'+ selectname +'}}',
        unique_id: mqttDevice.identifier() + "_" + selectname,
        device: mqttDevice
      };
  removeNullProperties(payload);
  await mqttclient.publish(topic, JSON.stringify(payload), {retain: true})
}


async function sendMQTTValveDiscoveryMessage(mqttclient, mqttDevice, valvename, humanreadable_name, device_class, entity_category, icon = 'mdi:pipe-valve') {
  var topic = 'homeassistant/valve/syr_watersoftening/' + mqttDevice.identifier() + '_' + valvename + '/config';
  var payload = {
        name: humanreadable_name,
        device_class: device_class,
        entity_category: entity_category,
        icon: icon,
        state_topic: 'syr/' + mqttDevice.identifier() + '/state',
        command_topic: 'syr/' + mqttDevice.identifier() + '/set_' + valvename,
        availability: generateAvailability(mqttDevice.identifier()),
        value_template: '{{ value_json.'+ valvename +'}}',
        unique_id: mqttDevice.identifier() + "_" + valvename,
        device: mqttDevice
      };
  removeNullProperties(payload);
  await mqttclient.publish(topic, JSON.stringify(payload), {retain: true})
}


async function sendMQTTTextDiscoveryMessage(mqttclient, mqttDevice, textname, humanreadable_name, device_class, entity_category, pattern, icon = 'mdi:water') {
  var topic = 'homeassistant/text/syr_watersoftening/' + mqttDevice.identifier() + '_' + textname + '/config';
  var payload = {
        name: humanreadable_name,
        device_class: device_class,
        entity_category: entity_category,
        icon: icon,
        state_topic: 'syr/' + mqttDevice.identifier() + '/state',
        command_topic: 'syr/' + mqttDevice.identifier() + '/set_' + textname,
        availability: generateAvailability(mqttDevice.identifier()),
        value_template: '{{ value_json.'+ textname +'}}',
        unique_id: mqttDevice.identifier() + "_" + textname,
        mode: 'text',
        pattern: pattern,
        device: mqttDevice
      };
  removeNullProperties(payload);
  await mqttclient.publish(topic, JSON.stringify(payload), {retain: true})
}


async function sendMQTTButtonDiscoveryMessage(mqttclient, mqttDevice, buttonname, humanreadable_name, entity_category) {
  var topic = 'homeassistant/button/syr_watersoftening/' + mqttDevice.identifier() + '_' + buttonname + '/config';
  var payload = {
        name: humanreadable_name,
        entity_category: entity_category,
        command_topic: 'syr/' + mqttDevice.identifier() + '/set_' + buttonname,
        availability: generateAvailability(mqttDevice.identifier()),
        unique_id: mqttDevice.identifier() + "_" + buttonname,
        device: mqttDevice
      };
  removeNullProperties(payload);
  await mqttclient.publish(topic, JSON.stringify(payload), {retain: true})
}


async function sendMQTTAvailabilityMessage(mqttclient, mqttDevice) {
  var availability_topic = 'syr/' + mqttDevice.identifier() + '/availability';

  await mqttclient.publish(availability_topic, 'online', {retain: true})
  await mqttclient.publish('syr/syrlex2mqtt/state', 'online', {retain: true})
}

async function sendMQTTStateMessage(mqttclient, model, snr, payload) {
  var identifier = (model + snr).toLowerCase();
  var topic = 'syr/' + identifier + '/state'

  await mqttclient.publish(topic, JSON.stringify(payload))
}

async function getDevice(model, snr, sw_version, url) {
  var identifier = (model + snr).toLowerCase();
  if(!devicesMap.has(identifier)) {
    logInfo("New MQTTDevice '" + identifier + "' at " + url);
    var mqttDevice = generateMQTTDevice(model, snr, sw_version, url);
    var device = {
      mqttDevice: mqttDevice,
      hasLeakageProtection: (model.valueOf() == 'LEXplus10SL'),
      setters: { }
    };
    devicesMap.set(identifier, device);

    await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'current_water_flow', 'Current Water Flow', null, null, 'l/min', 'mdi:water');
    await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'salt_remaining', 'Salt Remaining', null, null, 'weeks', 'mdi:cup');
    await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'remaining_resin_capacity', 'Remaining Resin Capacity', null, 'diagnostic', '%', 'mdi:water-percent');
    await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'remaining_water_capacity', 'Remaining Water Capacity', 'water', 'diagnostic', 'L', 'mdi:water');
    await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'total_water_consumption', 'Total Water Consumption', 'water', null, 'L', 'mdi:water');
    await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'number_of_regenerations', 'Number of Regenerations', null, 'diagnostic', null, 'mdi:counter');
    await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'last_regeneration', 'Last Regeneration', 'timestamp', null, null, 'mdi:clock-time-four-outline');
    await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'status_message', 'Status Message', null, null, null, 'mdi:message-text');
    await sendMQTTBinarySensorDiscoveryMessage(mqttclient, mqttDevice, 'regeneration_running', 'Regeneration Running', 'running', null);
  
    await sendMQTTButtonDiscoveryMessage(mqttclient, mqttDevice, 'start_regeneration', 'Start Regeneration', null);
    
    await sendMQTTNumberDiscoveryMessage(mqttclient, mqttDevice, 'salt_in_stock', 'Salt in Stock', 'weight', null, 'kg', 0, 25, 'mdi:cup');
    await sendMQTTSelectDiscoveryMessage(mqttclient, mqttDevice, 'regeneration_week_days', 'Regeneration Week Days', null, 'config', calculateRegenerationWeekDaysOptions(), 'mdi:calendar-clock');
    await sendMQTTNumberDiscoveryMessage(mqttclient, mqttDevice, 'regeneration_interval', 'Regeneration Interval', null, 'config', 'days', 1, 10, 'mdi:calendar-clock');
    await sendMQTTTextDiscoveryMessage(mqttclient, mqttDevice, 'regeneration_time', 'Regeneration Time (Hour:Minutes)', null, 'config', "\\d?\\d:\\d\\d", 'mdi:clock');

    if(device.hasLeakageProtection) {
      await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, 'water_temperature', 'Water Temperature', 'temperature', null, '°C', 'mdi:thermometer-water');
      await sendMQTTValveDiscoveryMessage(mqttclient, mqttDevice, "valve", "Valve", "water", null, 'mdi:pipe-valve');
    }

    for(var p of additionalProperties) {
      await sendMQTTSensorDiscoveryMessage(mqttclient, mqttDevice, p, p, null, null, null, 'mdi:water');
    }
  
    await sendMQTTAvailabilityMessage(mqttclient, mqttDevice);
  }

  return devicesMap.get(identifier);
}

function getXmlBasicC() {
	let ret = "";
	basicC.forEach(c => ret += '<c n="' + c + '" v=""/>');
	return ret;
}

function getXmlAllC(device) {
	let ret = "";
	allC.forEach(getter => {
    var setter = getter.replace("get","set");
    if(device.setters[setter]) {
      var value = device.setters[setter];
      ret += '<c n="' + setter + '" v="' + value + '"/>';
      delete device.setters[setter];
    } else {
      ret += '<c n="' + getter + '" v=""/>'
    }
  });

  var remainingSetters = Object.keys(device.setters);
  for(const remainingSetter of remainingSetters) {
    var value = device.setters[remainingSetter];
    ret += '<c n="' + remainingSetter + '" v="' + value + '"/>';
    delete device.setters[remainingSetter];
  }

	return ret;
}

function parseToValueMap(json) {
  var valueMap = new Map();
		
  for(let i = 0; i < json.length; i++) {
    let id = json[i].$.n;
    let value = json[i].$.v;
    valueMap.set(id, value);
  }

  return valueMap;
}

// normalize IPv6 mapped addresses and strip prefix ::ffff:
function normalizeRemoteAddress(addr) {
  if(!addr) return addr;
  if(addr.startsWith("::ffff:")) return addr.split(":").pop();
  return addr;
}

// macht einen POST (application/x-www-form-urlencoded) mit xml=<xml> zum Gerät
function postXmlToDevice(host, path, xmlPayload, port = 80, useTls = false) {
  return new Promise((resolve, reject) => {
    try {
      const body = 'xml=' + encodeURIComponent(xmlPayload);
      const opts = {
        hostname: host,
        port: port,
        path: path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body, 'utf8')
        },
        timeout: 8000
      };

      const reqModule = useTls ? https : http;
      const creq = reqModule.request(opts, (cres) => {
        let data = '';
        cres.setEncoding('utf8');
        cres.on('data', chunk => data += chunk);
        cres.on('end', () => {
          resolve({ statusCode: cres.statusCode, headers: cres.headers, body: data });
        });
      });

      creq.on('error', (err) => reject(err));
      creq.on('timeout', () => { creq.destroy(new Error('timeout')); });

      creq.write(body);
      creq.end();
    } catch (err) {
      reject(err);
    }
  });
}

// Hilfsfunktion: extrahiere XML-String aus express req.body (form-urlencoded oder raw text)
function extractXmlFromReqBody(req) {
  // 1) falls express.urlencoded({extended:true}) gesetzt ist, req.body.xml ist wahrscheinlich vorhanden
  if (req && req.body && typeof req.body === 'object' && req.body.xml) {
    return req.body.xml;
  }
  // 2) falls express.text() oder raw body: req.body kann ein String sein ("xml=...") oder reine XML
  if (req && typeof req.body === 'string') {
    let s = req.body;
    if (s.startsWith("xml=")) {
      try {
        return decodeURIComponent(s.slice(4));
      } catch(e) {
        // falls decodeURIComponent scheitert, gib den Rest roh zurück
        return s.slice(4);
      }
    }
    return s;
  }
  return null;
}


async function basicCommands(req, res) {
  // Content-Type wie gewohnt
  res.set('Content-Type', 'text/xml');

  // Erkenne Absender-IP (verwende Socket, Fallback Header)
  const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || '';
  const clientIp = normalizeRemoteAddress(String(rawIp));

  // Baue die XML anfrage mit den Basic-Gettern (dies ist der POST-Body, den wir an das Gerät senden)
  const requestXml = xmlStart + getXmlBasicC() + xmlEnd;

  // Der Pfad, den wir am Gerät ansprechen wollen (das gleiche, wie das Gerät später selbst an unseren Server postet)
  const devicePath = '/WebServices/SyrConnectLimexWebService.asmx/GetAllCommands';

  try {
    logVerbose(`📡 Proxying Basic -> POST to device ${clientIp}${devicePath} ...`);
    // POST an das Gerät (HTTP, Port 80). Falls du TLS brauchst, setze useTls=true und Port 443.
    const proxyResponse = await postXmlToDevice(clientIp, devicePath, requestXml, 80, false);

    if(proxyResponse && proxyResponse.statusCode == 200 && proxyResponse.body && proxyResponse.body.length > 0) {
      // Proxy hat geantwortet — evtl. "xml=..." Prefix entfernen
      let body = proxyResponse.body;
      if(body.startsWith("xml=")) {
        try { body = decodeURIComponent(body.slice(4)); } catch(e) { body = body.slice(4); }
      }

      // Logge die empfangene, ausgefüllte XML (verbose)
      logVerbose("📥 Response from device (proxy):\n" + body);

      // Versuche, die XML zu parsen und (wie allCommands) in MQTT zu verarbeiten
      try {
        const parsed = await xml.parseStringPromise(body);
        if(parsed && parsed.sc && parsed.sc.d && parsed.sc.d[0] && parsed.sc.d[0].c) {
          const json = parsed.sc.d[0].c;
          const valueMap = parseToValueMap(json);

          const model = valueMap.get('getCNA');
          const snr = valueMap.get('getSRN');
          const sw_version = valueMap.get('getVER');
          const url = "http://" + valueMap.get('getIPA');

          // getDevice legt Discovery Messages an falls neu
          const device = await getDevice(model, snr, sw_version, url);

          // Prüfe, ob alle Werte für Payload vorliegen (wie original in allCommands)
          var allFound = true;
          for(let i = 0; i < allC.length; i++) {
            if(!valueMap.has(allC[i])) {
              allFound = false;
              break;
            }
          }

          if(allFound) {
            // bau Payload (vorsichtig, mit Defaults)
            const payload = {
              current_water_flow: valueMap.get('getFLO') || null,
              salt_remaining: valueMap.get('getSS1') || null,
              remaining_resin_capacity: valueMap.get('getCS1') || null,
              remaining_water_capacity: valueMap.get('getRES') || null,
              total_water_consumption: valueMap.get('getCOF') || null,
              number_of_regenerations: valueMap.get('getTOR') || null,
              last_regeneration: (valueMap.get('getLAR')) ? formatTimestamp(valueMap.get('getLAR')) : null,
              status_message: valueMap.get('getSTA') || null,
              salt_in_stock: valueMap.get('getSV1') || null,
              regeneration_interval: valueMap.get('getRPD') || null,
              regeneration_week_days: valueMap.get('getRPW') ? fromRegenerationWeekDaysMask(valueMap.get('getRPW')) : null,
              regeneration_time: (valueMap.get('getRTH') && valueMap.get('getRTM')) ? String(valueMap.get('getRTH')).padStart(2,"0") + ":" + String(valueMap.get('getRTM')).padStart(2,"0") : null,
              regeneration_running: valueMap.get('getRG1') == "1" ? 'ON' : 'OFF'
            };
            for(var p of additionalProperties) {
              payload[p] = valueMap.get('get' + p) || null;
            }

            if(device.hasLeakageProtection) {
              const cel = valueMap.get('getCEL');
              payload['water_temperature'] = (cel != null) ? (cel / 10.0) : null;
              const ab = valueMap.get('getAB');
              payload['valve'] = (ab == "1") ? 'open' : 'closed';
            }

            logVerbose('Publishing state message from proxy response:\n' + JSON.stringify(payload));
            sendMQTTStateMessage(mqttclient, model, snr, payload);
          }
        }
      } catch(parseErr) {
        logInfo("Fehler beim Parsen der proxied Antwort: " + parseErr);
      }

      // Zum Schluss: die vom Gerät zurückgegebene (gefüllte) XML direkt an den originierenden Client zurückgeben
      res.set('Content-Type', 'text/xml');
      res.send(body);
      logVerbose("Response to basicCommands (proxied) sent to client.");
      return;
    } else {
      // fallback: keine Antwort vom Gerät -> normale Basic-Response (leere Getter)
      const fallback = xmlStart + getXmlBasicC() + xmlEnd;
      res.set('Content-Type', 'text/xml');
      res.send(fallback);
      logVerbose("No proxy response; sent fallback basicCommands response.");
      return;
    }
  } catch (err) {
    // Fehler beim Proxy-POST -> Fallback
    logInfo("Error proxying Basic->device: " + err);
    const fallback = xmlStart + getXmlBasicC() + xmlEnd;
    res.set('Content-Type', 'text/xml');
    res.send(fallback);
    return;
  }
}


function allCommands(req, res) {
  // Extrahiere XML aus req (form-urlencoded oder raw)
  let xmlBody = extractXmlFromReqBody(req);

  if(!xmlBody) {
    // nichts da -> antworten mit leerem allC (wie vorher)
    res.set('Content-Type', 'text/xml');
    const responseXml = xmlStart + getXmlAllC({setters:{}}) + xmlEnd;
    res.send(responseXml);
    logVerbose("allCommands: no body found, sent empty response.");
    return;
  }

  // Falls xmlBody beginnt mit "xml=" (falls text middleware genutzt wurde), säubern
  if(xmlBody.startsWith("xml=")) {
    try { xmlBody = decodeURIComponent(xmlBody.slice(4)); } catch(e) { xmlBody = xmlBody.slice(4); }
  }

  xml.parseStringPromise(xmlBody).then(async function(result) {
    try {
      let json = result.sc.d[0].c;
      var valueMap = parseToValueMap(json);

      var model = valueMap.get('getCNA');
      var snr = valueMap.get('getSRN');
      var sw_version = valueMap.get('getVER');
      var url = "http://" + valueMap.get('getIPA');

      var device = await getDevice(model, snr, sw_version, url);

      var allFound = true;
      for(let i = 0; i < allC.length; i++) {
        if(!valueMap.has(allC[i])) {
          allFound = false;
          break;
        }
      }

      if(allFound) {
        // sichere Leseoperationen mit Defaults
        const larp = valueMap.get('getLAR');
        const payload = {
          current_water_flow: valueMap.get('getFLO') || null,
          salt_remaining: valueMap.get('getSS1') || null,
          remaining_resin_capacity: valueMap.get('getCS1') || null,
          remaining_water_capacity: valueMap.get('getRES') || null,
          total_water_consumption: valueMap.get('getCOF') || null,
          number_of_regenerations: valueMap.get('getTOR') || null,
          last_regeneration: larp ? formatTimestamp(larp) : null,
          status_message: valueMap.get('getSTA') || null,
          salt_in_stock: valueMap.get('getSV1') || null,
          regeneration_interval: valueMap.get('getRPD') || null,
          regeneration_week_days: valueMap.get('getRPW') ? fromRegenerationWeekDaysMask(valueMap.get('getRPW')) : null,
          regeneration_time: (valueMap.get('getRTH') && valueMap.get('getRTM')) ? String(valueMap.get('getRTH')).padStart(2,"0") + ":" + String(valueMap.get('getRTM')).padStart(2,"0") : null,
          regeneration_running: valueMap.get('getRG1') == "1" ? 'ON' : 'OFF'
        };

        for(var p of additionalProperties) {
          payload[p] = valueMap.get('get' + p) || null;
        }

        if(device.hasLeakageProtection) {
          const cel = valueMap.get('getCEL');
          payload['water_temperature'] = (cel != null) ? (cel / 10.0) : null;
          const ab = valueMap.get('getAB');
          payload['valve'] = (ab == "1") ? 'open' : 'closed';
        }

        logVerbose('Publishing state message:\n' + JSON.stringify(payload));
        sendMQTTStateMessage(mqttclient, model, snr, payload);
      }

      // send response (device expects values for getters/setters)
      res.set('Content-Type', 'text/xml');
      let responseXml = xmlStart + getXmlAllC(device) + xmlEnd;
      res.send(responseXml);
      logVerbose("Response to allCommands: " + responseXml);
    } catch (innerErr) {
      logInfo("allCommands processing error: " + innerErr);
      // fallback response
      res.set('Content-Type', 'text/xml');
      res.send(xmlStart + getXmlAllC({setters:{}}) + xmlEnd);
    }
  })
  .catch(function(err) {
    logInfo("XML parse error in allCommands: " + err);
    res.set('Content-Type', 'text/xml');
    res.send(xmlStart + getXmlAllC({setters:{}}) + xmlEnd);
  });
}

async function initWebServer() {
  const app = express();

  // for parsing application/x-www-form-urlencoded
  app.use(express.urlencoded({ extended: true }));

  app.use((req, res, next) => {
	  logVerbose(
	    "📥 Request for " +
	      req.hostname +
	      req.url +
	      " via port " +
	      req.socket.localPort +
	      " from " +
	      req.socket.remoteAddress +
	      ((req.body.xml == undefined) ? "" : ("\n" + req.body.xml))
	  );
    next();
  });

  // BasicCommands: GET + POST
  app.get(
    '/WebServices/SyrConnectLimexWebService.asmx/GetBasicCommands',
    (req, res) => {
      basicCommands(req, res);
    }
  );

  app.post(
    '/WebServices/SyrConnectLimexWebService.asmx/GetBasicCommands',
    (req, res) => {
      basicCommands(req, res);
    }
  );

  // AllCommands: GET + POST
  app.post(
    '/WebServices/SyrConnectLimexWebService.asmx/GetAllCommands',
    (req, res) => {
      allCommands(req, res);
    }
  );

  app.get(
    '/WebServices/SyrConnectLimexWebService.asmx/GetAllCommands',
    (req, res) => {
      allCommands(req, res);
    }
  );


  // HTTP starten
  httpServer = http.createServer(app).listen(syrHttpPort, () => {
    logInfo(`🌍 HTTP listening on port ${syrHttpPort}`);
  });

  // HTTPS starten
  httpsServer = https.createServer(credentials, app).listen(syrHttpsPort, () => {
    logInfo(`🔒 HTTPS listening on port ${syrHttpsPort}`);
  });

  return app;
}


logInfo("Connecting to MQTT server '" + brokerUrl + "' with username '" + username + "'");

const mqttclient = mqtt.connect(brokerUrl,
                                {
                                  username: username,
                                  password: password,
                                  will: {
                                    topic: 'syr/syrlex2mqtt/state',
                                    payload: 'offline',
                                    retain: true
                                  }
                                });

const handleConnect = async () => {
  logInfo('Connected to MQTT server');

  mqttclient.subscribe('syr/#');
  mqttclient.subscribe('homeassistant/status');

  initWebServer().then(() => {
    logInfo("Webserver started listening");
  }).catch(err => {
          logInfo("Failed to initWebServer: " + err);
          process.exit(-1);
  });
}

const messageReceived = async (topic, message) => {
  const regex = /^syr\/([\w-]*)\/set_([\w-]*)$/;
  const match = topic.match(regex);

  if(match == null || match.length != 3)
  {
    return;
  }

  var device_identifier = match[1];
  var entity_name = match[2];

  if(entity_name == "state") {
    return;
  }

  logVerbose('Received message for topic ' + topic + ':\n' + message);

  if(!devicesMap.has(device_identifier)) {
    return;
  }
  var device = devicesMap.get(device_identifier);

  if(entity_name == 'salt_in_stock') {
    var salt = message.toString();
    device.setters["setSV1"] = salt;
  } else if(entity_name == 'regeneration_interval') {
    var regeneration_interval = message.toString();
    device.setters["setRPD"] = regeneration_interval;
  } else if(entity_name == 'regeneration_week_days') {
    var regeneration_week_days = message.toString();
    device.setters["setRPW"] = toRegenerationWeekDaysMask(regeneration_week_days);
  } else if(entity_name == 'regeneration_time') {
    var regeneration_time = message.toString();
    var matches = regeneration_time.match(/(\d?\d):(\d\d)/);
    if((matches != null) && (matches.length == 3)) {
      device.setters["setRTH"] = matches[1].toString();
      device.setters["setRTM"] = matches[2].toString();
    }
  } else if(entity_name == 'start_regeneration') {
    if(message == "PRESS") {
       device.setters["setSIR"] = "0";
    }
  } else if(entity_name == 'valve') {
    if(message == "OPEN") {
       device.setters["setAB"] = "1";
    } else if(message == "CLOSE") {
       device.setters["setAB"] = "2";
    }
  }
  
}

mqttclient.on('connect', handleConnect);

mqttclient.on('message', messageReceived);




