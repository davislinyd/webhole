#!/usr/bin/env node
"use strict";

/**
 * Webhole local DNS stub: longest-suffix rules → UDP upstream forwarder.
 * Config: runtime/dns-config.json (written by host.js).
 * Bind: 127.0.0.1 only.
 */

const dgram = require("dgram");
const fs = require("fs");
const net = require("net");
const path = require("path");

const RUNTIME_DIR = path.join(__dirname, "runtime");
const CONFIG_FILE = path.join(RUNTIME_DIR, "dns-config.json");
const LOG_FILE = path.join(RUNTIME_DIR, "dns.log");
const LOG_MAX_BYTES = 256 * 1024;
const UPSTREAM_TIMEOUT_MS = 2000;
const UPSTREAM_RETRIES = 1;
const CACHE_MIN_TTL_S = 30;
const CACHE_MAX_TTL_S = 300;
const CACHE_MAX_ENTRIES = 512;

const QTYPE_NAMES = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  255: "ANY"
};

function appendLog(message) {
  try {
    fs.mkdirSync(RUNTIME_DIR, { recursive: true, mode: 0o700 });
    fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${message}\n`);

    const stat = fs.statSync(LOG_FILE);

    if (stat.size > LOG_MAX_BYTES) {
      const text = fs.readFileSync(LOG_FILE, "utf8");
      fs.writeFileSync(LOG_FILE, text.slice(-Math.floor(LOG_MAX_BYTES / 2)));
    }
  } catch (_error) {
    // ignore log failures
  }
}

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));

    if (!raw || typeof raw !== "object") {
      throw new Error("invalid config root");
    }

    const listenHost = String(raw.listenHost || "127.0.0.1");
    const listenPort = Number(raw.listenPort) || 53535;
    const defaultUpstream = normalizeUpstream(raw.defaultUpstream) || {
      nameserver: "1.1.1.1",
      nameserverPort: 53
    };
    const rules = Array.isArray(raw.rules) ? raw.rules.map(normalizeRule).filter(Boolean) : [];

    rules.sort((a, b) => b.domain.length - a.domain.length);

    return { listenHost, listenPort, defaultUpstream, rules };
  } catch (error) {
    appendLog(`config load failed: ${error.message}`);
    return {
      listenHost: "127.0.0.1",
      listenPort: 53535,
      defaultUpstream: { nameserver: "1.1.1.1", nameserverPort: 53 },
      rules: []
    };
  }
}

function normalizeUpstream(value) {
  if (!value || typeof value !== "object") {
    return null;
  }

  const nameserver = String(value.nameserver || "").trim();
  const nameserverPort = Number(value.nameserverPort) || 53;

  if (!isIpLiteral(nameserver) || !Number.isInteger(nameserverPort) || nameserverPort < 1 || nameserverPort > 65535) {
    return null;
  }

  return { nameserver, nameserverPort };
}

function normalizeRule(rule) {
  if (!rule || typeof rule !== "object" || rule.enabled === false) {
    return null;
  }

  const domain = String(rule.domain || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");

  if (!domain || !/^[a-z0-9._-]+$/.test(domain)) {
    return null;
  }

  const upstream = normalizeUpstream(rule.upstream || {
    nameserver: rule.nameserver,
    nameserverPort: rule.nameserverPort
  });

  if (!upstream) {
    return null;
  }

  return {
    id: String(rule.id || domain),
    domain,
    upstream,
    label: String(rule.label || rule.id || domain)
  };
}

function isIpLiteral(value) {
  if (net.isIP(value)) {
    return true;
  }

  return false;
}

function isLoopbackAddress(address) {
  if (!address) {
    return false;
  }

  if (address === "127.0.0.1" || address === "::1" || address === "localhost") {
    return true;
  }

  // IPv4-mapped IPv6 ::ffff:127.0.0.1
  if (address.startsWith("::ffff:127.")) {
    return true;
  }

  return address.startsWith("127.");
}

function parseQuestion(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    return null;
  }

  const qdcount = buffer.readUInt16BE(4);

  if (qdcount < 1) {
    return null;
  }

  let offset = 12;
  const labels = [];

  while (offset < buffer.length) {
    const len = buffer[offset];

    if (len === 0) {
      offset += 1;
      break;
    }

    if ((len & 0xc0) === 0xc0) {
      return null;
    }

    if (len > 63 || offset + 1 + len > buffer.length) {
      return null;
    }

    labels.push(buffer.toString("ascii", offset + 1, offset + 1 + len).toLowerCase());
    offset += 1 + len;
  }

  if (offset + 4 > buffer.length) {
    return null;
  }

  const qtype = buffer.readUInt16BE(offset);
  const qclass = buffer.readUInt16BE(offset + 2);
  const qname = labels.join(".");

  return { qname, qtype, qclass, headerEnd: offset + 4 };
}

function matchRule(qname, rules) {
  const name = String(qname || "")
    .toLowerCase()
    .replace(/\.$/, "");

  for (const rule of rules) {
    const domain = rule.domain;

    if (name === domain || name.endsWith(`.${domain}`)) {
      return rule;
    }
  }

  return null;
}

function buildServFail(query) {
  if (!Buffer.isBuffer(query) || query.length < 12) {
    return null;
  }

  const response = Buffer.from(query);
  // QR=1, copy opcode, AA=0, TC=0, RD copy, RA=0, RCODE=SERVFAIL(2)
  const flags = response.readUInt16BE(2);
  const rd = flags & 0x0100;
  response.writeUInt16BE(0x8000 | rd | 0x0002, 2);
  response.writeUInt16BE(0, 6); // ANCOUNT
  response.writeUInt16BE(0, 8); // NSCOUNT
  response.writeUInt16BE(0, 10); // ARCOUNT
  return response.slice(0, Math.min(response.length, 512));
}

function extractMinTtl(response) {
  if (!Buffer.isBuffer(response) || response.length < 12) {
    return CACHE_MIN_TTL_S;
  }

  const ancount = response.readUInt16BE(6);
  let offset = 12;
  let minTtl = CACHE_MAX_TTL_S;
  let found = false;

  function skipName() {
    while (offset < response.length) {
      const len = response[offset];

      if (len === 0) {
        offset += 1;
        return true;
      }

      if ((len & 0xc0) === 0xc0) {
        offset += 2;
        return true;
      }

      if (len > 63 || offset + 1 + len > response.length) {
        return false;
      }

      offset += 1 + len;
    }

    return false;
  }

  // skip question
  const qdcount = response.readUInt16BE(4);

  for (let i = 0; i < qdcount; i += 1) {
    if (!skipName() || offset + 4 > response.length) {
      return CACHE_MIN_TTL_S;
    }

    offset += 4;
  }

  for (let i = 0; i < ancount; i += 1) {
    if (!skipName() || offset + 10 > response.length) {
      break;
    }

    const ttl = response.readUInt32BE(offset + 4);
    const rdlength = response.readUInt16BE(offset + 8);
    offset += 10 + rdlength;

    if (Number.isFinite(ttl) && ttl >= 0) {
      found = true;
      minTtl = Math.min(minTtl, ttl);
    }
  }

  if (!found) {
    return CACHE_MIN_TTL_S;
  }

  return Math.max(CACHE_MIN_TTL_S, Math.min(CACHE_MAX_TTL_S, minTtl));
}

function forwardUdp(query, upstream) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    let settled = false;
    let attempts = 0;

    function finish(result) {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timer);

      try {
        socket.close();
      } catch (_error) {
        // ignore
      }

      resolve(result);
    }

    function sendOnce() {
      attempts += 1;
      socket.send(query, upstream.nameserverPort, upstream.nameserver, (error) => {
        if (error && attempts > UPSTREAM_RETRIES + 1) {
          finish(null);
        }
      });
    }

    const timer = setTimeout(() => {
      if (attempts <= UPSTREAM_RETRIES) {
        sendOnce();
        // extend wait once
        setTimeout(() => finish(null), UPSTREAM_TIMEOUT_MS);
        return;
      }

      finish(null);
    }, UPSTREAM_TIMEOUT_MS);

    socket.on("message", (msg) => {
      finish(msg);
    });

    socket.on("error", () => {
      finish(null);
    });

    sendOnce();
  });
}

function parseAnswersSummary(response) {
  if (!Buffer.isBuffer(response) || response.length < 12) {
    return [];
  }

  const answers = [];
  const ancount = response.readUInt16BE(6);
  let offset = 12;

  function skipName() {
    while (offset < response.length) {
      const len = response[offset];

      if (len === 0) {
        offset += 1;
        return true;
      }

      if ((len & 0xc0) === 0xc0) {
        offset += 2;
        return true;
      }

      if (len > 63 || offset + 1 + len > response.length) {
        return false;
      }

      offset += 1 + len;
    }

    return false;
  }

  const qdcount = response.readUInt16BE(4);

  for (let i = 0; i < qdcount; i += 1) {
    if (!skipName() || offset + 4 > response.length) {
      return answers;
    }

    offset += 4;
  }

  for (let i = 0; i < ancount && answers.length < 8; i += 1) {
    if (!skipName() || offset + 10 > response.length) {
      break;
    }

    const type = response.readUInt16BE(offset);
    const rdlength = response.readUInt16BE(offset + 8);
    const rdataStart = offset + 10;
    const rdataEnd = rdataStart + rdlength;
    offset = rdataEnd;

    if (rdataEnd > response.length) {
      break;
    }

    if (type === 1 && rdlength === 4) {
      answers.push(Array.from(response.slice(rdataStart, rdataEnd)).join("."));
    } else if (type === 28 && rdlength === 16) {
      const parts = [];

      for (let j = 0; j < 16; j += 2) {
        parts.push(response.readUInt16BE(rdataStart + j).toString(16));
      }

      answers.push(parts.join(":"));
    } else {
      answers.push(QTYPE_NAMES[type] || `TYPE${type}`);
    }
  }

  return answers;
}

const cache = new Map();

function cacheGet(key) {
  const entry = cache.get(key);

  if (!entry) {
    return null;
  }

  if (Date.now() >= entry.expiresAt) {
    cache.delete(key);
    return null;
  }

  return entry.packet;
}

function cacheSet(key, packet) {
  if (cache.size >= CACHE_MAX_ENTRIES) {
    const first = cache.keys().next().value;
    cache.delete(first);
  }

  const ttlS = extractMinTtl(packet);
  cache.set(key, {
    packet: Buffer.from(packet),
    expiresAt: Date.now() + ttlS * 1000
  });
}

function rewriteTxId(packet, originalQuery) {
  if (!Buffer.isBuffer(packet) || packet.length < 2 || !Buffer.isBuffer(originalQuery) || originalQuery.length < 2) {
    return packet;
  }

  const out = Buffer.from(packet);
  out[0] = originalQuery[0];
  out[1] = originalQuery[1];
  return out;
}

async function handleQuery(msg, rinfo, config, server) {
  if (!isLoopbackAddress(rinfo.address)) {
    appendLog(`drop non-loopback ${rinfo.address}`);
    return;
  }

  const question = parseQuestion(msg);

  if (!question) {
    appendLog("drop unparseable query");
    return;
  }

  const rule = matchRule(question.qname, config.rules);
  const upstream = rule ? rule.upstream : config.defaultUpstream;
  const ruleLabel = rule ? rule.label : "default";
  const cacheKey = `${question.qname}|${question.qtype}|${upstream.nameserver}|${upstream.nameserverPort}`;
  const started = Date.now();

  const cached = cacheGet(cacheKey);

  if (cached) {
    const reply = rewriteTxId(cached, msg);
    server.send(reply, rinfo.port, rinfo.address);
    appendLog(
      `HIT ${question.qname} ${QTYPE_NAMES[question.qtype] || question.qtype} via=${ruleLabel} ${Date.now() - started}ms`
    );
    return;
  }

  const upstreamResponse = await forwardUdp(msg, upstream);
  const elapsed = Date.now() - started;

  if (!upstreamResponse) {
    const fail = buildServFail(msg);

    if (fail) {
      server.send(fail, rinfo.port, rinfo.address);
    }

    appendLog(
      `FAIL ${question.qname} ${QTYPE_NAMES[question.qtype] || question.qtype} via=${ruleLabel} up=${upstream.nameserver}:${upstream.nameserverPort} ${elapsed}ms`
    );
    return;
  }

  cacheSet(cacheKey, upstreamResponse);
  server.send(upstreamResponse, rinfo.port, rinfo.address);

  const answers = parseAnswersSummary(upstreamResponse);
  const rcode = upstreamResponse.readUInt16BE(2) & 0xf;
  appendLog(
    `OK ${question.qname} ${QTYPE_NAMES[question.qtype] || question.qtype} rcode=${rcode} via=${ruleLabel} up=${upstream.nameserver}:${upstream.nameserverPort} answers=${answers.join(",") || "-"} ${elapsed}ms`
  );
}

function main() {
  const config = loadConfig();

  if (config.listenHost !== "127.0.0.1" && config.listenHost !== "::1") {
    appendLog(`refusing non-loopback listenHost=${config.listenHost}`);
    process.exit(1);
  }

  const server = dgram.createSocket("udp4");

  server.on("message", (msg, rinfo) => {
    handleQuery(msg, rinfo, config, server).catch((error) => {
      appendLog(`handler error: ${error.message}`);
    });
  });

  server.on("error", (error) => {
    appendLog(`server error: ${error.message}`);
    process.exit(1);
  });

  server.bind(config.listenPort, config.listenHost, () => {
    appendLog(
      `listening udp ${config.listenHost}:${config.listenPort} rules=${config.rules.length} default=${config.defaultUpstream.nameserver}:${config.defaultUpstream.nameserverPort}`
    );
  });

  process.on("SIGTERM", () => {
    appendLog("SIGTERM");
    server.close(() => process.exit(0));
  });

  process.on("SIGINT", () => {
    appendLog("SIGINT");
    server.close(() => process.exit(0));
  });
}

main();
