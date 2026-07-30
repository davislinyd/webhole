#!/usr/bin/env node
"use strict";

/**
 * Webhole resolve-then-proxy HTTP CONNECT gateway.
 * Resolves hostnames ONLY via the local DNS stub (never system DNS),
 * then dials via SOCKS5 (by IP) or direct TCP.
 *
 * Config: runtime/gateway-config.json
 */

const dgram = require("dgram");
const fs = require("fs");
const net = require("net");
const path = require("path");

const RUNTIME_DIR = path.join(__dirname, "runtime");
const CONFIG_FILE = path.join(RUNTIME_DIR, "gateway-config.json");
const LOG_FILE = path.join(RUNTIME_DIR, "gateway.log");
const LOG_MAX_BYTES = 256 * 1024;
const DNS_TIMEOUT_MS = 3000;
const CONNECT_TIMEOUT_MS = 20000;

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
    // ignore
  }
}

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
    const listenHost = String(raw.listenHost || "127.0.0.1");
    const listenPort = Number(raw.listenPort) || 18080;
    const dnsHost = String(raw.dnsHost || "127.0.0.1");
    const dnsPort = Number(raw.dnsPort) || 53535;
    const rules = Array.isArray(raw.rules)
      ? raw.rules
          .map((rule) => ({
            hostPattern: String(rule.hostPattern || "")
              .toLowerCase()
              .replace(/\.$/, ""),
            pathPrefix: String(rule.pathPrefix || ""),
            // 0 = connect DIRECT after stub resolve (DNS Enforce / Direct mode)
            socksPort: Number.isInteger(Number(rule.socksPort))
              ? Number(rule.socksPort)
              : Number(rule.port) || 0
          }))
          .filter((rule) => rule.hostPattern)
      : [];
    const fallbackSocksPort = Number(raw.fallbackSocksPort) || 0;
    const mode =
      raw.mode === "global" ? "global" : raw.mode === "enforce" ? "enforce" : "routes";

    return { listenHost, listenPort, dnsHost, dnsPort, rules, fallbackSocksPort, mode };
  } catch (error) {
    appendLog(`config load failed: ${error.message}`);
    process.exit(1);
  }
}

function hostMatches(host, pattern) {
  const normalizedHost = String(host || "")
    .toLowerCase()
    .replace(/\.$/, "");
  const domain = String(pattern || "")
    .toLowerCase()
    .replace(/\.$/, "");
  const suffix = `.${domain}`;

  return normalizedHost === domain || normalizedHost.endsWith(suffix);
}

function selectSocksPort(host, config) {
  // DNS Enforce / Direct: always resolve via stub, then TCP direct (no SOCKS).
  if (config.mode === "enforce") {
    return 0;
  }

  if (config.mode === "global" && config.fallbackSocksPort > 0) {
    return config.fallbackSocksPort;
  }

  for (const rule of config.rules) {
    if (hostMatches(host, rule.hostPattern)) {
      // Explicit 0 = DIRECT after stub resolve (DNS Enforce domain without SOCKS).
      return rule.socksPort > 0 ? rule.socksPort : 0;
    }
  }

  if (config.fallbackSocksPort > 0) {
    return config.fallbackSocksPort;
  }

  return 0;
}

function encodeDnsName(name) {
  const labels = String(name)
    .replace(/\.$/, "")
    .split(".")
    .filter(Boolean);
  const parts = [];

  for (const label of labels) {
    const buf = Buffer.from(label, "ascii");

    if (buf.length === 0 || buf.length > 63) {
      throw new Error("invalid label");
    }

    parts.push(Buffer.from([buf.length]));
    parts.push(buf);
  }

  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function buildDnsQuery(name, qtype) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(Math.floor(Math.random() * 65535), 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const qname = encodeDnsName(name);
  const qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(qtype, 0);
  qtail.writeUInt16BE(1, 2);
  return Buffer.concat([header, qname, qtail]);
}

function parseARecords(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    return [];
  }

  const rcode = buffer.readUInt16BE(2) & 0xf;

  if (rcode !== 0) {
    return [];
  }

  const ancount = buffer.readUInt16BE(6);
  let offset = 12;
  const ips = [];

  function skipName() {
    while (offset < buffer.length) {
      const len = buffer[offset];

      if (len === 0) {
        offset += 1;
        return true;
      }

      if ((len & 0xc0) === 0xc0) {
        offset += 2;
        return true;
      }

      if (len > 63 || offset + 1 + len > buffer.length) {
        return false;
      }

      offset += 1 + len;
    }

    return false;
  }

  const qdcount = buffer.readUInt16BE(4);

  for (let i = 0; i < qdcount; i += 1) {
    if (!skipName() || offset + 4 > buffer.length) {
      return ips;
    }

    offset += 4;
  }

  for (let i = 0; i < ancount; i += 1) {
    if (!skipName() || offset + 10 > buffer.length) {
      break;
    }

    const type = buffer.readUInt16BE(offset);
    const rdlength = buffer.readUInt16BE(offset + 8);
    const start = offset + 10;
    const end = start + rdlength;
    offset = end;

    if (end > buffer.length) {
      break;
    }

    if (type === 1 && rdlength === 4) {
      ips.push(Array.from(buffer.slice(start, end)).join("."));
    }
  }

  return ips;
}

function queryStubA(name, dnsHost, dnsPort) {
  return new Promise((resolve) => {
    let packet;

    try {
      packet = buildDnsQuery(name, 1);
    } catch (_error) {
      resolve([]);
      return;
    }

    const socket = dgram.createSocket("udp4");
    let settled = false;

    function finish(ips) {
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

      resolve(ips);
    }

    const timer = setTimeout(() => finish([]), DNS_TIMEOUT_MS);

    socket.on("message", (msg) => finish(parseARecords(msg)));
    socket.on("error", () => finish([]));
    socket.send(packet, dnsPort, dnsHost, (error) => {
      if (error) {
        finish([]);
      }
    });
  });
}

function isIpv4(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split(".").every((p) => Number(p) <= 255);
}

async function resolveHostViaStub(host, config) {
  if (isIpv4(host)) {
    return host;
  }

  const ips = await queryStubA(host, config.dnsHost, config.dnsPort);
  return ips[0] || "";
}

function socks5Connect(socksHost, socksPort, destIp, destPort) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: socksHost, port: socksPort });
    let step = 0;
    let buf = Buffer.alloc(0);
    let settled = false;

    function fail(error) {
      if (settled) {
        return;
      }

      settled = true;
      socket.destroy();
      reject(error instanceof Error ? error : new Error(String(error)));
    }

    function ok() {
      if (settled) {
        return;
      }

      settled = true;
      socket.removeAllListeners("data");
      resolve(socket);
    }

    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.once("timeout", () => fail(new Error("socks timeout")));
    socket.once("error", fail);
    socket.once("connect", () => {
      // no-auth greeting
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      if (step === 0) {
        if (buf.length < 2) {
          return;
        }

        if (buf[0] !== 0x05 || buf[1] !== 0x00) {
          fail(new Error("socks auth rejected"));
          return;
        }

        buf = buf.slice(2);
        step = 1;

        const ipParts = destIp.split(".").map((p) => Number(p));
        const req = Buffer.alloc(10);
        req[0] = 0x05;
        req[1] = 0x01; // CONNECT
        req[2] = 0x00;
        req[3] = 0x01; // IPv4
        req[4] = ipParts[0];
        req[5] = ipParts[1];
        req[6] = ipParts[2];
        req[7] = ipParts[3];
        req.writeUInt16BE(destPort, 8);
        socket.write(req);
      }

      if (step === 1) {
        if (buf.length < 5) {
          return;
        }

        const atyp = buf[3];
        let need = 4;

        if (atyp === 0x01) {
          need = 10;
        } else if (atyp === 0x03) {
          need = 5 + buf[4] + 2;
        } else if (atyp === 0x04) {
          need = 22;
        } else {
          fail(new Error("socks bad atyp"));
          return;
        }

        if (buf.length < need) {
          return;
        }

        if (buf[1] !== 0x00) {
          fail(new Error(`socks connect failed code=${buf[1]}`));
          return;
        }

        ok();
      }
    });
  });
}

function directConnect(ip, port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: ip, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("direct connect timeout"));
    }, CONNECT_TIMEOUT_MS);

    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function pipeSockets(a, b) {
  a.pipe(b);
  b.pipe(a);
  const cleanup = () => {
    a.destroy();
    b.destroy();
  };
  a.on("error", cleanup);
  b.on("error", cleanup);
  a.on("close", cleanup);
  b.on("close", cleanup);
}

function parseConnect(buffer) {
  const text = buffer.toString("utf8");
  const end = text.indexOf("\r\n\r\n");

  if (end === -1) {
    return null;
  }

  const first = text.slice(0, text.indexOf("\r\n"));
  const match = first.match(/^CONNECT\s+([^:\s]+):(\d+)\s+HTTP\/1\.[01]$/i);

  if (!match) {
    return { error: "only CONNECT supported", headerEnd: end + 4 };
  }

  return {
    host: match[1],
    port: Number(match[2]),
    headerEnd: end + 4,
    rest: buffer.slice(end + 4)
  };
}

function handleClient(client, config) {
  let buf = Buffer.alloc(0);
  let handled = false;

  const onData = async (chunk) => {
    if (handled) {
      return;
    }

    buf = Buffer.concat([buf, chunk]);
    const parsed = parseConnect(buf);

    if (!parsed) {
      if (buf.length > 65536) {
        client.destroy();
      }

      return;
    }

    handled = true;
    client.removeListener("data", onData);

    if (parsed.error) {
      client.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      client.destroy();
      return;
    }

    const { host, port } = parsed;
    const socksPort = selectSocksPort(host, config);

    try {
      const ip = await resolveHostViaStub(host, config);

      if (!ip) {
        appendLog(`RESOLVE_FAIL ${host}`);
        client.write("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
        client.destroy();
        return;
      }

      let upstream;

      if (socksPort > 0) {
        appendLog(`CONNECT ${host}:${port} -> ${ip} via socks ${socksPort}`);
        upstream = await socks5Connect("127.0.0.1", socksPort, ip, port);
      } else {
        appendLog(`CONNECT ${host}:${port} -> ${ip} direct`);
        upstream = await directConnect(ip, port);
      }

      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");

      if (parsed.rest && parsed.rest.length) {
        upstream.write(parsed.rest);
      }

      pipeSockets(client, upstream);
    } catch (error) {
      appendLog(`CONNECT_ERR ${host}:${port} ${error.message}`);

      try {
        client.write("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
      } catch (_error) {
        // ignore
      }

      client.destroy();
    }
  };

  client.on("data", onData);
  client.on("error", () => client.destroy());
  client.setTimeout(CONNECT_TIMEOUT_MS, () => {
    if (!handled) {
      client.destroy();
    }
  });
}

function main() {
  const config = loadConfig();

  if (config.listenHost !== "127.0.0.1" && config.listenHost !== "::1") {
    appendLog(`refusing non-loopback ${config.listenHost}`);
    process.exit(1);
  }

  const server = net.createServer((client) => handleClient(client, config));

  server.on("error", (error) => {
    appendLog(`server error: ${error.message}`);
    process.exit(1);
  });

  server.listen(config.listenPort, config.listenHost, () => {
    appendLog(
      `listening ${config.listenHost}:${config.listenPort} dns=${config.dnsHost}:${config.dnsPort} mode=${config.mode} rules=${config.rules.length}`
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
