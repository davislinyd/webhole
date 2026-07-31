#!/usr/bin/env node
"use strict";

const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const { execFile, spawn } = require("child_process");

const HOST_ALIAS_RE = /^[A-Za-z0-9._-]+$/;
const DOMAIN_RE = /^[a-z0-9._-]+$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const PROXY_HOST = "127.0.0.1";
const BASE_PORT = 1080;
// Avoid 5353 (often used by mDNSResponder on macOS).
const DNS_DEFAULT_PORT = 53535;
const DNS_FORWARD_BASE_PORT = 15353;
const GATEWAY_DEFAULT_PORT = 18080;
const MAX_TUNNELS = 8;
const MAX_DNS_RULES = 50;
const MAX_DNS_FORWARDS = 16;
const MAX_INCLUDE_DEPTH = 16;
// ProxyCommand / jump hosts often need longer than a few seconds.
const TUNNEL_READY_TIMEOUT_MS = 30000;
const TUNNEL_POLL_MS = 200;
const SSH_STDERR_LIMIT = 4000;
const RUNTIME_DIR = path.join(__dirname, "runtime");
const STATE_FILE = path.join(RUNTIME_DIR, "state.json");
const SSH_LOG_FILE = path.join(RUNTIME_DIR, "ssh.log");
const DNS_LOG_FILE = path.join(RUNTIME_DIR, "dns.log");
const DNS_CONFIG_FILE = path.join(RUNTIME_DIR, "dns-config.json");
const DNS_RESOLVER_MANIFEST = path.join(RUNTIME_DIR, "resolver-files.json");
const DNS_DAEMON_SCRIPT = path.join(__dirname, "dns-daemon.js");
const GATEWAY_SCRIPT = path.join(__dirname, "proxy-gateway.js");
const GATEWAY_CONFIG_FILE = path.join(RUNTIME_DIR, "gateway-config.json");
const DEFAULT_SSH_CONFIG = path.join(os.homedir(), ".ssh", "config");
const RESOLVER_DIR = "/etc/resolver";

function ensureRuntimeDir() {
  fs.mkdirSync(RUNTIME_DIR, { recursive: true, mode: 0o700 });
}

function readRawState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
  } catch (error) {
    return {};
  }
}

function normalizeGatewayState(rawGateway) {
  if (!rawGateway || typeof rawGateway !== "object") {
    return null;
  }

  const pid = Number(rawGateway.pid);
  const port = Number(rawGateway.port);

  if (!Number.isInteger(pid) || pid <= 0 || !Number.isInteger(port) || port < 1) {
    return null;
  }

  return {
    pid,
    port,
    startedAt: rawGateway.startedAt || ""
  };
}

function normalizeDnsState(rawDns) {
  if (!rawDns || typeof rawDns !== "object") {
    return null;
  }

  const pid = Number(rawDns.pid);
  const port = Number(rawDns.port);

  if (!Number.isInteger(pid) || pid <= 0 || !Number.isInteger(port) || port < 1) {
    return null;
  }

  const forwards = {};

  if (rawDns.forwards && typeof rawDns.forwards === "object") {
    for (const [key, entry] of Object.entries(rawDns.forwards)) {
      if (!entry || typeof entry !== "object") {
        continue;
      }

      const fPid = Number(entry.pid);
      const localPort = Number(entry.localPort);

      if (!Number.isInteger(fPid) || fPid <= 0 || !Number.isInteger(localPort) || localPort < 1) {
        continue;
      }

      forwards[key] = {
        pid: fPid,
        localPort,
        hostAlias: String(entry.hostAlias || ""),
        remoteDns: String(entry.remoteDns || ""),
        remotePort: Number(entry.remotePort) || 53,
        startedAt: entry.startedAt || ""
      };
    }
  }

  return {
    pid,
    port,
    startedAt: rawDns.startedAt || "",
    forwards,
    enforce: rawDns.enforce !== false,
    resolverInstalled: Boolean(rawDns.resolverInstalled),
    gateway: normalizeGatewayState(rawDns.gateway)
  };
}

function normalizeState(raw) {
  if (!raw || typeof raw !== "object") {
    return { tunnels: {}, dns: null };
  }

  const tunnels = {};

  if (raw.tunnels && typeof raw.tunnels === "object") {
    for (const [hostAlias, entry] of Object.entries(raw.tunnels)) {
      if (!entry || typeof entry !== "object") {
        continue;
      }

      const pid = Number(entry.pid);
      const port = Number(entry.port);

      if (!HOST_ALIAS_RE.test(hostAlias) || !Number.isInteger(pid) || !Number.isInteger(port)) {
        continue;
      }

      tunnels[hostAlias] = {
        pid,
        port,
        startedAt: entry.startedAt || ""
      };
    }
  } else if (raw.pid && raw.hostAlias) {
    // Legacy single-tunnel state.
    const hostAlias = String(raw.hostAlias);
    const pid = Number(raw.pid);

    if (HOST_ALIAS_RE.test(hostAlias) && Number.isInteger(pid)) {
      tunnels[hostAlias] = {
        pid,
        port: BASE_PORT,
        startedAt: raw.startedAt || ""
      };
    }
  }

  return {
    tunnels,
    dns: normalizeDnsState(raw.dns)
  };
}

function readState() {
  return normalizeState(readRawState());
}

function writeState(partial) {
  ensureRuntimeDir();
  const current = readState();
  const tunnels =
    partial && Object.prototype.hasOwnProperty.call(partial, "tunnels")
      ? partial.tunnels && typeof partial.tunnels === "object"
        ? partial.tunnels
        : {}
      : current.tunnels;
  const dns = partial && Object.prototype.hasOwnProperty.call(partial, "dns")
    ? normalizeDnsState(partial.dns)
    : current.dns;

  const hasTunnels = Object.keys(tunnels).length > 0;
  const hasDns = Boolean(dns);

  if (!hasTunnels && !hasDns) {
    clearState();
    return;
  }

  const payload = { tunnels };

  if (hasDns) {
    payload.dns = dns;
  }

  fs.writeFileSync(STATE_FILE, JSON.stringify(payload, null, 2));
}

function appendSshLog(message) {
  ensureRuntimeDir();
  fs.appendFileSync(SSH_LOG_FILE, `[${new Date().toISOString()}] ${message}\n`);
}

function clearState() {
  try {
    fs.unlinkSync(STATE_FILE);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
}

function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false;
  }

  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return false;
  }
}

function readProcessCommand(pid) {
  return new Promise((resolve) => {
    if (!Number.isInteger(pid) || pid <= 0) {
      resolve("");
      return;
    }

    execFile("ps", ["-p", String(pid), "-o", "command="], (error, stdout) => {
      resolve(error ? "" : stdout.trim());
    });
  });
}

async function isRecordedSshProcess(pid, port) {
  const command = await readProcessCommand(pid);

  return (
    command.includes("ssh") &&
    command.includes("-N") &&
    command.includes("-D") &&
    command.includes(`${PROXY_HOST}:${port}`)
  );
}

function isPortOpen(port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: PROXY_HOST, port });
    let settled = false;

    function finish(result) {
      if (settled) {
        return;
      }

      settled = true;
      socket.destroy();
      resolve(result);
    }

    socket.setTimeout(500);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

function wait(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function validateHostAlias(hostAlias) {
  if (!HOST_ALIAS_RE.test(hostAlias)) {
    return {
      ok: false,
      state: "error",
      message: `Invalid SSH Host alias: ${hostAlias || "(empty)"}`
    };
  }

  return null;
}

function usedPorts(tunnels) {
  return new Set(Object.values(tunnels).map((entry) => entry.port));
}

function allocatePort(tunnels, preferredPort) {
  const taken = usedPorts(tunnels);

  if (Number.isInteger(preferredPort) && preferredPort >= BASE_PORT && !taken.has(preferredPort)) {
    return preferredPort;
  }

  for (let offset = 0; offset < MAX_TUNNELS * 4; offset += 1) {
    const port = BASE_PORT + offset;

    if (!taken.has(port)) {
      return port;
    }
  }

  return null;
}

async function inspectTunnel(hostAlias, entry) {
  const pid = Number(entry.pid);
  const port = Number(entry.port);
  const portOpen = await isPortOpen(port);

  if (!pid || !isProcessAlive(pid)) {
    if (portOpen) {
      return {
        hostAlias,
        port,
        pid: pid || 0,
        state: "error",
        message: `${PROXY_HOST}:${port} is in use by an unknown process.`
      };
    }

    return null;
  }

  if (!(await isRecordedSshProcess(pid, port))) {
    return {
      hostAlias,
      port,
      pid,
      state: "error",
      message: `Recorded PID for ${hostAlias} is no longer the Webhole ssh process.`
    };
  }

  return {
    hostAlias,
    port,
    pid,
    state: portOpen ? "connected" : "starting"
  };
}

async function reconcileState() {
  const state = readState();
  const nextTunnels = {};
  const reports = [];
  let hasError = false;

  for (const [hostAlias, entry] of Object.entries(state.tunnels)) {
    const report = await inspectTunnel(hostAlias, entry);

    if (!report) {
      continue;
    }

    if (report.state === "error") {
      hasError = true;
      reports.push(report);
      continue;
    }

    nextTunnels[hostAlias] = {
      pid: report.pid,
      port: report.port,
      startedAt: entry.startedAt || ""
    };
    reports.push(report);
  }

  writeState({ tunnels: nextTunnels });
  return { tunnels: nextTunnels, dns: readState().dns, reports, hasError };
}

function aggregateState(reports) {
  if (!reports.length) {
    return "disconnected";
  }

  if (reports.every((item) => item.state === "connected")) {
    return "connected";
  }

  if (reports.some((item) => item.state === "connected" || item.state === "starting")) {
    if (reports.some((item) => item.state === "error")) {
      return "partial";
    }

    if (reports.some((item) => item.state === "starting")) {
      return "starting";
    }

    return "partial";
  }

  if (reports.some((item) => item.state === "error")) {
    return "error";
  }

  return "disconnected";
}

async function getStatus() {
  const { reports, hasError } = await reconcileState();
  const state = aggregateState(reports);
  const connected = reports.filter((item) => item.state === "connected" || item.state === "starting");

  if (hasError && connected.length === 0) {
    return {
      ok: false,
      state: "error",
      message: reports.find((item) => item.state === "error")?.message || "Tunnel error",
      tunnels: reports
    };
  }

  return {
    ok: true,
    state,
    tunnels: reports,
    message:
      state === "partial"
        ? reports
            .filter((item) => item.state === "error")
            .map((item) => item.message)
            .join(" ")
        : undefined
  };
}

async function stopTunnelProcess(pid) {
  if (!pid || !isProcessAlive(pid)) {
    return;
  }

  try {
    process.kill(pid, "SIGTERM");
  } catch (_error) {
    return;
  }

  for (let i = 0; i < 20; i += 1) {
    if (!isProcessAlive(pid)) {
      return;
    }

    await wait(100);
  }

  if (isProcessAlive(pid)) {
    try {
      process.kill(pid, "SIGKILL");
    } catch (_error) {
      // already gone
    }
  }
}

async function disconnectHost(hostAlias, entry) {
  const report = await inspectTunnel(hostAlias, entry);

  if (!report || report.state === "error") {
    return;
  }

  await stopTunnelProcess(report.pid);
  appendSshLog(`stopped ssh tunnel for ${hostAlias} on ${PROXY_HOST}:${report.port}`);
}

function trimSshStderr(stderr) {
  const text = String(stderr || "").trim();

  if (!text) {
    return "";
  }

  if (text.length <= SSH_STDERR_LIMIT) {
    return text;
  }

  return text.slice(-SSH_STDERR_LIMIT);
}

function formatSshFailure(hostAlias, port, reason, stderr) {
  const detail = trimSshStderr(stderr);
  const base = `${reason} for ${hostAlias} (${PROXY_HOST}:${port})`;
  return detail ? `${base}: ${detail}` : `${base}.`;
}

async function spawnTunnel(hostAlias, port) {
  ensureRuntimeDir();
  appendSshLog(`starting ssh tunnel for ${hostAlias} on ${PROXY_HOST}:${port}`);

  let stderrBuf = "";
  const child = spawn(
    "ssh",
    [
      "-N",
      "-n",
      "-D",
      `${PROXY_HOST}:${port}`,
      // Independent session: ControlMaster mux clients often exit while
      // forwards attach to another process, which breaks PID tracking.
      "-o",
      "ControlMaster=no",
      "-o",
      "ControlPath=none",
      "-o",
      "ExitOnForwardFailure=yes",
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=20",
      "-o",
      "ServerAliveInterval=30",
      "-o",
      "ServerAliveCountMax=3",
      hostAlias
    ],
    {
      detached: true,
      stdio: ["ignore", "ignore", "pipe"]
    }
  );

  if (child.stderr) {
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      const text = String(chunk);
      stderrBuf += text;

      for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();

        if (trimmed) {
          appendSshLog(`ssh[${hostAlias}] ${trimmed}`);
        }
      }
    });
  }

  child.once("error", (error) => {
    appendSshLog(`ssh spawn failed for ${hostAlias}: ${error.message}`);
    stderrBuf += `${error.message}\n`;
  });

  child.unref();

  if (!child.pid) {
    return {
      ok: false,
      hostAlias,
      port,
      state: "error",
      message: formatSshFailure(hostAlias, port, "ssh failed to start", stderrBuf)
    };
  }

  const deadline = Date.now() + TUNNEL_READY_TIMEOUT_MS;

  while (Date.now() < deadline) {
    if (!isProcessAlive(child.pid)) {
      // Allow stderr flush after exit.
      await wait(150);
      const message = formatSshFailure(
        hostAlias,
        port,
        "ssh exited before opening SOCKS5 port",
        stderrBuf
      );
      appendSshLog(message);
      return {
        ok: false,
        hostAlias,
        port,
        state: "error",
        message
      };
    }

    if (await isPortOpen(port)) {
      appendSshLog(`ssh tunnel ready for ${hostAlias} on ${PROXY_HOST}:${port} pid=${child.pid}`);
      return {
        ok: true,
        hostAlias,
        port,
        pid: child.pid,
        state: "connected",
        startedAt: new Date().toISOString()
      };
    }

    await wait(TUNNEL_POLL_MS);
  }

  const timeoutMessage = formatSshFailure(
    hostAlias,
    port,
    `ssh did not open SOCKS5 within ${TUNNEL_READY_TIMEOUT_MS / 1000}s`,
    stderrBuf
  );
  appendSshLog(timeoutMessage);
  await stopTunnelProcess(child.pid);

  return {
    ok: false,
    hostAlias,
    port,
    state: "error",
    message: timeoutMessage
  };
}

function normalizeHostAliases(message) {
  const values = [];

  if (Array.isArray(message.hostAliases)) {
    values.push(...message.hostAliases);
  }

  if (message.hostAlias) {
    values.push(message.hostAlias);
  }

  const seen = new Set();
  const result = [];

  for (const value of values) {
    const hostAlias = String(value || "").trim();

    if (!hostAlias || seen.has(hostAlias)) {
      continue;
    }

    seen.add(hostAlias);
    result.push(hostAlias);
  }

  return result;
}

async function connectTunnels(hostAliases) {
  if (!hostAliases.length) {
    return {
      ok: false,
      state: "error",
      message: "No SSH Host aliases provided.",
      tunnels: []
    };
  }

  if (hostAliases.length > MAX_TUNNELS) {
    return {
      ok: false,
      state: "error",
      message: `At most ${MAX_TUNNELS} tunnels are supported.`,
      tunnels: []
    };
  }

  for (const hostAlias of hostAliases) {
    const validationError = validateHostAlias(hostAlias);

    if (validationError) {
      return { ...validationError, tunnels: [] };
    }
  }

  const reconciled = await reconcileState();
  let tunnels = { ...reconciled.tunnels };

  // Stop tunnels that are no longer requested.
  for (const [hostAlias, entry] of Object.entries(tunnels)) {
    if (!hostAliases.includes(hostAlias)) {
      await disconnectHost(hostAlias, entry);
      delete tunnels[hostAlias];
    }
  }

  writeState({ tunnels });

  const reports = [];

  for (const hostAlias of hostAliases) {
    const existing = tunnels[hostAlias];

    if (existing) {
      const report = await inspectTunnel(hostAlias, existing);

      if (report && (report.state === "connected" || report.state === "starting")) {
        reports.push(report);
        continue;
      }

      if (existing.pid) {
        await stopTunnelProcess(existing.pid);
      }

      delete tunnels[hostAlias];
      writeState({ tunnels });
    }

    const preferredPort = existing?.port;
    const port = allocatePort(tunnels, preferredPort);

    if (!port) {
      reports.push({
        hostAlias,
        port: 0,
        state: "error",
        message: "No free local SOCKS port available."
      });
      continue;
    }

    if (await isPortOpen(port)) {
      // Port taken by something else; try next free ports.
      let assigned = null;

      for (let offset = 0; offset < MAX_TUNNELS * 4; offset += 1) {
        const candidate = BASE_PORT + offset;

        if (usedPorts(tunnels).has(candidate)) {
          continue;
        }

        if (!(await isPortOpen(candidate))) {
          assigned = candidate;
          break;
        }
      }

      if (!assigned) {
        reports.push({
          hostAlias,
          port,
          state: "error",
          message: `No free local SOCKS port near ${BASE_PORT}.`
        });
        continue;
      }

      const spawned = await spawnTunnel(hostAlias, assigned);

      if (spawned.ok) {
        tunnels[hostAlias] = {
          pid: spawned.pid,
          port: spawned.port,
          startedAt: spawned.startedAt
        };
        writeState({ tunnels });
        reports.push({
          hostAlias,
          port: spawned.port,
          pid: spawned.pid,
          state: "connected"
        });
      } else {
        reports.push(spawned);
      }

      continue;
    }

    const spawned = await spawnTunnel(hostAlias, port);

    if (spawned.ok) {
      tunnels[hostAlias] = {
        pid: spawned.pid,
        port: spawned.port,
        startedAt: spawned.startedAt
      };
      writeState({ tunnels });
      reports.push({
        hostAlias,
        port: spawned.port,
        pid: spawned.pid,
        state: "connected"
      });
    } else {
      reports.push(spawned);
    }
  }

  const state = aggregateState(reports);
  const ok = reports.some((item) => item.state === "connected" || item.state === "starting");

  return {
    ok,
    state: ok ? state : "error",
    tunnels: reports,
    message: ok
      ? state === "partial"
        ? reports
            .filter((item) => item.state === "error")
            .map((item) => item.message)
            .join(" ")
        : undefined
      : reports.find((item) => item.state === "error")?.message || "Failed to connect tunnels."
  };
}

async function disconnectAll() {
  const state = readState();

  for (const [hostAlias, entry] of Object.entries(state.tunnels)) {
    await disconnectHost(hostAlias, entry);
  }

  // Keep DNS session independent of SOCKS disconnect.
  writeState({ tunnels: {}, dns: state.dns });
  return { ok: true, state: "disconnected", tunnels: [] };
}

function appendDnsLog(message) {
  ensureRuntimeDir();
  fs.appendFileSync(DNS_LOG_FILE, `[${new Date().toISOString()}] ${message}\n`);
}

function isValidIpv4(value) {
  if (!IPV4_RE.test(value)) {
    return false;
  }

  return value.split(".").every((part) => {
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function normalizeDnsDomain(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

function normalizeDnsMessageConfig(message) {
  const listenPort = Number(message.listenPort) || DNS_DEFAULT_PORT;
  const defaultNs = String(message.defaultNameserver || message.defaultUpstream?.nameserver || "1.1.1.1").trim();
  const defaultPort = Number(message.defaultNameserverPort || message.defaultUpstream?.nameserverPort) || 53;
  const rulesIn = Array.isArray(message.rules) ? message.rules : [];
  const rules = [];
  const seen = new Set();

  for (const rule of rulesIn) {
    if (!rule || typeof rule !== "object" || rule.enabled === false) {
      continue;
    }

    const domain = normalizeDnsDomain(rule.domain);
    const kind = rule.kind === "via_ssh" ? "via_ssh" : "direct";
    const nameserver = String(rule.nameserver || "").trim();
    const nameserverPort = Number(rule.nameserverPort) || 53;
    const hostAlias = String(rule.hostAlias || "").trim();

    if (!domain || !DOMAIN_RE.test(domain) || !isValidIpv4(nameserver)) {
      continue;
    }

    if (!Number.isInteger(nameserverPort) || nameserverPort < 1 || nameserverPort > 65535) {
      continue;
    }

    if (kind === "via_ssh") {
      if (!HOST_ALIAS_RE.test(hostAlias)) {
        continue;
      }
    }

    const key = `${domain}\0${kind}\0${nameserver}\0${nameserverPort}\0${hostAlias}`;

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    rules.push({
      id: String(rule.id || `d_${domain}`),
      enabled: true,
      domain,
      kind,
      nameserver,
      nameserverPort,
      hostAlias: kind === "via_ssh" ? hostAlias : ""
    });

    if (rules.length >= MAX_DNS_RULES) {
      break;
    }
  }

  rules.sort((a, b) => b.domain.length - a.domain.length);

  if (!isValidIpv4(defaultNs) || !Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
    return {
      ok: false,
      message: "Invalid DNS listen port or default nameserver (IPv4 required)."
    };
  }

  return {
    ok: true,
    config: {
      listenHost: PROXY_HOST,
      listenPort,
      defaultUpstream: {
        nameserver: defaultNs,
        nameserverPort: defaultPort
      },
      rules
    }
  };
}

function forwardKey(hostAlias, remoteDns, remotePort) {
  return `${hostAlias}|${remoteDns}|${remotePort}`;
}

async function isRecordedDnsForwardProcess(pid, localPort, hostAlias) {
  const command = await readProcessCommand(pid);

  return (
    command.includes("ssh") &&
    command.includes("-N") &&
    command.includes("-L") &&
    command.includes(`${PROXY_HOST}:${localPort}:`) &&
    command.includes(hostAlias)
  );
}

async function isRecordedDnsDaemon(pid) {
  const command = await readProcessCommand(pid);
  return command.includes("dns-daemon.js") || command.includes("dns-daemon");
}

async function isRecordedGateway(pid) {
  const command = await readProcessCommand(pid);
  return command.includes("proxy-gateway.js") || command.includes("proxy-gateway");
}

async function stopProcess(pid) {
  await stopTunnelProcess(pid);
}

function usedForwardPorts(forwards) {
  return new Set(Object.values(forwards || {}).map((entry) => entry.localPort));
}

function allocateForwardPort(forwards) {
  const taken = usedForwardPorts(forwards);

  for (let offset = 0; offset < MAX_DNS_FORWARDS * 4; offset += 1) {
    const port = DNS_FORWARD_BASE_PORT + offset;

    if (!taken.has(port)) {
      return port;
    }
  }

  return null;
}

async function spawnDnsForward(hostAlias, remoteDns, remotePort, localPort) {
  ensureRuntimeDir();
  appendDnsLog(
    `starting dns forward ${PROXY_HOST}:${localPort} -> ${remoteDns}:${remotePort} via ${hostAlias}`
  );

  let stderrBuf = "";
  const child = spawn(
    "ssh",
    [
      "-N",
      "-n",
      "-L",
      `${PROXY_HOST}:${localPort}:${remoteDns}:${remotePort}`,
      "-o",
      "ControlMaster=no",
      "-o",
      "ControlPath=none",
      "-o",
      "ExitOnForwardFailure=yes",
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=20",
      "-o",
      "ServerAliveInterval=30",
      "-o",
      "ServerAliveCountMax=3",
      hostAlias
    ],
    {
      detached: true,
      stdio: ["ignore", "ignore", "pipe"]
    }
  );

  if (child.stderr) {
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderrBuf += String(chunk);
    });
  }

  child.once("error", (error) => {
    stderrBuf += `${error.message}\n`;
  });

  child.unref();

  if (!child.pid) {
    return {
      ok: false,
      message: formatSshFailure(hostAlias, localPort, "dns forward failed to start", stderrBuf)
    };
  }

  const deadline = Date.now() + TUNNEL_READY_TIMEOUT_MS;

  while (Date.now() < deadline) {
    if (!isProcessAlive(child.pid)) {
      await wait(150);
      return {
        ok: false,
        message: formatSshFailure(hostAlias, localPort, "dns forward exited early", stderrBuf)
      };
    }

    if (await isPortOpen(localPort)) {
      appendDnsLog(`dns forward ready ${PROXY_HOST}:${localPort} pid=${child.pid}`);
      return {
        ok: true,
        pid: child.pid,
        localPort,
        startedAt: new Date().toISOString()
      };
    }

    await wait(TUNNEL_POLL_MS);
  }

  await stopProcess(child.pid);
  return {
    ok: false,
    message: formatSshFailure(hostAlias, localPort, "dns forward timeout", stderrBuf)
  };
}

async function ensureDnsForwards(rules, existingForwards) {
  const needed = new Map();

  for (const rule of rules) {
    if (rule.kind !== "via_ssh") {
      continue;
    }

    const key = forwardKey(rule.hostAlias, rule.nameserver, rule.nameserverPort);
    needed.set(key, {
      hostAlias: rule.hostAlias,
      remoteDns: rule.nameserver,
      remotePort: rule.nameserverPort
    });
  }

  if (needed.size > MAX_DNS_FORWARDS) {
    return {
      ok: false,
      forwards: {},
      message: `At most ${MAX_DNS_FORWARDS} DNS SSH forwards are supported.`
    };
  }

  const next = {};
  const current = existingForwards && typeof existingForwards === "object" ? { ...existingForwards } : {};

  // Stop unneeded forwards.
  for (const [key, entry] of Object.entries(current)) {
    if (!needed.has(key)) {
      if (entry.pid) {
        await stopProcess(entry.pid);
        appendDnsLog(`stopped dns forward ${key}`);
      }

      delete current[key];
    }
  }

  for (const [key, spec] of needed.entries()) {
    const existing = current[key];

    if (existing && isProcessAlive(existing.pid)) {
      if (await isRecordedDnsForwardProcess(existing.pid, existing.localPort, spec.hostAlias)) {
        if (await isPortOpen(existing.localPort)) {
          next[key] = existing;
          continue;
        }
      }

      await stopProcess(existing.pid);
    }

    let localPort = existing?.localPort || allocateForwardPort(next);

    if (!localPort) {
      return {
        ok: false,
        forwards: next,
        message: "No free local DNS forward port."
      };
    }

    if (await isPortOpen(localPort)) {
      localPort = null;

      for (let offset = 0; offset < MAX_DNS_FORWARDS * 4; offset += 1) {
        const candidate = DNS_FORWARD_BASE_PORT + offset;

        if (usedForwardPorts(next).has(candidate)) {
          continue;
        }

        if (!(await isPortOpen(candidate))) {
          localPort = candidate;
          break;
        }
      }
    }

    if (!localPort) {
      return {
        ok: false,
        forwards: next,
        message: `No free local DNS forward port near ${DNS_FORWARD_BASE_PORT}.`
      };
    }

    const spawned = await spawnDnsForward(spec.hostAlias, spec.remoteDns, spec.remotePort, localPort);

    if (!spawned.ok) {
      return {
        ok: false,
        forwards: next,
        message: spawned.message
      };
    }

    next[key] = {
      pid: spawned.pid,
      localPort: spawned.localPort,
      hostAlias: spec.hostAlias,
      remoteDns: spec.remoteDns,
      remotePort: spec.remotePort,
      startedAt: spawned.startedAt
    };
  }

  return { ok: true, forwards: next };
}

function buildDaemonConfig(config, forwards, enforce) {
  const rules = [];

  for (const rule of config.rules) {
    if (rule.kind === "via_ssh") {
      const key = forwardKey(rule.hostAlias, rule.nameserver, rule.nameserverPort);
      const forward = forwards[key];

      if (!forward) {
        continue;
      }

      rules.push({
        id: rule.id,
        enabled: true,
        domain: rule.domain,
        label: `${rule.domain}@${rule.hostAlias}`,
        upstream: {
          nameserver: PROXY_HOST,
          nameserverPort: forward.localPort
        }
      });
    } else {
      rules.push({
        id: rule.id,
        enabled: true,
        domain: rule.domain,
        label: rule.domain,
        upstream: {
          nameserver: rule.nameserver,
          nameserverPort: rule.nameserverPort
        }
      });
    }
  }

  return {
    listenHost: PROXY_HOST,
    listenPort: config.listenPort,
    defaultUpstream: config.defaultUpstream,
    rules,
    enforce: enforce !== false
  };
}

function writeDnsConfigFile(daemonConfig) {
  ensureRuntimeDir();
  fs.writeFileSync(DNS_CONFIG_FILE, JSON.stringify(daemonConfig, null, 2));
}

function findPidsByCommandSubstring(substr) {
  return new Promise((resolve) => {
    execFile("pgrep", ["-f", substr], (error, stdout) => {
      if (error || !stdout) {
        resolve([]);
        return;
      }

      const pids = String(stdout)
        .trim()
        .split(/\s+/)
        .map((value) => Number(value))
        .filter((pid) => Number.isInteger(pid) && pid > 0 && pid !== process.pid);

      resolve(pids);
    });
  });
}

function findUdpListenerPids(port) {
  return new Promise((resolve) => {
    execFile("lsof", ["-nP", `-iUDP:${port}`, "-t"], (error, stdout) => {
      if (error || !stdout) {
        resolve([]);
        return;
      }

      const pids = String(stdout)
        .trim()
        .split(/\s+/)
        .map((value) => Number(value))
        .filter((pid) => Number.isInteger(pid) && pid > 0 && pid !== process.pid);

      resolve([...new Set(pids)]);
    });
  });
}

async function stopDnsDaemonOnly(dnsState) {
  const pids = new Set();

  if (dnsState?.pid) {
    pids.add(Number(dnsState.pid));
  }

  // Orphans: state.json may be missing after crash/uninstall while daemon still holds the port.
  for (const pid of await findPidsByCommandSubstring("dns-daemon.js")) {
    pids.add(pid);
  }

  if (dnsState?.port) {
    for (const pid of await findUdpListenerPids(dnsState.port)) {
      const command = await readProcessCommand(pid);

      if (command.includes("dns-daemon")) {
        pids.add(pid);
      }
    }
  }

  for (const pid of pids) {
    if (!Number.isInteger(pid) || pid <= 0) {
      continue;
    }

    await stopProcess(pid);
    appendDnsLog(`stopped dns-daemon pid=${pid}`);
  }
}

async function stopAllDnsForwards(forwards) {
  for (const [key, entry] of Object.entries(forwards || {})) {
    if (entry?.pid) {
      await stopProcess(entry.pid);
      appendDnsLog(`stopped dns forward ${key}`);
    }
  }
}

function readLastDnsLogLines(limit = 8) {
  try {
    const text = fs.readFileSync(DNS_LOG_FILE, "utf8");
    const lines = text.trim().split(/\n/).filter(Boolean);
    return lines.slice(-limit);
  } catch (_error) {
    return [];
  }
}

function formatDaemonSpawnFailure(listenPort) {
  const lines = readLastDnsLogLines(12);
  const bindLine = [...lines].reverse().find((line) => /bind|EADDRINUSE|EACCES|error/i.test(line));

  if (bindLine && /EADDRINUSE/i.test(bindLine)) {
    return `dns-daemon failed: port ${PROXY_HOST}:${listenPort} already in use (EADDRINUSE). Stop other Webhole DNS processes or change Listen port.`;
  }

  if (bindLine) {
    return `dns-daemon exited immediately. Last log: ${bindLine.replace(/^\[[^\]]+\]\s*/, "")}`;
  }

  return `dns-daemon exited immediately on ${PROXY_HOST}:${listenPort}. See native-host/runtime/dns.log.`;
}

async function waitForUdpPortFree(port, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const holders = await findUdpListenerPids(port);

    if (!holders.length) {
      return true;
    }

    // Only treat non-dns-daemon holders as blocking after we tried to kill ours.
    let foreign = false;

    for (const pid of holders) {
      const command = await readProcessCommand(pid);

      if (command.includes("dns-daemon")) {
        await stopProcess(pid);
        appendDnsLog(`reaped leftover dns-daemon pid=${pid} on :${port}`);
      } else if (command) {
        foreign = true;
        appendDnsLog(`port ${port} held by foreign pid=${pid}: ${command.slice(0, 160)}`);
      }
    }

    if (foreign) {
      return false;
    }

    await wait(100);
  }

  return (await findUdpListenerPids(port)).length === 0;
}

async function spawnDnsDaemon(listenPort) {
  ensureRuntimeDir();
  appendDnsLog(`starting dns-daemon on ${PROXY_HOST}:${listenPort}`);

  // Ensure no orphan holds the UDP port (common after state.json wipe / partial stop).
  await stopDnsDaemonOnly({ port: listenPort });
  const free = await waitForUdpPortFree(listenPort, 4000);

  if (!free) {
    const holders = await findUdpListenerPids(listenPort);
    return {
      ok: false,
      message: `UDP ${PROXY_HOST}:${listenPort} is busy (pids: ${holders.join(",") || "?"}). Change Listen port or free the port.`
    };
  }

  const child = spawn(process.execPath, [DNS_DAEMON_SCRIPT], {
    detached: true,
    stdio: "ignore",
    cwd: __dirname,
    env: process.env
  });

  child.unref();

  if (!child.pid) {
    return { ok: false, message: "Failed to spawn dns-daemon." };
  }

  const deadline = Date.now() + 5000;

  while (Date.now() < deadline) {
    if (!isProcessAlive(child.pid)) {
      // Allow log flush from child.
      await wait(80);
      return { ok: false, message: formatDaemonSpawnFailure(listenPort) };
    }

    await wait(120);

    // Ready when our pid still lives and something is listening on the UDP port.
    const holders = await findUdpListenerPids(listenPort);

    if (holders.includes(child.pid) || (isProcessAlive(child.pid) && holders.length > 0)) {
      appendDnsLog(`dns-daemon ready pid=${child.pid} port=${listenPort}`);
      return {
        ok: true,
        pid: child.pid,
        port: listenPort,
        startedAt: new Date().toISOString()
      };
    }

    // Still starting.
    if (isProcessAlive(child.pid) && Date.now() + 200 >= deadline) {
      // Last chance: process alive after settle even if lsof is slow.
      appendDnsLog(`dns-daemon assumed ready pid=${child.pid} port=${listenPort} (lsof pending)`);
      return {
        ok: true,
        pid: child.pid,
        port: listenPort,
        startedAt: new Date().toISOString()
      };
    }
  }

  if (isProcessAlive(child.pid)) {
    appendDnsLog(`dns-daemon ready pid=${child.pid} port=${listenPort}`);
    return {
      ok: true,
      pid: child.pid,
      port: listenPort,
      startedAt: new Date().toISOString()
    };
  }

  await stopProcess(child.pid);
  return { ok: false, message: formatDaemonSpawnFailure(listenPort) };
}

async function dnsStart(message) {
  const normalized = normalizeDnsMessageConfig(message || {});

  if (!normalized.ok) {
    return { ok: false, state: "error", message: normalized.message, dns: null };
  }

  const enforce = message?.enforce !== false;
  // Explicit opt-in only (Chrome gateway does not need /etc/resolver).
  const autoInstallResolver = message?.autoInstallResolver === true && enforce;
  const config = normalized.config;
  const state = readState();
  const existingDns = state.dns;

  // Keep gateway if tunnels still need it; stop/restart separately via gatewayStart.
  if (existingDns?.gateway?.pid) {
    await stopGatewayOnly(existingDns.gateway);
  }

  const forwardsResult = await ensureDnsForwards(config.rules, existingDns?.forwards || {});

  if (!forwardsResult.ok) {
    return {
      ok: false,
      state: "error",
      message: forwardsResult.message,
      dns: null
    };
  }

  const daemonConfig = buildDaemonConfig(config, forwardsResult.forwards, enforce);
  writeDnsConfigFile(daemonConfig);

  // Always tear down orphans + recorded daemon before rebind (state may be missing).
  await stopDnsDaemonOnly({
    pid: existingDns?.pid,
    port: config.listenPort
  });
  await wait(150);

  const spawned = await spawnDnsDaemon(config.listenPort);

  if (!spawned.ok) {
    await stopAllDnsForwards(forwardsResult.forwards);
    writeState({ dns: null });
    return {
      ok: false,
      state: "error",
      message: spawned.message,
      dns: null
    };
  }

  let resolverInstalled = false;
  let resolverMessage = "";

  if (autoInstallResolver) {
    // Sync stubs to *enabled* domains only. Empty list removes all Webhole stubs.
    // No admin prompt when already in sync (stops password spam on every reconcile).
    const synced = await syncResolverStubs(
      config.rules.map((rule) => rule.domain),
      config.listenPort,
      { force: Boolean(message.forceResolverSync) }
    );
    resolverInstalled = Boolean(synced.ok) && (synced.state === "installed" || synced.skipped);
    resolverMessage = synced.message || "";

    if (!synced.ok) {
      appendDnsLog(`auto resolver sync failed: ${resolverMessage}`);
      resolverInstalled = false;
    } else if (synced.state === "absent" || !config.rules.length) {
      resolverInstalled = false;
    }
  }

  const dns = {
    pid: spawned.pid,
    port: spawned.port,
    startedAt: spawned.startedAt,
    forwards: forwardsResult.forwards,
    enforce,
    resolverInstalled,
    gateway: null
  };

  writeState({ dns });

  const parts = [`DNS stub on ${PROXY_HOST}:${dns.port}`];

  if (autoInstallResolver) {
    parts.push(resolverInstalled ? "resolver installed" : `resolver: ${resolverMessage || "not installed"}`);
  }

  return {
    ok: true,
    state: "running",
    message: parts.join("; "),
    dns: {
      pid: dns.pid,
      port: dns.port,
      startedAt: dns.startedAt,
      rules: daemonConfig.rules.length,
      forwards: Object.keys(dns.forwards).length,
      enforce,
      resolverInstalled,
      resolverMessage
    }
  };
}

async function dnsStop() {
  const state = readState();
  const dns = state.dns;

  // Always reap gateways even if state.json was lost (orphans break Chrome PAC).
  await stopAllGateways(dns?.gateway?.port);

  if (dns) {
    await stopDnsDaemonOnly(dns);
    await stopAllDnsForwards(dns.forwards);
  } else {
    // Still try to kill orphan daemons by command line / port.
    await stopDnsDaemonOnly({ port: DNS_DEFAULT_PORT });
  }

  let resolverMessage = "";

  if (process.platform === "darwin") {
    const uninstalled = await dnsUninstallResolver();
    resolverMessage = uninstalled.message || "";
  }

  writeState({ dns: null });

  return {
    ok: true,
    state: "stopped",
    message: resolverMessage ? `DNS stopped. ${resolverMessage}` : "DNS stopped.",
    dns: null
  };
}

async function dnsStatus() {
  const state = readState();
  const dns = state.dns;

  if (!dns) {
    return {
      ok: true,
      state: "stopped",
      dns: null
    };
  }

  if (!isProcessAlive(dns.pid) || !(await isRecordedDnsDaemon(dns.pid))) {
    if (dns.gateway?.pid) {
      await stopGatewayOnly(dns.gateway);
    }

    await stopAllDnsForwards(dns.forwards);
    writeState({ dns: null });
    return {
      ok: true,
      state: "stopped",
      message: "DNS daemon not running.",
      dns: null
    };
  }

  const forwardReports = [];

  for (const [key, entry] of Object.entries(dns.forwards || {})) {
    const alive = isProcessAlive(entry.pid);
    const ok = alive && (await isRecordedDnsForwardProcess(entry.pid, entry.localPort, entry.hostAlias));
    forwardReports.push({
      key,
      localPort: entry.localPort,
      hostAlias: entry.hostAlias,
      remoteDns: entry.remoteDns,
      remotePort: entry.remotePort,
      state: ok ? "connected" : "error"
    });
  }

  let gateway = null;

  if (dns.gateway?.pid) {
    if (isProcessAlive(dns.gateway.pid) && (await isRecordedGateway(dns.gateway.pid))) {
      gateway = {
        pid: dns.gateway.pid,
        port: dns.gateway.port,
        startedAt: dns.gateway.startedAt,
        state: "running"
      };
    } else {
      const nextDns = { ...dns, gateway: null };
      writeState({ dns: nextDns });
    }
  }

  const onDisk = listManagedResolverFilesOnDisk();
  const resolverInstalled =
    onDisk.length > 0 || Boolean(dns.resolverInstalled && readResolverManifest().length);

  // Heal stale flag after manual uninstall/reinstall cycles.
  if (resolverInstalled !== Boolean(dns.resolverInstalled)) {
    writeState({
      dns: {
        ...dns,
        resolverInstalled,
        gateway: dns.gateway || null
      }
    });
  }

  return {
    ok: true,
    state: "running",
    dns: {
      pid: dns.pid,
      port: dns.port,
      startedAt: dns.startedAt,
      forwards: forwardReports,
      enforce: dns.enforce !== false,
      resolverInstalled,
      resolverFiles: onDisk,
      gateway
    }
  };
}

function writeGatewayConfigFile(config) {
  ensureRuntimeDir();
  fs.writeFileSync(GATEWAY_CONFIG_FILE, JSON.stringify(config, null, 2));
}

async function stopGatewayOnly(gateway) {
  if (gateway?.pid) {
    await stopProcess(gateway.pid);
    appendDnsLog(`stopped proxy-gateway pid=${gateway.pid}`);
  }
}

/** Kill recorded + orphan proxy-gateway processes (state.json may be missing). */
async function stopAllGateways(preferredPort) {
  const pids = new Set();
  const state = readState();

  if (state.dns?.gateway?.pid) {
    pids.add(Number(state.dns.gateway.pid));
  }

  for (const pid of await findPidsByCommandSubstring("proxy-gateway.js")) {
    pids.add(pid);
  }

  const ports = new Set([GATEWAY_DEFAULT_PORT]);

  if (Number.isInteger(preferredPort) && preferredPort > 0) {
    ports.add(preferredPort);
  }

  if (state.dns?.gateway?.port) {
    ports.add(Number(state.dns.gateway.port));
  }

  for (const port of ports) {
    // isPortOpen is TCP connect — good for gateway listen port.
    if (await isPortOpen(port)) {
      // lsof TCP listen
      const tcpPids = await new Promise((resolve) => {
        execFile("lsof", ["-nP", `-iTCP:${port}`, "-sTCP:LISTEN", "-t"], (error, stdout) => {
          if (error || !stdout) {
            resolve([]);
            return;
          }

          resolve(
            String(stdout)
              .trim()
              .split(/\s+/)
              .map((v) => Number(v))
              .filter((n) => Number.isInteger(n) && n > 0)
          );
        });
      });

      for (const pid of tcpPids) {
        const command = await readProcessCommand(pid);

        if (command.includes("proxy-gateway") || command.includes("node")) {
          pids.add(pid);
        }
      }
    }
  }

  for (const pid of pids) {
    if (!Number.isInteger(pid) || pid <= 0) {
      continue;
    }

    await stopProcess(pid);
    appendDnsLog(`stopped proxy-gateway (cleanup) pid=${pid}`);
  }
}

async function spawnGateway(listenPort) {
  ensureRuntimeDir();
  appendDnsLog(`starting proxy-gateway on ${PROXY_HOST}:${listenPort}`);

  const child = spawn(process.execPath, [GATEWAY_SCRIPT], {
    detached: true,
    stdio: "ignore",
    cwd: __dirname
  });

  child.unref();

  if (!child.pid) {
    return { ok: false, message: "Failed to spawn proxy-gateway." };
  }

  const deadline = Date.now() + 5000;

  while (Date.now() < deadline) {
    if (!isProcessAlive(child.pid)) {
      return { ok: false, message: "proxy-gateway exited immediately." };
    }

    if (await isPortOpen(listenPort)) {
      appendDnsLog(`proxy-gateway ready pid=${child.pid} port=${listenPort}`);
      return {
        ok: true,
        pid: child.pid,
        port: listenPort,
        startedAt: new Date().toISOString()
      };
    }

    await wait(100);
  }

  if (isProcessAlive(child.pid) && (await isPortOpen(listenPort))) {
    return {
      ok: true,
      pid: child.pid,
      port: listenPort,
      startedAt: new Date().toISOString()
    };
  }

  await stopProcess(child.pid);
  return { ok: false, message: "proxy-gateway failed to become ready." };
}

async function gatewayStart(message) {
  const dnsState = readState().dns;

  if (!dnsState?.pid || !isProcessAlive(dnsState.pid)) {
    return {
      ok: false,
      state: "error",
      message: "DNS stub must be running before gateway start."
    };
  }

  const listenPort = Number(message.listenPort) || GATEWAY_DEFAULT_PORT;
  const dnsPort = Number(message.dnsPort) || dnsState.port || DNS_DEFAULT_PORT;
  const mode =
    message.mode === "global" ? "global" : message.mode === "enforce" ? "enforce" : "routes";
  const rulesIn = Array.isArray(message.rules) ? message.rules : [];
  const rules = [];

  for (const rule of rulesIn) {
    const hostPattern = String(rule.hostPattern || "")
      .toLowerCase()
      .replace(/\.$/, "");
    const rawPort = rule.socksPort != null ? rule.socksPort : rule.port;
    const socksPort = Number(rawPort);

    if (!hostPattern) {
      continue;
    }

    // socksPort 0 = DIRECT after stub resolve (valid for DNS Enforce domains).
    if (!Number.isInteger(socksPort) || socksPort < 0) {
      continue;
    }

    rules.push({
      hostPattern,
      pathPrefix: String(rule.pathPrefix || ""),
      socksPort
    });
  }

  const fallbackSocksPort = Number(message.fallbackSocksPort) || 0;
  const dnsPatterns = Array.isArray(message.dnsPatterns)
    ? message.dnsPatterns.map((d) => String(d || "").toLowerCase().replace(/\.$/, "")).filter(Boolean)
    : [];

  if (mode === "global" && !fallbackSocksPort) {
    return {
      ok: false,
      state: "error",
      message: "Global gateway requires fallbackSocksPort."
    };
  }

  if (mode === "routes" && !rules.length && !fallbackSocksPort && !dnsPatterns.length) {
    return {
      ok: false,
      state: "error",
      message: "Gateway has no SOCKS routes or DNS patterns."
    };
  }

  if (mode === "enforce" && !dnsPatterns.length && !rules.length) {
    return {
      ok: false,
      state: "error",
      message: "Enforce gateway requires at least one DNS domain pattern."
    };
  }

  // For enforce mode, ensure every DNS pattern is a host rule (direct after resolve).
  if (mode === "enforce") {
    for (const pattern of dnsPatterns) {
      if (!rules.some((rule) => rule.hostPattern === pattern)) {
        rules.push({ hostPattern: pattern, pathPrefix: "", socksPort: 0 });
      }
    }
  }

  writeGatewayConfigFile({
    listenHost: PROXY_HOST,
    listenPort,
    dnsHost: PROXY_HOST,
    dnsPort,
    mode,
    rules,
    fallbackSocksPort,
    dnsPatterns
  });

  if (dnsState.gateway?.pid) {
    await stopGatewayOnly(dnsState.gateway);
  }

  const spawned = await spawnGateway(listenPort);

  if (!spawned.ok) {
    const next = { ...dnsState, gateway: null };
    writeState({ dns: next });
    return { ok: false, state: "error", message: spawned.message };
  }

  const gateway = {
    pid: spawned.pid,
    port: spawned.port,
    startedAt: spawned.startedAt
  };

  writeState({
    dns: {
      ...dnsState,
      gateway
    }
  });

  return {
    ok: true,
    state: "running",
    message: `Gateway on ${PROXY_HOST}:${gateway.port}`,
    gateway
  };
}

async function gatewayStop() {
  const state = readState();
  const dns = state.dns;

  await stopAllGateways(dns?.gateway?.port);

  if (dns) {
    writeState({ dns: { ...dns, gateway: null } });
  }

  return { ok: true, state: "stopped", message: "Gateway stopped.", gateway: null };
}

function encodeDnsName(name) {
  const labels = String(name)
    .replace(/\.$/, "")
    .split(".")
    .filter(Boolean);
  const parts = [];

  for (const label of labels) {
    const buf = Buffer.from(label, "ascii");

    if (buf.length > 63) {
      throw new Error("label too long");
    }

    parts.push(Buffer.from([buf.length]));
    parts.push(buf);
  }

  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function buildDnsQuery(name, qtype) {
  const id = Math.floor(Math.random() * 65535);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // RD
  header.writeUInt16BE(1, 4); // QDCOUNT
  const qname = encodeDnsName(name);
  const qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(qtype, 0);
  qtail.writeUInt16BE(1, 2); // IN
  return { id, packet: Buffer.concat([header, qname, qtail]) };
}

const DNS_QTYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  ANY: 255
};

function parseDnsAnswers(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    return { rcode: 2, answers: [] };
  }

  const rcode = buffer.readUInt16BE(2) & 0xf;
  const ancount = buffer.readUInt16BE(6);
  let offset = 12;
  const answers = [];

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
      return { rcode, answers };
    }

    offset += 4;
  }

  for (let i = 0; i < ancount && answers.length < 16; i += 1) {
    if (!skipName() || offset + 10 > buffer.length) {
      break;
    }

    const type = buffer.readUInt16BE(offset);
    const ttl = buffer.readUInt32BE(offset + 4);
    const rdlength = buffer.readUInt16BE(offset + 8);
    const start = offset + 10;
    const end = start + rdlength;
    offset = end;

    if (end > buffer.length) {
      break;
    }

    let data = "";

    if (type === 1 && rdlength === 4) {
      data = Array.from(buffer.slice(start, end)).join(".");
    } else if (type === 28 && rdlength === 16) {
      const parts = [];

      for (let j = 0; j < 16; j += 2) {
        parts.push(buffer.readUInt16BE(start + j).toString(16));
      }

      data = parts.join(":");
    } else {
      data = `TYPE${type}(${rdlength}b)`;
    }

    answers.push({ type, ttl, data });
  }

  return { rcode, answers };
}

function queryUdpDns(packet, host, port, timeoutMs) {
  return new Promise((resolve) => {
    const dgram = require("dgram");
    const socket = dgram.createSocket("udp4");
    let settled = false;

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

    const timer = setTimeout(() => finish(null), timeoutMs);

    socket.on("message", (msg) => finish(msg));
    socket.on("error", () => finish(null));
    socket.send(packet, port, host, (error) => {
      if (error) {
        finish(null);
      }
    });
  });
}

async function dnsQuery(message) {
  const name = normalizeDnsDomain(message.name || message.qname);

  if (!name || !DOMAIN_RE.test(name)) {
    return { ok: false, state: "error", message: "Invalid query name." };
  }

  const typeName = String(message.type || message.qtype || "A").toUpperCase();
  const qtype = DNS_QTYPES[typeName] || Number(message.qtype) || 1;
  const status = await dnsStatus();

  if (status.state !== "running" || !status.dns?.port) {
    return {
      ok: false,
      state: "error",
      message: "DNS stub is not running. Turn DNS On first."
    };
  }

  let packet;

  try {
    packet = buildDnsQuery(name, qtype).packet;
  } catch (error) {
    return { ok: false, state: "error", message: error.message };
  }

  const started = Date.now();
  const response = await queryUdpDns(packet, PROXY_HOST, status.dns.port, 3000);
  const elapsed = Date.now() - started;

  if (!response) {
    return {
      ok: false,
      state: "error",
      message: `No response from stub within ${elapsed}ms.`,
      elapsedMs: elapsed
    };
  }

  const parsed = parseDnsAnswers(response);

  return {
    ok: true,
    state: "ok",
    name,
    type: typeName,
    rcode: parsed.rcode,
    answers: parsed.answers,
    elapsedMs: elapsed,
    listenPort: status.dns.port
  };
}

function readResolverManifest() {
  try {
    const raw = JSON.parse(fs.readFileSync(DNS_RESOLVER_MANIFEST, "utf8"));
    return Array.isArray(raw.files) ? raw.files.map(String) : [];
  } catch (_error) {
    return [];
  }
}

function writeResolverManifest(files) {
  ensureRuntimeDir();
  fs.writeFileSync(DNS_RESOLVER_MANIFEST, JSON.stringify({ files }, null, 2));
}

/** Discover Webhole-managed stubs even if manifest was lost after uninstall/reinstall. */
function listManagedResolverFilesOnDisk() {
  try {
    if (!fs.existsSync(RESOLVER_DIR)) {
      return [];
    }

    const names = fs.readdirSync(RESOLVER_DIR);
    const files = [];

    for (const name of names) {
      if (!name || name.startsWith(".")) {
        continue;
      }

      const full = path.join(RESOLVER_DIR, name);

      try {
        const stat = fs.statSync(full);

        if (!stat.isFile()) {
          continue;
        }

        const text = fs.readFileSync(full, "utf8");

        if (text.includes("Managed by Webhole")) {
          files.push(full);
        }
      } catch (_error) {
        // ignore unreadable entry
      }
    }

    return files;
  } catch (_error) {
    return [];
  }
}

function mergeResolverFileLists(...lists) {
  const seen = new Set();
  const result = [];

  for (const list of lists) {
    for (const file of list || []) {
      const value = String(file || "");

      if (!value || seen.has(value)) {
        continue;
      }

      if (!value.startsWith(`${RESOLVER_DIR}/`) || value.includes("..")) {
        continue;
      }

      seen.add(value);
      result.push(value);
    }
  }

  return result;
}

function verifyResolverFiles(files, port) {
  const missing = [];
  const wrong = [];

  for (const file of files) {
    try {
      const text = fs.readFileSync(file, "utf8");

      if (!text.includes("Managed by Webhole") || !text.includes("127.0.0.1")) {
        wrong.push(file);
        continue;
      }

      if (!text.includes(`port ${port}`)) {
        wrong.push(file);
      }
    } catch (_error) {
      missing.push(file);
    }
  }

  return { missing, wrong, ok: missing.length === 0 && wrong.length === 0 };
}

function resolverFilesForDomains(domains, port) {
  return [...new Set(domains || [])]
    .filter((domain) => DOMAIN_RE.test(domain) && !domain.includes("/"))
    .sort()
    .map((domain) => `${RESOLVER_DIR}/${domain}`);
}

/** True when on-disk Webhole stubs already match desired domains + port. */
function resolversAlreadySynced(domains, port) {
  const desired = resolverFilesForDomains(domains, port);
  const onDisk = listManagedResolverFilesOnDisk().sort();

  if (desired.length !== onDisk.length) {
    return false;
  }

  for (let i = 0; i < desired.length; i += 1) {
    if (desired[i] !== onDisk[i]) {
      return false;
    }
  }

  if (!desired.length) {
    return true;
  }

  return verifyResolverFiles(desired, port).ok;
}

function setDnsResolverInstalledFlag(installed) {
  const state = readState();

  if (!state.dns) {
    return;
  }

  writeState({
    dns: {
      ...state.dns,
      resolverInstalled: Boolean(installed)
    }
  });
}

function runExecFile(command, args, options = {}) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: options.timeout || 120000, ...options }, (error, stdout, stderr) => {
      if (error) {
        resolve({
          ok: false,
          message: String(stderr || error.message || `${command} failed`).trim(),
          stdout: String(stdout || ""),
          stderr: String(stderr || "")
        });
        return;
      }

      resolve({ ok: true, stdout: String(stdout || ""), stderr: String(stderr || "") });
    });
  });
}

/**
 * Run a shell script with elevation (simple path, no Terminal / Touch ID flow).
 * 1) sudo -n if already authorized
 * 2) macOS admin password dialog via osascript
 */
async function runPrivilegedShell(shellScript, options = {}) {
  const prompt = options.prompt || "Webhole 需要管理員權限以更新 /etc/resolver。";

  const sudoN = await runExecFile("sudo", ["-n", "/bin/bash", "-c", shellScript], {
    timeout: 60000
  });

  if (sudoN.ok) {
    appendDnsLog("privileged shell via sudo -n");
    return { ok: true, stdout: sudoN.stdout, method: "sudo-n" };
  }

  const apple = [
    `do shell script ${JSON.stringify(shellScript)}`,
    `with prompt ${JSON.stringify(prompt)}`,
    "with administrator privileges"
  ].join(" ");

  const osa = await runExecFile("osascript", ["-e", apple], { timeout: 180000 });

  if (osa.ok) {
    appendDnsLog("privileged shell via osascript admin dialog");
    return { ok: true, stdout: osa.stdout, method: "osascript-admin" };
  }

  const cancelled =
    /user canceled|cancelled|(-128)/i.test(osa.message || "") ||
    /user canceled|cancelled|(-128)/i.test(osa.stderr || "");

  return {
    ok: false,
    method: "osascript-admin",
    message: cancelled ? "已取消管理員授權。" : osa.message || "Failed to elevate privileges."
  };
}

/** @deprecated name kept as alias for call sites */
async function runOsascriptAdmin(shellScript) {
  return runPrivilegedShell(shellScript);
}

/**
 * Sync /etc/resolver to match enabled domains.
 * - empty domains → uninstall all Webhole stubs (admin only if stubs exist)
 * - already in sync → no admin prompt
 * - force: true → always rewrite
 */
async function syncResolverStubs(domains, port, options = {}) {
  if (process.platform !== "darwin") {
    return {
      ok: false,
      state: "error",
      message: "Resolver stubs are only supported on macOS."
    };
  }

  const force = Boolean(options.force);
  const uniqueDomains = [
    ...new Set((domains || []).map((d) => normalizeDnsDomain(d)).filter(Boolean))
  ];
  const nextFiles = resolverFilesForDomains(uniqueDomains, port);
  const previous = mergeResolverFileLists(readResolverManifest(), listManagedResolverFilesOnDisk());

  if (!nextFiles.length) {
    if (!previous.length) {
      writeResolverManifest([]);
      setDnsResolverInstalledFlag(false);
      return {
        ok: true,
        state: "absent",
        message: "No DNS rules enabled; no resolver stubs on disk.",
        skipped: true
      };
    }

    // All rules off / no domains → remove stubs so system DNS takes over.
    appendDnsLog("sync resolvers: uninstalling all (no enabled domains)");
    return dnsUninstallResolver();
  }

  if (!force && resolversAlreadySynced(uniqueDomains, port)) {
    writeResolverManifest(nextFiles);
    setDnsResolverInstalledFlag(true);
    appendDnsLog(`sync resolvers: already in sync (${uniqueDomains.join(", ")}) port=${port}`);
    return {
      ok: true,
      state: "installed",
      message: `Resolver stubs already up to date (${nextFiles.length}).`,
      files: nextFiles,
      skipped: true
    };
  }

  const lines = ["mkdir -p /etc/resolver"];

  for (const file of previous) {
    if (!nextFiles.includes(file)) {
      lines.push(`rm -f ${JSON.stringify(file)}`);
    }
  }

  for (const domain of uniqueDomains) {
    if (!DOMAIN_RE.test(domain) || domain.includes("/")) {
      continue;
    }

    const content = `# Managed by Webhole\nnameserver 127.0.0.1\nport ${port}\n`;
    const filePath = `${RESOLVER_DIR}/${domain}`;
    lines.push(
      `python3 -c ${JSON.stringify(
        `import pathlib; pathlib.Path(${JSON.stringify(filePath)}).write_text(${JSON.stringify(content)})`
      )}`
    );
  }

  lines.push("dscacheutil -flushcache >/dev/null 2>&1 || true");
  lines.push("killall -HUP mDNSResponder >/dev/null 2>&1 || true");
  lines.push("sleep 0.3");
  lines.push("true");

  const result = await runPrivilegedShell(lines.join(" && "), {
    prompt: "Webhole 需要管理員權限以更新 /etc/resolver。"
  });

  if (!result.ok) {
    setDnsResolverInstalledFlag(false);
    return {
      ok: false,
      state: "error",
      message: result.message || "Failed to sync resolver stubs (admin cancelled?)."
    };
  }

  await wait(400);
  const verification = verifyResolverFiles(nextFiles, port);

  if (!verification.ok) {
    setDnsResolverInstalledFlag(false);
    appendDnsLog(
      `resolver verify failed missing=${verification.missing.join(",")} wrong=${verification.wrong.join(",")}`
    );
    return {
      ok: false,
      state: "error",
      message: `Resolver write reported ok but files invalid (missing=${verification.missing.length}, wrong=${verification.wrong.length}).`
    };
  }

  writeResolverManifest(nextFiles);
  setDnsResolverInstalledFlag(true);
  appendDnsLog(`synced resolver stubs for ${uniqueDomains.join(", ")} port=${port}`);

  const dns = readState().dns;
  const stubUp = Boolean(dns?.pid && isProcessAlive(dns.pid));

  return {
    ok: true,
    state: "installed",
    message: `Synced ${nextFiles.length} resolver stub(s) → 127.0.0.1:${port}`,
    files: nextFiles,
    stubRunning: stubUp,
    skipped: false
  };
}

async function dnsInstallResolver(message) {
  if (process.platform !== "darwin") {
    return {
      ok: false,
      state: "error",
      message: "Resolver stubs are only supported on macOS."
    };
  }

  const normalized = normalizeDnsMessageConfig(message || {});

  if (!normalized.ok) {
    return { ok: false, state: "error", message: normalized.message };
  }

  const port = normalized.config.listenPort;
  const domains = [
    ...new Set(normalized.config.rules.map((rule) => rule.domain).filter(Boolean))
  ];

  if (!domains.length) {
    // Explicit reinstall with no rules → clear stubs.
    return syncResolverStubs([], port, { force: Boolean(message.force) });
  }

  return syncResolverStubs(domains, port, { force: Boolean(message.force) || message.forceInstall === true });
}

async function dnsUninstallResolver() {
  if (process.platform !== "darwin") {
    return {
      ok: false,
      state: "error",
      message: "Resolver stubs are only supported on macOS."
    };
  }

  const files = mergeResolverFileLists(readResolverManifest(), listManagedResolverFilesOnDisk());

  if (!files.length) {
    writeResolverManifest([]);
    setDnsResolverInstalledFlag(false);
    return {
      ok: true,
      state: "absent",
      message: "No Webhole resolver stubs found on disk."
    };
  }

  const safeFiles = files.filter(
    (file) => file.startsWith(`${RESOLVER_DIR}/`) && !file.includes("..")
  );

  if (!safeFiles.length) {
    writeResolverManifest([]);
    setDnsResolverInstalledFlag(false);
    return { ok: true, state: "absent", message: "No safe resolver files to remove." };
  }

  const script = [
    ...safeFiles.map((file) => `rm -f ${JSON.stringify(file)}`),
    "dscacheutil -flushcache >/dev/null 2>&1 || true",
    "killall -HUP mDNSResponder >/dev/null 2>&1 || true",
    "sleep 0.2",
    "true"
  ].join(" && ");
  const result = await runOsascriptAdmin(script);

  if (!result.ok) {
    return {
      ok: false,
      state: "error",
      message: result.message || "Failed to uninstall resolver stubs."
    };
  }

  writeResolverManifest([]);
  setDnsResolverInstalledFlag(false);
  appendDnsLog(`uninstalled resolver stubs: ${safeFiles.join(", ")}`);

  // Confirm removal.
  const leftovers = listManagedResolverFilesOnDisk();

  return {
    ok: leftovers.length === 0,
    state: leftovers.length === 0 ? "uninstalled" : "partial",
    message:
      leftovers.length === 0
        ? `Removed ${safeFiles.length} resolver stub(s).`
        : `Removed some stubs; still left: ${leftovers.join(", ")}`,
    files: safeFiles,
    leftovers
  };
}

function expandHomePath(value) {
  if (value === "~") {
    return os.homedir();
  }

  if (value.startsWith("~/") || value.startsWith("~\\")) {
    return path.join(os.homedir(), value.slice(2));
  }

  return value;
}

function resolveConfigPath(value, baseDir) {
  const expanded = expandHomePath(value.trim());

  if (!expanded) {
    return "";
  }

  return path.isAbsolute(expanded) ? expanded : path.resolve(baseDir, expanded);
}

function matchSimpleGlob(name, pattern) {
  let regexSource = "^";

  for (const char of pattern) {
    if (char === "*") {
      regexSource += ".*";
    } else if (char === "?") {
      regexSource += ".";
    } else if (/[.+^${}()|[\]\\]/.test(char)) {
      regexSource += `\\${char}`;
    } else {
      regexSource += char;
    }
  }

  regexSource += "$";
  return new RegExp(regexSource).test(name);
}

function expandIncludePaths(pattern, baseDir) {
  const resolved = resolveConfigPath(pattern, baseDir);

  if (!resolved) {
    return [];
  }

  if (!/[*?]/.test(resolved)) {
    return [resolved];
  }

  const dir = path.dirname(resolved);
  const filePattern = path.basename(resolved);

  try {
    return fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && matchSimpleGlob(entry.name, filePattern))
      .map((entry) => path.join(dir, entry.name));
  } catch (error) {
    return [];
  }
}

function tokenizeConfigLine(line) {
  const tokens = [];
  let current = "";
  let quote = null;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];

    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }

    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (current) {
    tokens.push(current);
  }

  return tokens;
}

function isConcreteHostAlias(token) {
  if (!token || token.startsWith("!")) {
    return false;
  }

  if (/[*?]/.test(token)) {
    return false;
  }

  return HOST_ALIAS_RE.test(token);
}

function collectHostsFromConfig(filePath, hosts, visited, depth) {
  if (depth > MAX_INCLUDE_DEPTH) {
    return;
  }

  let resolvedPath;

  try {
    resolvedPath = fs.realpathSync(filePath);
  } catch (error) {
    if (error.code === "ENOENT") {
      return;
    }

    throw error;
  }

  if (visited.has(resolvedPath)) {
    return;
  }

  visited.add(resolvedPath);

  const content = fs.readFileSync(resolvedPath, "utf8");
  const baseDir = path.dirname(resolvedPath);

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();

    if (!line) {
      continue;
    }

    const tokens = tokenizeConfigLine(line);

    if (tokens.length < 2) {
      continue;
    }

    const keyword = tokens[0].toLowerCase();

    if (keyword === "host") {
      for (const token of tokens.slice(1)) {
        if (isConcreteHostAlias(token)) {
          hosts.add(token);
        }
      }
      continue;
    }

    if (keyword === "include") {
      for (const pattern of tokens.slice(1)) {
        for (const includePath of expandIncludePaths(pattern, baseDir)) {
          collectHostsFromConfig(includePath, hosts, visited, depth + 1);
        }
      }
    }
  }
}

function listSshHosts() {
  const hosts = new Set();
  const visited = new Set();

  try {
    collectHostsFromConfig(DEFAULT_SSH_CONFIG, hosts, visited, 0);
  } catch (error) {
    if (error.code === "ENOENT") {
      return { ok: true, state: "ready", hosts: [] };
    }

    return {
      ok: false,
      state: "error",
      message: `Failed to read SSH config: ${error.message}`,
      hosts: []
    };
  }

  return {
    ok: true,
    state: "ready",
    hosts: Array.from(hosts).sort((a, b) => a.localeCompare(b))
  };
}

function readNativeMessage() {
  return new Promise((resolve, reject) => {
    let input = Buffer.alloc(0);
    let expectedLength = null;
    let settled = false;

    function finish(message) {
      if (settled) {
        return;
      }

      settled = true;
      resolve(message);
    }

    function fail(error) {
      if (settled) {
        return;
      }

      settled = true;
      reject(error);
    }

    process.stdin.on("data", (chunk) => {
      input = Buffer.concat([input, chunk]);

      if (expectedLength === null && input.length >= 4) {
        expectedLength = input.readUInt32LE(0);
      }

      if (expectedLength === null || input.length < 4 + expectedLength) {
        return;
      }

      try {
        const payload = input.slice(4, 4 + expectedLength).toString("utf8");
        finish(JSON.parse(payload));
      } catch (error) {
        fail(error);
      }
    });

    process.stdin.on("end", () => {
      if (!settled) {
        fail(new Error("Missing native message payload."));
      }
    });

    process.stdin.on("error", fail);
  });
}

function writeNativeMessage(message) {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  const header = Buffer.alloc(4);

  header.writeUInt32LE(payload.length, 0);
  return new Promise((resolve) => {
    process.stdout.write(Buffer.concat([header, payload]), resolve);
  });
}

async function handleMessage(message) {
  if (!message || typeof message !== "object") {
    return { ok: false, state: "error", message: "Invalid message." };
  }

  if (message.action === "status") {
    return getStatus();
  }

  if (message.action === "listHosts") {
    return listSshHosts();
  }

  if (message.action === "connect") {
    return connectTunnels(normalizeHostAliases(message));
  }

  if (message.action === "disconnect") {
    return disconnectAll();
  }

  if (message.action === "dnsStart") {
    return dnsStart(message);
  }

  if (message.action === "dnsStop") {
    return dnsStop();
  }

  if (message.action === "dnsStatus") {
    return dnsStatus();
  }

  if (message.action === "dnsQuery") {
    return dnsQuery(message);
  }

  if (message.action === "dnsInstallResolver") {
    return dnsInstallResolver(message);
  }

  if (message.action === "dnsUninstallResolver") {
    return dnsUninstallResolver();
  }

  if (message.action === "gatewayStart") {
    return gatewayStart(message);
  }

  if (message.action === "gatewayStop") {
    return gatewayStop();
  }

  return { ok: false, state: "error", message: "Unknown action." };
}

async function main() {
  try {
    const message = await readNativeMessage();
    await writeNativeMessage(await handleMessage(message));
    process.exit(0);
  } catch (error) {
    await writeNativeMessage({
      ok: false,
      state: "error",
      message: error.message
    });
    process.exit(1);
  }
}

main();
