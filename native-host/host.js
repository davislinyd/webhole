#!/usr/bin/env node
"use strict";

const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const { execFile, spawn } = require("child_process");

const HOST_ALIAS_RE = /^[A-Za-z0-9._-]+$/;
const PROXY_HOST = "127.0.0.1";
const BASE_PORT = 1080;
const MAX_TUNNELS = 8;
const MAX_INCLUDE_DEPTH = 16;
// ProxyCommand / jump hosts often need longer than a few seconds.
const TUNNEL_READY_TIMEOUT_MS = 30000;
const TUNNEL_POLL_MS = 200;
const SSH_STDERR_LIMIT = 4000;
const RUNTIME_DIR = path.join(__dirname, "runtime");
const STATE_FILE = path.join(RUNTIME_DIR, "state.json");
const SSH_LOG_FILE = path.join(RUNTIME_DIR, "ssh.log");
const DEFAULT_SSH_CONFIG = path.join(os.homedir(), ".ssh", "config");

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

function normalizeState(raw) {
  if (!raw || typeof raw !== "object") {
    return { tunnels: {} };
  }

  if (raw.tunnels && typeof raw.tunnels === "object") {
    const tunnels = {};

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

    return { tunnels };
  }

  // Legacy single-tunnel state.
  if (raw.pid && raw.hostAlias) {
    const hostAlias = String(raw.hostAlias);
    const pid = Number(raw.pid);

    if (HOST_ALIAS_RE.test(hostAlias) && Number.isInteger(pid)) {
      return {
        tunnels: {
          [hostAlias]: {
            pid,
            port: BASE_PORT,
            startedAt: raw.startedAt || ""
          }
        }
      };
    }
  }

  return { tunnels: {} };
}

function readState() {
  return normalizeState(readRawState());
}

function writeState(state) {
  ensureRuntimeDir();
  const tunnels = state.tunnels && typeof state.tunnels === "object" ? state.tunnels : {};

  if (Object.keys(tunnels).length === 0) {
    clearState();
    return;
  }

  fs.writeFileSync(STATE_FILE, JSON.stringify({ tunnels }, null, 2));
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
  return { tunnels: nextTunnels, reports, hasError };
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

  process.kill(pid, "SIGTERM");

  for (let i = 0; i < 20; i += 1) {
    if (!isProcessAlive(pid)) {
      return;
    }

    await wait(100);
  }

  if (isProcessAlive(pid)) {
    process.kill(pid, "SIGKILL");
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

  clearState();
  return { ok: true, state: "disconnected", tunnels: [] };
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
