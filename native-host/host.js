#!/usr/bin/env node
"use strict";

const fs = require("fs");
const net = require("net");
const path = require("path");
const { execFile, spawn } = require("child_process");

const HOST_ALIAS_RE = /^[A-Za-z0-9._-]+$/;
const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 1080;
const RUNTIME_DIR = path.join(__dirname, "runtime");
const STATE_FILE = path.join(RUNTIME_DIR, "state.json");
const SSH_LOG_FILE = path.join(RUNTIME_DIR, "ssh.log");

function ensureRuntimeDir() {
  fs.mkdirSync(RUNTIME_DIR, { recursive: true, mode: 0o700 });
}

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
  } catch (error) {
    return {};
  }
}

function writeState(state) {
  ensureRuntimeDir();
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
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

async function isRecordedSshProcess(pid) {
  const command = await readProcessCommand(pid);

  return (
    command.includes("ssh") &&
    command.includes("-N") &&
    command.includes("-D") &&
    command.includes(`${PROXY_HOST}:${PROXY_PORT}`)
  );
}

function isPortOpen() {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: PROXY_HOST, port: PROXY_PORT });
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

async function getStatus() {
  const state = readState();
  const pid = Number(state.pid);
  const portOpen = await isPortOpen();

  if (!pid || !isProcessAlive(pid)) {
    if (portOpen) {
      return {
        ok: false,
        state: "error",
        message: `${PROXY_HOST}:${PROXY_PORT} is already in use by an unknown process.`
      };
    }

    clearState();
    return { ok: true, state: "disconnected" };
  }

  if (!(await isRecordedSshProcess(pid))) {
    clearState();
    return {
      ok: false,
      state: "error",
      message: "Recorded PID is no longer the Webhole ssh process."
    };
  }

  return {
    ok: true,
    state: portOpen ? "connected" : "starting",
    pid,
    hostAlias: state.hostAlias || ""
  };
}

function validateHostAlias(hostAlias) {
  if (!HOST_ALIAS_RE.test(hostAlias)) {
    return {
      ok: false,
      state: "error",
      message: "Invalid SSH Host alias."
    };
  }

  return null;
}

async function connectTunnel(hostAlias) {
  const validationError = validateHostAlias(hostAlias);

  if (validationError) {
    return validationError;
  }

  const status = await getStatus();

  if (status.ok && (status.state === "connected" || status.state === "starting")) {
    return status;
  }

  if (!status.ok) {
    return status;
  }

  ensureRuntimeDir();
  appendSshLog(`starting ssh tunnel for ${hostAlias}`);

  const stderrFd = fs.openSync(SSH_LOG_FILE, "a");
  const child = spawn(
    "ssh",
    [
      "-N",
      "-n",
      "-D",
      `${PROXY_HOST}:${PROXY_PORT}`,
      "-o",
      "ExitOnForwardFailure=yes",
      "-o",
      "BatchMode=yes",
      hostAlias
    ],
    {
      detached: true,
      stdio: ["ignore", "ignore", stderrFd]
    }
  );

  child.once("error", (error) => {
    appendSshLog(`ssh spawn failed: ${error.message}`);
  });

  child.unref();
  fs.closeSync(stderrFd);

  if (!child.pid) {
    return {
      ok: false,
      state: "error",
      message: "ssh failed to start."
    };
  }

  writeState({
    pid: child.pid,
    hostAlias,
    startedAt: new Date().toISOString()
  });

  for (let i = 0; i < 50; i += 1) {
    if (!isProcessAlive(child.pid)) {
      clearState();
      appendSshLog("ssh exited before opening SOCKS5 port");
      return {
        ok: false,
        state: "error",
        message: `ssh exited before opening ${PROXY_HOST}:${PROXY_PORT}.`
      };
    }

    if (await isPortOpen()) {
      return {
        ok: true,
        state: "connected",
        pid: child.pid,
        hostAlias
      };
    }

    await wait(100);
  }

  appendSshLog(`ssh did not open ${PROXY_HOST}:${PROXY_PORT} within 5 seconds`);
  process.kill(child.pid, "SIGTERM");
  clearState();

  return {
    ok: false,
    state: "error",
    message: `ssh did not open ${PROXY_HOST}:${PROXY_PORT}.`
  };
}

async function disconnectTunnel() {
  const state = readState();
  const pid = Number(state.pid);

  if (!pid || !isProcessAlive(pid)) {
    clearState();
    return { ok: true, state: "disconnected" };
  }

  if (!(await isRecordedSshProcess(pid))) {
    clearState();
    return {
      ok: false,
      state: "error",
      message: "Recorded PID is no longer the Webhole ssh process."
    };
  }

  process.kill(pid, "SIGTERM");

  for (let i = 0; i < 20; i += 1) {
    if (!isProcessAlive(pid)) {
      clearState();
      return { ok: true, state: "disconnected" };
    }

    await wait(100);
  }

  process.kill(pid, "SIGKILL");
  clearState();
  return { ok: true, state: "disconnected" };
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

  if (message.action === "connect") {
    return connectTunnel(String(message.hostAlias || "").trim());
  }

  if (message.action === "disconnect") {
    return disconnectTunnel();
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
