const DEFAULT_MODE = "direct";
const HOST_ALIAS_RE = /^[A-Za-z0-9._-]+$/;
const LOG_LIMIT = 80;
const VALID_MODES = new Set(["direct", "global", "auto"]);

const modeInputs = Array.from(document.querySelectorAll('input[name="mode"]'));
const hostAliasInput = document.getElementById("hostAliasInput");
const connectButton = document.getElementById("connectButton");
const disconnectButton = document.getElementById("disconnectButton");
const domainsSection = document.getElementById("domainsSection");
const domainsInput = document.getElementById("domainsInput");
const helpToggle = document.getElementById("helpToggle");
const helpSection = document.getElementById("helpSection");
const logToggle = document.getElementById("logToggle");
const logSection = document.getElementById("logSection");
const logList = document.getElementById("logList");
const logSummaryText = document.getElementById("logSummaryText");
const logSummaryMeta = document.getElementById("logSummaryMeta");
const clearLogButton = document.getElementById("clearLogButton");
const statusEl = document.getElementById("status");

let saveTimer = 0;

setStatus("Ready");

function normalizeMode(mode) {
  return VALID_MODES.has(mode) ? mode : DEFAULT_MODE;
}

function normalizeDomains(value) {
  const seen = new Set();

  return value
    .split(/\r?\n/)
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean)
    .filter((domain) => {
      if (seen.has(domain)) {
        return false;
      }

      seen.add(domain);
      return true;
    });
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("is-error", isError);
}

function formatLogTime(value) {
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function renderLogs(logs) {
  const entries = Array.isArray(logs) ? logs.slice(-LOG_LIMIT).reverse() : [];

  if (entries.length === 0) {
    logSummaryText.textContent = "No logs yet.";
    logSummaryMeta.textContent = "";
    logList.innerHTML = '<div class="hint">No logs yet.</div>';
    return;
  }

  const latest = entries[0];
  logSummaryText.textContent = latest.message || "Log entry";
  logSummaryMeta.textContent = formatLogTime(latest.time || Date.now());

  logList.replaceChildren(
    ...entries.map((entry) => {
      const item = document.createElement("div");
      const time = document.createElement("span");
      const message = document.createElement("span");

      item.className = "log-item";
      time.className = "log-time";
      message.className = "log-message";
      time.textContent = formatLogTime(entry.time || Date.now());
      message.textContent = entry.message || "";

      item.append(time, message);
      return item;
    })
  );
}

function appendLog(message) {
  chrome.storage.local.get({ logs: [] }, (items) => {
    const logs = Array.isArray(items.logs) ? items.logs : [];

    chrome.storage.local.set({
      logs: logs.concat({ time: Date.now(), message }).slice(-LOG_LIMIT)
    });
  });
}

function normalizeHostAlias(value) {
  return value.trim();
}

function isValidHostAlias(value) {
  return HOST_ALIAS_RE.test(value);
}

function getSelectedMode() {
  const selected = modeInputs.find((input) => input.checked);
  return normalizeMode(selected?.value);
}

function setSelectedMode(mode) {
  const normalizedMode = normalizeMode(mode);

  for (const input of modeInputs) {
    input.checked = input.value === normalizedMode;
  }

  domainsSection.classList.toggle("is-open", normalizedMode === "auto");
}

function saveSettings(showStatus = true) {
  clearTimeout(saveTimer);

  saveTimer = setTimeout(() => {
    const domains = normalizeDomains(domainsInput.value);
    const hostAlias = normalizeHostAlias(hostAliasInput.value);
    domainsInput.value = domains.join("\n");

    chrome.storage.local.set(
      {
        mode: getSelectedMode(),
        domains,
        hostAlias
      },
      () => {
        const error = chrome.runtime.lastError;

        if (showStatus || error) {
          setStatus(error ? error.message : "Saved", Boolean(error));
        }
      }
    );
  }, 120);
}

function sendTunnelMessage(action) {
  return new Promise((resolve) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }

      settled = true;
      resolve({
        ok: false,
        state: "error",
        message: "Timed out waiting for background response."
      });
    }, 8000);

    chrome.runtime.sendMessage(
      {
        type: "webhole:tunnel",
        action,
        hostAlias: normalizeHostAlias(hostAliasInput.value),
        mode: getSelectedMode(),
        domains: normalizeDomains(domainsInput.value)
      },
      (response) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timeout);

        const error = chrome.runtime.lastError;

        if (error) {
          resolve({
            ok: false,
            state: "error",
            message: error.message
          });
          return;
        }

        resolve(response || { ok: false, state: "error", message: "Empty background response." });
      }
    );
  });
}

function setBusy(isBusy) {
  connectButton.disabled = isBusy;
  disconnectButton.disabled = isBusy;
}

function setConnectButtonState(state) {
  connectButton.classList.remove("is-connected", "is-disconnected", "is-pending");

  if (state === "connected") {
    connectButton.classList.add("is-connected");
    connectButton.textContent = "On";
    return;
  }

  if (state === "starting") {
    connectButton.classList.add("is-pending");
    connectButton.textContent = "On";
    return;
  }

  connectButton.classList.add("is-disconnected");
  connectButton.textContent = "On";
}

function formatTunnelStatus(response) {
  if (!response.ok) {
    return response.message || "Tunnel error";
  }

  if (response.state === "connected") {
    return "Tunnel connected";
  }

  if (response.state === "starting") {
    return "Tunnel starting";
  }

  return "Tunnel disconnected";
}

async function refreshTunnelStatus() {
  try {
    const response = await sendTunnelMessage("status");
    setConnectButtonState(response.state);
    setStatus(formatTunnelStatus(response), !response.ok);
    appendLog(`Status: ${formatTunnelStatus(response)}`);
  } catch (error) {
    setConnectButtonState("error");
    setStatus(error.message, true);
    appendLog(`Status failed: ${error.message}`);
  }
}

async function connectTunnel() {
  const hostAlias = normalizeHostAlias(hostAliasInput.value);

  if (!isValidHostAlias(hostAlias)) {
    setStatus("Invalid SSH Host alias", true);
    return;
  }

  setBusy(true);
  setStatus("Connecting...");
  setConnectButtonState("starting");
  appendLog(`Connect requested: ${hostAlias}`);

  if (getSelectedMode() === DEFAULT_MODE) {
    setSelectedMode("global");
  }

  try {
    saveSettings(false);

    const response = await sendTunnelMessage("connect");
    setConnectButtonState(response.state);
    setStatus(formatTunnelStatus(response), !response.ok);
    appendLog(`Connect result: ${formatTunnelStatus(response)}`);
  } catch (error) {
    setConnectButtonState("error");
    setStatus(error.message, true);
    appendLog(`Connect failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

async function disconnectTunnel() {
  setBusy(true);
  setStatus("Disconnecting...");
  setConnectButtonState("starting");
  appendLog("Disconnect requested");

  try {
    const response = await sendTunnelMessage("disconnect");

    setSelectedMode(DEFAULT_MODE);
    setConnectButtonState(response.state);
    setStatus(formatTunnelStatus(response), !response.ok);
    appendLog(`Disconnect result: ${formatTunnelStatus(response)}`);
  } catch (error) {
    setConnectButtonState("error");
    setStatus(error.message, true);
    appendLog(`Disconnect failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

chrome.storage.local.get(
  {
    mode: DEFAULT_MODE,
    domains: [],
    hostAlias: "",
    logs: []
  },
  (items) => {
    const mode = normalizeMode(items.mode);
    const domains = Array.isArray(items.domains) ? items.domains : [];

    setSelectedMode(mode);
    setConnectButtonState("disconnected");
    hostAliasInput.value = normalizeHostAlias(String(items.hostAlias || ""));
    domainsInput.value = normalizeDomains(domains.join("\n")).join("\n");
    renderLogs(items.logs);
    refreshTunnelStatus();
  }
);

for (const input of modeInputs) {
  input.addEventListener("change", () => {
    setSelectedMode(input.value);
    saveSettings();
  });
}

hostAliasInput.addEventListener("input", saveSettings);
connectButton.addEventListener("click", connectTunnel);
disconnectButton.addEventListener("click", disconnectTunnel);
domainsInput.addEventListener("input", saveSettings);

helpToggle.addEventListener("click", () => {
  helpSection.classList.toggle("is-open");
});

logToggle.addEventListener("click", () => {
  logSection.classList.toggle("is-open");
});

clearLogButton.addEventListener("click", () => {
  chrome.storage.local.set({ logs: [] }, () => {
    renderLogs([]);
    setStatus("Log cleared");
  });
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.logs) {
    renderLogs(changes.logs.newValue);
  }
});
