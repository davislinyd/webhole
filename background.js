const DEFAULT_MODE = "direct";
const LOG_LIMIT = 80;
const NATIVE_HOST = "com.webhole.host";
const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 1080;
const VALID_MODES = new Set(["direct", "global", "auto"]);
const ICONS = {
  connected: {
    16: "icons/connected/icon-16.png",
    32: "icons/connected/icon-32.png",
    48: "icons/connected/icon-48.png",
    128: "icons/connected/icon-128.png"
  },
  disconnected: {
    16: "icons/disconnected/icon-16.png",
    32: "icons/disconnected/icon-32.png",
    48: "icons/disconnected/icon-48.png",
    128: "icons/disconnected/icon-128.png"
  }
};

function normalizeMode(mode) {
  return VALID_MODES.has(mode) ? mode : DEFAULT_MODE;
}

function normalizeDomains(domains) {
  const values = Array.isArray(domains) ? domains : [];
  const seen = new Set();

  return values
    .map((domain) => String(domain).trim().toLowerCase())
    .filter(Boolean)
    .filter((domain) => {
      if (seen.has(domain)) {
        return false;
      }

      seen.add(domain);
      return true;
    });
}

function appendLog(message) {
  return new Promise((resolve) => {
    chrome.storage.local.get({ logs: [] }, (items) => {
      const logs = Array.isArray(items.logs) ? items.logs : [];

      chrome.storage.local.set(
        {
          logs: logs.concat({ time: Date.now(), message }).slice(-LOG_LIMIT)
        },
        resolve
      );
    });
  });
}

function setActionIcon(isConnected) {
  chrome.action.setIcon({
    path: isConnected ? ICONS.connected : ICONS.disconnected
  });
}

function logProxyResult(action) {
  const error = chrome.runtime.lastError;

  if (error) {
    console.error(`Webhole proxy ${action} failed: ${error.message}`);
    appendLog(`Proxy ${action} failed: ${error.message}`);
    return;
  }

  appendLog(`Proxy ${action} applied`);
}

function clearProxy() {
  chrome.proxy.settings.clear({ scope: "regular" }, () => logProxyResult("clear"));
}

function setGlobalProxy() {
  chrome.proxy.settings.set(
    {
      scope: "regular",
      value: {
        mode: "fixed_servers",
        rules: {
          singleProxy: {
            scheme: "socks5",
            host: PROXY_HOST,
            port: PROXY_PORT
          }
        }
      }
    },
    () => logProxyResult("set global")
  );
}

function createPacScript(domains) {
  return `
var WEBHOLE_DOMAINS = ${JSON.stringify(domains)};

function FindProxyForURL(url, host) {
  var normalizedHost = String(host).toLowerCase();

  for (var i = 0; i < WEBHOLE_DOMAINS.length; i += 1) {
    var domain = WEBHOLE_DOMAINS[i];
    var suffix = "." + domain;

    if (
      normalizedHost === domain ||
      normalizedHost.slice(-suffix.length) === suffix
    ) {
      return "SOCKS5 ${PROXY_HOST}:${PROXY_PORT}";
    }
  }

  return "DIRECT";
}
`;
}

function setAutoProxy(domains) {
  chrome.proxy.settings.set(
    {
      scope: "regular",
      value: {
        mode: "pac_script",
        pacScript: {
          data: createPacScript(domains)
        }
      }
    },
    () => logProxyResult("set auto")
  );
}

function applyProxy(mode, domains) {
  const normalizedMode = normalizeMode(mode);
  const normalizedDomains = normalizeDomains(domains);

  if (normalizedMode === "global") {
    setGlobalProxy();
    return;
  }

  if (normalizedMode === "auto") {
    setAutoProxy(normalizedDomains);
    return;
  }

  clearProxy();
}

function saveSettings(settings) {
  return new Promise((resolve) => {
    chrome.storage.local.set(settings, () => {
      const error = chrome.runtime.lastError;

      if (error) {
        console.error(`Webhole settings save failed: ${error.message}`);
      }

      resolve();
    });
  });
}

function getStoredSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(
      {
        mode: DEFAULT_MODE,
        domains: [],
        hostAlias: ""
      },
      (items) => {
        const error = chrome.runtime.lastError;

        if (error) {
          console.error(`Webhole settings load failed: ${error.message}`);
          resolve({ mode: DEFAULT_MODE, domains: [], hostAlias: "" });
          return;
        }

        resolve(items);
      }
    );
  });
}

function setDirectMode() {
  return new Promise((resolve) => {
    chrome.storage.local.set({ mode: DEFAULT_MODE }, () => {
      const error = chrome.runtime.lastError;

      if (error) {
        console.error(`Webhole settings save failed: ${error.message}`);
      }

      clearProxy();
      resolve();
    });
  });
}

function applyStoredProxy() {
  chrome.storage.local.get(
    {
      mode: DEFAULT_MODE,
      domains: []
    },
    (items) => {
      const error = chrome.runtime.lastError;

      if (error) {
        console.error(`Webhole settings load failed: ${error.message}`);
        clearProxy();
        return;
      }

      applyProxy(items.mode, items.domains);
    }
  );
}

function sendNativeMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      const error = chrome.runtime.lastError;

      if (error) {
        appendLog(`Native ${message.action} failed: ${error.message}`);
        resolve({
          ok: false,
          state: "error",
          message: error.message
        });
        return;
      }

      const result = response || { ok: false, state: "error", message: "Empty native host response." };
      appendLog(`Native ${message.action}: ${result.state}`);
      resolve(result);
    });
  });
}

async function syncTunnelAndProxy() {
  const response = await sendNativeMessage({ action: "status" });

  if (response.ok && response.state === "connected") {
    setActionIcon(true);
    applyStoredProxy();
    return response;
  }

  setActionIcon(false);
  clearProxy();
  return response;
}

async function handleTunnelMessage(message) {
  const settings = await getStoredSettings();
  const hostAlias = String(message.hostAlias || settings.hostAlias || "").trim();

  if (message.action === "status") {
    return sendNativeMessage({ action: "status" });
  }

  if (message.action === "connect") {
    appendLog(`Background connect: ${hostAlias || "(empty host)"}`);
    const mode = normalizeMode(message.mode || settings.mode);
    const domains = normalizeDomains(message.domains || settings.domains);
    const response = await sendNativeMessage({
      action: "connect",
      hostAlias
    });

    if (response.ok && (response.state === "connected" || response.state === "starting")) {
      setActionIcon(response.state === "connected");
      await saveSettings({
        mode,
        domains,
        hostAlias
      });
      applyProxy(mode, domains);
    } else {
      setActionIcon(false);
    }

    return response;
  }

  if (message.action === "disconnect") {
    appendLog("Background disconnect");
    const response = await sendNativeMessage({ action: "disconnect" });

    setActionIcon(false);
    await setDirectMode();

    return response;
  }

  return {
    ok: false,
    state: "error",
    message: "Unknown tunnel action."
  };
}

chrome.runtime.onInstalled.addListener(syncTunnelAndProxy);
chrome.runtime.onStartup.addListener(syncTunnelAndProxy);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "webhole:tunnel") {
    return false;
  }

  handleTunnelMessage(message).then(sendResponse);
  return true;
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local" || (!changes.mode && !changes.domains)) {
    return;
  }

  syncTunnelAndProxy();
});
