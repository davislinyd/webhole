const DEFAULT_MODE = "direct";
const HOST_ALIAS_RE = /^[A-Za-z0-9._-]+$/;
const DOMAIN_PATTERN_RE = /^[a-z0-9._-]+$/;
const LOG_LIMIT = 80;
const MAX_ROUTES = 50;
const VALID_MODES = new Set(["direct", "global", "routes"]);
const VALID_ROUTES_FALLBACKS = new Set(["direct", "default"]);
const DEFAULT_ROUTES_FALLBACK = "direct";

const popupOpenSource = new URLSearchParams(window.location.search).get("src") || "action";
const popupOpenAt = Date.now();

// Diagnostic: proves whether the popup document actually loaded when the icon was clicked.
console.info("[webhole] popup open", { at: popupOpenAt, source: popupOpenSource });
try {
  chrome.storage.local.set({
    lastPopupOpenAt: popupOpenAt,
    lastPopupOpenSource: popupOpenSource
  });
} catch (error) {
  console.warn("[webhole] popup open mark failed", error);
}

const modeInputs = Array.from(document.querySelectorAll('input[name="mode"]'));
const routesFallbackInputs = Array.from(document.querySelectorAll('input[name="routesFallback"]'));
const defaultHostSelect = document.getElementById("defaultHostSelect");
const defaultHostLabel = document.getElementById("defaultHostLabel");
const defaultHostHint = document.getElementById("defaultHostHint");
const connectButton = document.getElementById("connectButton");
const disconnectButton = document.getElementById("disconnectButton");
const routesSection = document.getElementById("routesSection");
const directPanel = document.getElementById("directPanel");
const routesFallbackRow = document.getElementById("routesFallbackRow");
const routesList = document.getElementById("routesList");
const addRouteButton = document.getElementById("addRouteButton");
const enableAllRoutesButton = document.getElementById("enableAllRoutesButton");
const disableAllRoutesButton = document.getElementById("disableAllRoutesButton");
const helpToggle = document.getElementById("helpToggle");
const helpSection = document.getElementById("helpSection");
const logToggle = document.getElementById("logToggle");
const logSection = document.getElementById("logSection");
const logList = document.getElementById("logList");
const logSummaryText = document.getElementById("logSummaryText");
const logSummaryMeta = document.getElementById("logSummaryMeta");
const clearLogButton = document.getElementById("clearLogButton");
const openWindowButton = document.getElementById("openWindowButton");
const statusEl = document.getElementById("status");
const tunnelDetailsEl = document.getElementById("tunnelDetails");
const endpointLabel = document.getElementById("endpointLabel");

let saveTimer = 0;
let availableHosts = [];
let routesState = [];

// Paint shell immediately; data loads after first frame (see bootPopup).
if (statusEl) {
  statusEl.textContent = "Loading…";
  statusEl.classList.remove("is-error");
}

function normalizeMode(mode) {
  if (mode === "auto") {
    return "routes";
  }

  return VALID_MODES.has(mode) ? mode : DEFAULT_MODE;
}

function normalizeRoutesFallback(value) {
  return VALID_ROUTES_FALLBACKS.has(value) ? value : DEFAULT_ROUTES_FALLBACK;
}

function normalizeHostAlias(value) {
  return String(value || "").trim();
}

/**
 * Parse user route pattern into host + optional path prefix.
 * Examples: example.com | example.com/api | https://example.com/wiki
 */
function parseRoutePattern(value) {
  let raw = String(value || "").trim();

  if (!raw) {
    return { pattern: "", hostPattern: "", pathPrefix: "" };
  }

  raw = raw.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");

  const at = raw.indexOf("@");
  const firstSlash = raw.indexOf("/");

  if (at !== -1 && (firstSlash === -1 || at < firstSlash)) {
    raw = raw.slice(at + 1);
  }

  raw = raw.split(/[?#]/)[0];

  let hostPart = raw;
  let pathPart = "";
  const slash = raw.indexOf("/");

  if (slash !== -1) {
    hostPart = raw.slice(0, slash);
    pathPart = raw.slice(slash);
  }

  hostPart = hostPart.replace(/:\d+$/, "").toLowerCase();

  let pathPrefix = "";

  if (pathPart && pathPart !== "/") {
    pathPrefix = pathPart.replace(/\/+$/, "");

    if (pathPrefix && !pathPrefix.startsWith("/")) {
      pathPrefix = `/${pathPrefix}`;
    }

    if (pathPrefix === "/") {
      pathPrefix = "";
    }
  }

  const pattern = pathPrefix ? `${hostPart}${pathPrefix}` : hostPart;

  return { pattern, hostPattern: hostPart, pathPrefix };
}

function isValidHostAlias(value) {
  return HOST_ALIAS_RE.test(value);
}

function isValidHostPattern(hostPattern) {
  return Boolean(hostPattern) && DOMAIN_PATTERN_RE.test(hostPattern);
}

function createRouteId() {
  return `r_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeRoutes(routes, { allowIncomplete = true, onlyEnabled = false } = {}) {
  const values = Array.isArray(routes) ? routes : [];
  const result = [];
  const seen = new Set();

  for (const route of values) {
    if (!route || typeof route !== "object") {
      continue;
    }

    const parsed = parseRoutePattern(route.pattern);
    const hostAlias = normalizeHostAlias(route.hostAlias);
    const enabled = route.enabled !== false;

    if (!allowIncomplete && (!isValidHostPattern(parsed.hostPattern) || !isValidHostAlias(hostAlias))) {
      continue;
    }

    if (onlyEnabled && !enabled) {
      continue;
    }

    const key = `${route.id || ""}\0${parsed.hostPattern}\0${parsed.pathPrefix}\0${hostAlias}`;

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push({
      id: String(route.id || createRouteId()),
      pattern: parsed.pattern,
      hostPattern: parsed.hostPattern,
      pathPrefix: parsed.pathPrefix,
      hostAlias,
      enabled
    });

    if (result.length >= MAX_ROUTES) {
      break;
    }
  }

  result.sort((a, b) => {
    const pathDiff = (b.pathPrefix || "").length - (a.pathPrefix || "").length;

    if (pathDiff !== 0) {
      return pathDiff;
    }

    const hostDiff = (b.hostPattern || "").length - (a.hostPattern || "").length;

    if (hostDiff !== 0) {
      return hostDiff;
    }

    return a.pattern.localeCompare(b.pattern);
  });

  return result;
}

function setStatus(message, isError = false) {
  if (!statusEl) {
    return;
  }

  statusEl.textContent = message;
  statusEl.classList.toggle("is-error", Boolean(isError));
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

function getSelectedMode() {
  const selected = modeInputs.find((input) => input.checked);
  return normalizeMode(selected?.value);
}

function getRoutesFallback() {
  const selected = routesFallbackInputs.find((input) => input.checked);
  return normalizeRoutesFallback(selected?.value);
}

function setRoutesFallback(value) {
  const normalized = normalizeRoutesFallback(value);

  for (const input of routesFallbackInputs) {
    input.checked = input.value === normalized;
  }
}

function updateDefaultHostUi(mode = getSelectedMode(), fallback = getRoutesFallback()) {
  const normalizedMode = normalizeMode(mode);
  const routesMode = normalizedMode === "routes";
  const globalMode = normalizedMode === "global";
  const directMode = normalizedMode === "direct";
  const useDefaultFallback = routesMode && fallback === "default";

  routesSection?.classList.toggle("is-open", routesMode);
  directPanel?.classList.toggle("is-open", directMode);

  if (globalMode) {
    defaultHostLabel.textContent = "SSH Host（必選）";
    defaultHostHint.textContent = "全部流量走此 SOCKS 出口。";
    defaultHostSelect.disabled = false;
  } else if (routesMode && useDefaultFallback) {
    defaultHostLabel.textContent = "SSH Host（未匹配兜底）";
    defaultHostHint.textContent = "未命中任何 route 時走此 Host。";
    defaultHostSelect.disabled = false;
  } else if (routesMode) {
    defaultHostLabel.textContent = "SSH Host（可空白）";
    defaultHostHint.textContent = "未匹配走本機；各規則在下方選 via。";
    defaultHostSelect.disabled = false;
  } else {
    defaultHostLabel.textContent = "SSH Host";
    defaultHostHint.textContent = "Direct 不使用；On 會切到 Global。";
    defaultHostSelect.disabled = false;
  }
}

function setSelectedMode(mode) {
  const normalizedMode = normalizeMode(mode);

  for (const input of modeInputs) {
    input.checked = input.value === normalizedMode;
  }

  updateDefaultHostUi(normalizedMode, getRoutesFallback());
}

function getDefaultHostAlias() {
  return normalizeHostAlias(defaultHostSelect.value);
}

function buildHostSelectOptions(selectedHost, includeBlank = true) {
  const fragment = document.createDocumentFragment();

  if (includeBlank) {
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = availableHosts.length ? "Select host…" : "No hosts found";
    fragment.append(blank);
  }

  const hosts = availableHosts.slice();
  const preferred = normalizeHostAlias(selectedHost || "");

  if (preferred && !hosts.includes(preferred)) {
    hosts.unshift(preferred);
  }

  for (const alias of hosts) {
    const option = document.createElement("option");
    option.value = alias;
    option.textContent = alias;
    fragment.append(option);
  }

  return fragment;
}

function populateDefaultHostSelect(selectedHost) {
  defaultHostSelect.replaceChildren(buildHostSelectOptions(selectedHost, true));
  const preferred = normalizeHostAlias(selectedHost || "");
  defaultHostSelect.value = preferred && [...defaultHostSelect.options].some((opt) => opt.value === preferred)
    ? preferred
    : "";
  defaultHostSelect.disabled = availableHosts.length === 0 && !preferred;
}

function readRoutesFromDom() {
  const rows = Array.from(routesList.querySelectorAll(".route-row"));
  const routes = [];

  for (const row of rows) {
    const enabledInput = row.querySelector('[data-field="enabled"]');
    const patternInput = row.querySelector('[data-field="pattern"]');
    const hostSelect = row.querySelector('[data-field="host"]');

    routes.push({
      id: row.dataset.routeId || createRouteId(),
      pattern: parseRoutePattern(patternInput?.value || "").pattern,
      hostAlias: normalizeHostAlias(hostSelect?.value || ""),
      enabled: enabledInput ? Boolean(enabledInput.checked) : true
    });
  }

  return routes;
}

function renderRoutes(routes) {
  routesState = normalizeRoutes(routes, { allowIncomplete: true });
  routesList.replaceChildren();

  if (!routesState.length) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = "No routes yet. Click + Add.";
    routesList.append(empty);
    return;
  }

  for (const route of routesState) {
    const row = document.createElement("div");
    row.className = `route-row${route.enabled ? "" : " is-disabled"}`;
    row.dataset.routeId = route.id;

    const enabledInput = document.createElement("input");
    enabledInput.type = "checkbox";
    enabledInput.dataset.field = "enabled";
    enabledInput.checked = route.enabled !== false;
    enabledInput.title = "Enable this route";
    enabledInput.setAttribute("aria-label", "Enable route");

    const patternInput = document.createElement("input");
    patternInput.type = "text";
    patternInput.dataset.field = "pattern";
    patternInput.placeholder = "example.com or example.com/api";
    patternInput.spellcheck = false;
    patternInput.autocomplete = "off";
    patternInput.value = route.pattern;

    const hostSelect = document.createElement("select");
    hostSelect.dataset.field = "host";
    hostSelect.replaceChildren(buildHostSelectOptions(route.hostAlias, true));
    hostSelect.value = route.hostAlias || "";

    const hostRow = document.createElement("div");
    hostRow.className = "route-host-row";
    const viaLabel = document.createElement("span");
    viaLabel.className = "route-via";
    viaLabel.textContent = "via";
    hostRow.append(viaLabel, hostSelect);

    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.className = "route-remove";
    removeButton.title = "Remove route";
    removeButton.textContent = "×";

    enabledInput.addEventListener("change", () => {
      row.classList.toggle("is-disabled", !enabledInput.checked);
      applyRouteSettingsNow({
        announce: enabledInput.checked ? "Route enabled" : "Route disabled",
        preferSession: enabledInput.checked
      });
    });
    patternInput.addEventListener("input", () => saveSettings());
    hostSelect.addEventListener("change", () => saveSettings());
    removeButton.addEventListener("click", () => {
      routesState = readRoutesFromDom().filter((item) => item.id !== route.id);
      renderRoutes(routesState);
      saveSettings();
    });

    row.append(enabledInput, patternInput, removeButton, hostRow);
    routesList.append(row);
  }
}

function addRoute() {
  const current = readRoutesFromDom();

  if (current.length >= MAX_ROUTES) {
    setStatus(`At most ${MAX_ROUTES} routes`, true);
    return;
  }

  current.push({
    id: createRouteId(),
    pattern: "",
    hostAlias: getDefaultHostAlias() || availableHosts[0] || "",
    enabled: true
  });
  renderRoutes(current);
  saveSettings(false);

  const lastPattern = routesList.querySelector(".route-row:last-child [data-field='pattern']");
  lastPattern?.focus();
}

function collectSettingsFromUi() {
  const routes = normalizeRoutes(readRoutesFromDom(), { allowIncomplete: true });
  const defaultHostAlias = getDefaultHostAlias();
  const mode = getSelectedMode();
  const routesFallback = getRoutesFallback();

  return {
    mode,
    defaultHostAlias,
    hostAlias: defaultHostAlias,
    routes,
    routesFallback,
    // Selecting Direct clears the desired session; Off also clears it in background.
    ...(mode === DEFAULT_MODE ? { sessionDesired: false } : {})
  };
}

function isUiConnected() {
  return connectButton.classList.contains("is-connected");
}

function countEnabledCompleteRoutes(routes) {
  return normalizeRoutes(routes, { allowIncomplete: false, onlyEnabled: true }).length;
}

/**
 * Persist settings immediately and ask background to reconcile tunnels/PAC.
 * Used by All on/off and enable checkboxes so changes are not lost under debounce/suppress races.
 */
function applyRouteSettingsNow(options = {}) {
  const { announce = "", preferSession = false } = options;
  const settings = collectSettingsFromUi();
  routesState = settings.routes;

  return new Promise((resolve) => {
    chrome.storage.local.get({ sessionDesired: false }, (items) => {
      let sessionDesired = Boolean(items.sessionDesired);
      const mode = settings.mode;
      const enabledComplete = countEnabledCompleteRoutes(settings.routes);

      // All on / enabling routes while already in a session (or preferSession) should reconnect.
      if (preferSession && mode === "routes" && enabledComplete > 0) {
        sessionDesired = true;
        settings.sessionDesired = true;
      }

      if (mode === DEFAULT_MODE) {
        settings.sessionDesired = false;
        sessionDesired = false;
      }

      const wasActive = isUiConnected() || sessionDesired;

      if (wasActive && mode !== DEFAULT_MODE) {
        setStatus("Updating tunnels…");
        setConnectButtonState("starting");
      } else if (announce) {
        setStatus(announce);
      }

      chrome.storage.local.set(settings, async () => {
        const error = chrome.runtime.lastError;

        if (error) {
          setStatus(error.message, true);
          resolve(null);
          return;
        }

        if (!wasActive) {
          if (mode === "routes" && enabledComplete > 0 && announce) {
            setStatus(`${announce} — 請按 On 連線`);
          } else if (announce) {
            setStatus(announce);
          } else if (mode === "routes" && enabledComplete > 0) {
            setStatus("Routes saved — 請按 On 連線");
          } else {
            setStatus("Saved");
          }

          resolve(null);
          return;
        }

        try {
          const response = await sendTunnelMessage("reconcile");
          setConnectButtonState(response.state === "pending" ? "starting" : response.state);
          updateEndpointLabel(response.tunnels);
          renderTunnelDetails(response.tunnels);

          if (response.state === "pending") {
            setStatus("Updating tunnels…");
            setTimeout(() => {
              refreshTunnelStatus().catch((refreshError) => setStatus(refreshError.message, true));
            }, 900);
          } else {
            setStatus(formatTunnelStatus(response), response.state === "error" || !response.ok);
          }

          appendLog(`Route apply: ${formatTunnelStatus(response)}`);
          resolve(response);
        } catch (applyError) {
          setStatus(applyError.message, true);
          resolve(null);
        }
      });
    });
  });
}

function setAllRoutesEnabled(enabled) {
  const current = readRoutesFromDom();

  if (!current.length) {
    setStatus("No routes to update", true);
    return;
  }

  for (const route of current) {
    route.enabled = enabled;
  }

  renderRoutes(current);
  applyRouteSettingsNow({
    announce: enabled ? "All routes enabled" : "All routes disabled",
    preferSession: enabled
  });
}

function saveSettings(showStatus = true) {
  clearTimeout(saveTimer);

  saveTimer = setTimeout(() => {
    const settings = collectSettingsFromUi();
    routesState = settings.routes;

    chrome.storage.local.get({ sessionDesired: false }, (items) => {
      const sessionDesired = Boolean(items.sessionDesired) && settings.mode !== DEFAULT_MODE;
      const wasActive = isUiConnected() || sessionDesired;

      if (wasActive) {
        setStatus(settings.mode === DEFAULT_MODE ? "Disconnecting…" : "Updating tunnels…");
        setConnectButtonState("starting");
      }

      chrome.storage.local.set(settings, () => {
        const error = chrome.runtime.lastError;

        if (error) {
          setStatus(error.message, true);
          return;
        }

        if (showStatus && !wasActive) {
          setStatus("Saved");
        }

        if (wasActive) {
          sendTunnelMessage("reconcile")
            .then((response) => {
              if (response?.state === "pending") {
                setTimeout(() => refreshTunnelStatus(), 900);
                return;
              }

              setConnectButtonState(response.state);
              updateEndpointLabel(response.tunnels);
              renderTunnelDetails(response.tunnels);
              setStatus(formatTunnelStatus(response), response.state === "error" || !response.ok);
            })
            .catch((refreshError) => {
              setStatus(refreshError.message, true);
            });
        }
      });
    });
  }, 120);
}

function sendTunnelMessage(action, timeoutMs = 12000) {
  return new Promise((resolve) => {
    let settled = false;
    // Connect may start multiple tunnels with ProxyCommand; allow long waits.
    const waitMs =
      action === "connect" || action === "reconcile" ? Math.max(timeoutMs, 120000) : timeoutMs;
    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }

      settled = true;
      resolve({
        ok: false,
        state: "error",
        message: "Timed out waiting for background response.",
        tunnels: []
      });
    }, waitMs);

    const settings = collectSettingsFromUi();

    chrome.runtime.sendMessage(
      {
        type: "webhole:tunnel",
        action,
        mode: settings.mode,
        defaultHostAlias: settings.defaultHostAlias,
        hostAlias: settings.defaultHostAlias,
        routes: settings.routes,
        routesFallback: settings.routesFallback
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
            message: error.message,
            tunnels: []
          });
          return;
        }

        resolve(response || { ok: false, state: "error", message: "Empty background response.", tunnels: [] });
      }
    );
  });
}

async function loadHostOptions(selectedHost, routes) {
  const response = await sendTunnelMessage("listHosts");
  availableHosts = Array.isArray(response.hosts) ? response.hosts.slice() : [];

  populateDefaultHostSelect(selectedHost);
  renderRoutes(routes);

  if (!response.ok) {
    setStatus(response.message || "Failed to load SSH hosts", true);
    appendLog(`List hosts failed: ${response.message || "unknown error"}`);
    return response;
  }

  if (availableHosts.length === 0) {
    setStatus("No concrete Host entries in ~/.ssh/config", true);
    appendLog("List hosts: empty");
  } else {
    appendLog(`List hosts: ${availableHosts.length}`);
  }

  return response;
}

function setBusy(isBusy) {
  connectButton.disabled = isBusy;
  disconnectButton.disabled = isBusy;
  addRouteButton.disabled = isBusy;
  enableAllRoutesButton.disabled = isBusy;
  disableAllRoutesButton.disabled = isBusy;
}

function setConnectButtonState(state) {
  connectButton.classList.remove("is-connected", "is-disconnected", "is-pending");

  if (state === "connected" || state === "partial") {
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

function updateEndpointLabel(tunnels) {
  const list = Array.isArray(tunnels) ? tunnels.filter((item) => item && item.port) : [];

  if (!list.length) {
    endpointLabel.textContent = "SOCKS5 127.0.0.1:1080+";
    return;
  }

  const ports = [...new Set(list.map((item) => item.port))].sort((a, b) => a - b);
  endpointLabel.textContent =
    ports.length === 1
      ? `SOCKS5 127.0.0.1:${ports[0]}`
      : `SOCKS5 127.0.0.1:{${ports.join(",")}}`;
}

function renderTunnelDetails(tunnels) {
  const list = Array.isArray(tunnels) ? tunnels : [];

  if (!list.length) {
    tunnelDetailsEl.replaceChildren();
    return;
  }

  tunnelDetailsEl.replaceChildren(
    ...list.map((tunnel) => {
      const line = document.createElement("div");
      const hostAlias = tunnel.hostAlias || "(unknown)";
      const port = tunnel.port ? `127.0.0.1:${tunnel.port}` : "no-port";
      const state = tunnel.state || "unknown";
      const ok = state === "connected" || state === "starting";

      line.className = `tunnel-line ${ok ? "is-ok" : "is-error"}`;
      line.textContent = ok
        ? `${hostAlias} → SOCKS5 ${port} (${state})`
        : `${hostAlias} → ${state}${tunnel.message ? `: ${tunnel.message}` : ""}`;
      return line;
    })
  );
}

function formatTunnelStatus(response) {
  if (!response) {
    return "Tunnel error";
  }

  if (!response.ok && response.state === "error") {
    return response.message || "Tunnel error";
  }

  if (response.state === "pending") {
    return response.message || "Updating tunnels…";
  }

  const tunnels = Array.isArray(response.tunnels) ? response.tunnels : [];
  const connected = tunnels.filter((item) => item.state === "connected" || item.state === "starting");
  const errors = tunnels.filter((item) => item.state === "error");

  if (response.state === "connected" && connected.length) {
    const detail = connected.map((item) => `${item.hostAlias}:${item.port}`).join(", ");
    return `Connected (${connected.length}): ${detail}`;
  }

  if (response.state === "partial") {
    const detail = connected.map((item) => `${item.hostAlias}:${item.port}`).join(", ");
    const err = errors.map((item) => item.message || item.hostAlias).join("; ");
    return `Partial (${connected.length}): ${detail}${err ? ` · ${err}` : ""}`;
  }

  if (response.state === "starting") {
    return "Tunnels starting…";
  }

  if (response.state === "disconnected" && response.message) {
    return response.message;
  }

  if (response.message && response.state !== "disconnected") {
    return response.message;
  }

  return "Tunnels disconnected";
}

async function refreshTunnelStatus() {
  try {
    const response = await sendTunnelMessage("status");
    setConnectButtonState(response.state);
    updateEndpointLabel(response.tunnels);
    renderTunnelDetails(response.tunnels);
    setStatus(formatTunnelStatus(response), response.state === "error" || !response.ok);
    appendLog(`Status: ${formatTunnelStatus(response)}`);
  } catch (error) {
    setConnectButtonState("error");
    renderTunnelDetails([]);
    setStatus(error.message, true);
    appendLog(`Status failed: ${error.message}`);
  }
}

async function connectTunnel() {
  const mode = getSelectedMode();
  const settings = collectSettingsFromUi();

  if (mode === DEFAULT_MODE) {
    setSelectedMode("global");
  }

  const activeMode = getSelectedMode();

  if (activeMode === "global") {
    if (!settings.defaultHostAlias) {
      setStatus("請選擇 Default SSH Host", true);
      return;
    }

    if (!isValidHostAlias(settings.defaultHostAlias)) {
      setStatus("Invalid SSH Host alias", true);
      return;
    }
  }

  if (activeMode === "routes") {
    const completeRoutes = normalizeRoutes(settings.routes, { allowIncomplete: false });
    const enabledComplete = completeRoutes.filter((route) => route.enabled);
    const routesFallback = normalizeRoutesFallback(settings.routesFallback);

    if (!completeRoutes.length) {
      setStatus("請至少新增一條有效 Route（host 或 host/path + SSH Host）", true);
      return;
    }

    if (!enabledComplete.length) {
      setStatus("請至少啟用一條 Route", true);
      return;
    }

    if (routesFallback === "default") {
      if (!settings.defaultHostAlias) {
        setStatus("未匹配走 Default 時，請選擇 Default SSH Host", true);
        return;
      }

      if (!isValidHostAlias(settings.defaultHostAlias)) {
        setStatus("Invalid SSH Host alias", true);
        return;
      }
    }

    // Persist complete routes (keep disabled ones).
    settings.routes = completeRoutes;
    routesState = completeRoutes;
    renderRoutes(completeRoutes);
  }

  setBusy(true);
  setStatus("Connecting...");
  setConnectButtonState("starting");
  appendLog(`Connect requested (${activeMode})`);

  try {
    saveSettings(false);

    const response = await sendTunnelMessage("connect");
    setConnectButtonState(response.state);
    updateEndpointLabel(response.tunnels);
    renderTunnelDetails(response.tunnels);
    setStatus(formatTunnelStatus(response), response.state === "error" || !response.ok);
    appendLog(`Connect result: ${formatTunnelStatus(response)}`);
  } catch (error) {
    setConnectButtonState("error");
    renderTunnelDetails([]);
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
    updateEndpointLabel(response.tunnels);
    renderTunnelDetails(response.tunnels);
    setStatus(formatTunnelStatus(response), response.state === "error" || !response.ok);
    appendLog(`Disconnect result: ${formatTunnelStatus(response)}`);
  } catch (error) {
    setConnectButtonState("error");
    renderTunnelDetails([]);
    setStatus(error.message, true);
    appendLog(`Disconnect failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

function migrateLoadedSettings(items) {
  const mode = normalizeMode(items.mode);
  const defaultHostAlias = normalizeHostAlias(items.defaultHostAlias || items.hostAlias || "");
  const routesFallback = normalizeRoutesFallback(items.routesFallback);
  let routes = normalizeRoutes(items.routes, { allowIncomplete: true });

  if (!routes.length && Array.isArray(items.domains) && items.domains.length && defaultHostAlias) {
    routes = normalizeRoutes(
      items.domains.map((domain) => ({
        pattern: domain,
        hostAlias: defaultHostAlias,
        enabled: true
      })),
      { allowIncomplete: true }
    );
  }

  return { mode, defaultHostAlias, routes, routesFallback };
}

function bootPopup() {
  chrome.storage.local.get(
    {
      mode: DEFAULT_MODE,
      domains: [],
      hostAlias: "",
      defaultHostAlias: "",
      routes: [],
      routesFallback: DEFAULT_ROUTES_FALLBACK,
      logs: []
    },
    async (items) => {
      try {
        const error = chrome.runtime.lastError;

        if (error) {
          setStatus(error.message, true);
          return;
        }

        const migrated = migrateLoadedSettings(items || {});

        setRoutesFallback(migrated.routesFallback);
        setSelectedMode(migrated.mode);
        setConnectButtonState("disconnected");
        routesState = migrated.routes;
        renderLogs(items?.logs);

        await refreshTunnelStatus();

        try {
          await loadHostOptions(migrated.defaultHostAlias, migrated.routes);
        } catch (listError) {
          availableHosts = [];
          populateDefaultHostSelect(migrated.defaultHostAlias);
          renderRoutes(migrated.routes);
          setStatus(listError.message, true);
          appendLog(`List hosts failed: ${listError.message}`);
        }
      } catch (bootError) {
        setStatus(bootError instanceof Error ? bootError.message : String(bootError), true);
        appendLog(`Popup boot failed: ${bootError instanceof Error ? bootError.message : String(bootError)}`);
      }
    }
  );
}

// Defer native/SW work so the action popup paints before any messaging.
requestAnimationFrame(() => {
  setTimeout(bootPopup, 0);
});

for (const input of modeInputs) {
  input.addEventListener("change", () => {
    setSelectedMode(input.value);
    saveSettings();
  });
}

for (const input of routesFallbackInputs) {
  input.addEventListener("change", () => {
    updateDefaultHostUi();
    saveSettings();
  });
}

defaultHostSelect?.addEventListener("change", saveSettings);
addRouteButton?.addEventListener("click", addRoute);
enableAllRoutesButton?.addEventListener("click", () => setAllRoutesEnabled(true));
disableAllRoutesButton?.addEventListener("click", () => setAllRoutesEnabled(false));
connectButton?.addEventListener("click", connectTunnel);
disconnectButton?.addEventListener("click", disconnectTunnel);

helpToggle?.addEventListener("click", () => {
  helpSection?.classList.toggle("is-open");
});

logToggle?.addEventListener("click", () => {
  logSection?.classList.toggle("is-open");
});

clearLogButton?.addEventListener("click", () => {
  chrome.storage.local.set({ logs: [] }, () => {
    renderLogs([]);
    setStatus("Log cleared");
  });
});

openWindowButton?.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "webhole:openWindow" }, (response) => {
    const error = chrome.runtime.lastError;

    if (error) {
      setStatus(error.message, true);
      return;
    }

    if (!response?.ok) {
      setStatus(response?.message || "Failed to open window", true);
      return;
    }

    // Close the flaky action popup if we successfully opened a real window.
    if (popupOpenSource === "action") {
      window.close();
    }
  });
});

// Hide the "open window" control when already in a window popup.
if (popupOpenSource === "window" && openWindowButton) {
  openWindowButton.hidden = true;
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.logs) {
    renderLogs(changes.logs.newValue);
  }
});
