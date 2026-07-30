const DEFAULT_MODE = "direct";
const LOG_LIMIT = 80;
const NATIVE_HOST = "com.webhole.host";
const PROXY_HOST = "127.0.0.1";
const MAX_ROUTES = 50;
const MAX_DNS_RULES = 50;
const HOST_ALIAS_RE = /^[A-Za-z0-9._-]+$/;
const DOMAIN_PATTERN_RE = /^[a-z0-9._-]+$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const VALID_MODES = new Set(["direct", "global", "routes"]);
const VALID_ROUTES_FALLBACKS = new Set(["direct", "default"]);
const VALID_DNS_KINDS = new Set(["direct", "via_ssh"]);
const DEFAULT_ROUTES_FALLBACK = "direct";
const DEFAULT_DNS_LISTEN_PORT = 53535;
const DEFAULT_DNS_NAMESERVER = "1.1.1.1";
const DEFAULT_GATEWAY_PORT = 18080;
const POPUP_PATH = "popup.html";

/** Remember Chrome secure DNS mode so we can restore on DNS Off. */
let previousSecureDnsMode = null;
let lastGatewayPort = null;
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

// Allow single-label hosts like "intranet" as well as FQDNs.
function isValidHostPattern(hostPattern) {
  return Boolean(hostPattern) && DOMAIN_PATTERN_RE.test(hostPattern);
}

function createRouteId() {
  return `r_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeRoutes(routes) {
  const values = Array.isArray(routes) ? routes : [];
  const seen = new Set();
  const result = [];

  for (const route of values) {
    if (!route || typeof route !== "object") {
      continue;
    }

    const parsed = parseRoutePattern(route.pattern);
    const hostAlias = normalizeHostAlias(route.hostAlias);

    if (!isValidHostPattern(parsed.hostPattern) || !isValidHostAlias(hostAlias)) {
      continue;
    }

    const key = `${parsed.hostPattern}\0${parsed.pathPrefix}\0${hostAlias}`;

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
      // Missing field (legacy) defaults to enabled.
      enabled: route.enabled !== false
    });

    if (result.length >= MAX_ROUTES) {
      break;
    }
  }

  // Longer path first, then longer host (specificity).
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

function enabledRoutes(routes) {
  return normalizeRoutes(routes).filter((route) => route.enabled);
}

function isValidIpv4(value) {
  if (!IPV4_RE.test(String(value || ""))) {
    return false;
  }

  return String(value)
    .split(".")
    .every((part) => {
      const n = Number(part);
      return n >= 0 && n <= 255;
    });
}

function createDnsRuleId() {
  return `d_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeDnsDomain(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

function normalizeDnsRules(rules) {
  const values = Array.isArray(rules) ? rules : [];
  const seen = new Set();
  const result = [];

  for (const rule of values) {
    if (!rule || typeof rule !== "object") {
      continue;
    }

    const domain = normalizeDnsDomain(rule.domain);
    const kind = VALID_DNS_KINDS.has(rule.kind) ? rule.kind : "direct";
    const nameserver = String(rule.nameserver || "").trim();
    const nameserverPort = Number(rule.nameserverPort) || 53;
    const hostAlias = normalizeHostAlias(rule.hostAlias);
    const enabled = rule.enabled !== false;

    if (!domain || !DOMAIN_PATTERN_RE.test(domain) || !isValidIpv4(nameserver)) {
      // Keep incomplete rows only if they have an id (UI drafting) — drop for native payload later.
      if (!rule.id) {
        continue;
      }
    }

    if (kind === "via_ssh" && hostAlias && !isValidHostAlias(hostAlias)) {
      continue;
    }

    if (!Number.isInteger(nameserverPort) || nameserverPort < 1 || nameserverPort > 65535) {
      continue;
    }

    const key = `${rule.id || ""}\0${domain}\0${kind}\0${nameserver}\0${nameserverPort}\0${hostAlias}`;

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push({
      id: String(rule.id || createDnsRuleId()),
      domain,
      kind,
      nameserver,
      nameserverPort,
      hostAlias: kind === "via_ssh" ? hostAlias : "",
      enabled
    });

    if (result.length >= MAX_DNS_RULES) {
      break;
    }
  }

  result.sort((a, b) => (b.domain || "").length - (a.domain || "").length);
  return result;
}

function enabledDnsRules(rules) {
  return normalizeDnsRules(rules).filter(
    (rule) =>
      rule.enabled &&
      rule.domain &&
      DOMAIN_PATTERN_RE.test(rule.domain) &&
      isValidIpv4(rule.nameserver) &&
      (rule.kind !== "via_ssh" || isValidHostAlias(rule.hostAlias))
  );
}

function normalizeDnsListenPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : DEFAULT_DNS_LISTEN_PORT;
}

function migrateSettings(items) {
  const mode = normalizeMode(items.mode);
  const defaultHostAlias = normalizeHostAlias(items.defaultHostAlias || items.hostAlias || "");
  let routes = normalizeRoutes(items.routes);

  if (!routes.length && Array.isArray(items.domains) && items.domains.length && defaultHostAlias) {
    routes = normalizeRoutes(
      items.domains.map((domain) => ({
        pattern: domain,
        hostAlias: defaultHostAlias,
        enabled: true
      }))
    );
  }

  const defaultNameserver = isValidIpv4(items.dnsDefaultNameserver)
    ? String(items.dnsDefaultNameserver).trim()
    : DEFAULT_DNS_NAMESERVER;
  const defaultNameserverPort = Number(items.dnsDefaultNameserverPort) || 53;

  return {
    mode,
    defaultHostAlias,
    routes,
    hostAlias: defaultHostAlias,
    sessionDesired: Boolean(items.sessionDesired),
    routesFallback: normalizeRoutesFallback(items.routesFallback),
    dnsEnabled: Boolean(items.dnsEnabled),
    sessionDesiredDns: Boolean(items.sessionDesiredDns),
    dnsListenPort: normalizeDnsListenPort(items.dnsListenPort),
    dnsDefaultNameserver: defaultNameserver,
    dnsDefaultNameserverPort:
      Number.isInteger(defaultNameserverPort) && defaultNameserverPort >= 1 && defaultNameserverPort <= 65535
        ? defaultNameserverPort
        : 53,
    dnsRules: normalizeDnsRules(items.dnsRules),
    dnsInstallResolverStubs: Boolean(items.dnsInstallResolverStubs),
    // Enforce is the product default (scheme D).
    dnsEnforce: items.dnsEnforce !== false
  };
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

function ensureActionPopup() {
  chrome.action.setPopup({ popup: POPUP_PATH }, () => {
    const error = chrome.runtime.lastError;

    if (error) {
      console.error(`Webhole popup binding failed: ${error.message}`);
      appendLog(`Popup binding failed: ${error.message}`);
    }
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

function tunnelMapFromResponse(response) {
  const map = {};
  const tunnels = Array.isArray(response?.tunnels) ? response.tunnels : [];

  for (const tunnel of tunnels) {
    if (!tunnel || tunnel.state === "error") {
      continue;
    }

    const hostAlias = normalizeHostAlias(tunnel.hostAlias);
    const port = Number(tunnel.port);

    if (!isValidHostAlias(hostAlias) || !Number.isInteger(port) || port <= 0) {
      continue;
    }

    map[hostAlias] = port;
  }

  return map;
}

function createPacScript(routes, tunnelMap, fallbackPort, options = {}) {
  const gatewayPort = Number(options.gatewayPort) || 0;
  const useGateway = Boolean(options.useGateway) && gatewayPort > 0;
  const globalViaGateway = Boolean(options.globalViaGateway) && useGateway;

  const rules = routes
    .map((route) => {
      const parsed =
        route.hostPattern != null
          ? {
              hostPattern: route.hostPattern,
              pathPrefix: route.pathPrefix || ""
            }
          : parseRoutePattern(route.pattern);

      return {
        hostPattern: parsed.hostPattern,
        pathPrefix: parsed.pathPrefix || "",
        port: tunnelMap[route.hostAlias]
      };
    })
    .filter((rule) => rule.hostPattern && Number.isInteger(rule.port));

  const fallback =
    useGateway && Number.isInteger(fallbackPort) && fallbackPort > 0
      ? `"PROXY ${PROXY_HOST}:${gatewayPort}"`
      : Number.isInteger(fallbackPort) && fallbackPort > 0
        ? `"SOCKS5 ${PROXY_HOST}:${fallbackPort}"`
        : '"DIRECT"';

  if (globalViaGateway) {
    return `
function FindProxyForURL(url, host) {
  return "PROXY ${PROXY_HOST}:${gatewayPort}";
}
`;
  }

  const matchedReturn = useGateway
    ? `"PROXY ${PROXY_HOST}:${gatewayPort}"`
    : `"SOCKS5 ${PROXY_HOST}:" + rule.port`;

  return `
var WEBHOLE_RULES = ${JSON.stringify(rules)};

function webholePathFromUrl(url) {
  var s = String(url || "");
  var scheme = s.indexOf("://");
  var start = -1;

  if (scheme !== -1) {
    start = s.indexOf("/", scheme + 3);
  } else {
    start = s.indexOf("/");
  }

  if (start === -1) {
    return "/";
  }

  var path = s.slice(start);
  var q = path.indexOf("?");
  if (q !== -1) {
    path = path.slice(0, q);
  }
  var hash = path.indexOf("#");
  if (hash !== -1) {
    path = path.slice(0, hash);
  }

  return path || "/";
}

function webholeHostMatches(host, pattern) {
  var normalizedHost = String(host).toLowerCase();
  var domain = String(pattern).toLowerCase();
  var suffix = "." + domain;

  return (
    normalizedHost === domain ||
    normalizedHost.slice(-suffix.length) === suffix
  );
}

function webholePathMatches(path, prefix) {
  if (!prefix) {
    return true;
  }

  if (path === prefix) {
    return true;
  }

  return path.slice(0, prefix.length + 1) === prefix + "/";
}

function FindProxyForURL(url, host) {
  var path = webholePathFromUrl(url);

  for (var i = 0; i < WEBHOLE_RULES.length; i += 1) {
    var rule = WEBHOLE_RULES[i];

    if (!webholeHostMatches(host, rule.hostPattern)) {
      continue;
    }

    if (!webholePathMatches(path, rule.pathPrefix)) {
      continue;
    }

    return ${matchedReturn};
  }

  return ${fallback};
}
`;
}

function setRoutesProxy(routes, tunnelMap, fallbackPort, options = {}) {
  chrome.proxy.settings.set(
    {
      scope: "regular",
      value: {
        mode: "pac_script",
        pacScript: {
          data: createPacScript(routes, tunnelMap, fallbackPort, options)
        }
      }
    },
    () => logProxyResult(options.useGateway ? "set routes+gateway" : "set routes")
  );
}

function setGlobalProxy(port, options = {}) {
  const gatewayPort = Number(options.gatewayPort) || 0;

  if (options.useGateway && gatewayPort > 0) {
    chrome.proxy.settings.set(
      {
        scope: "regular",
        value: {
          mode: "pac_script",
          pacScript: {
            data: createPacScript([], {}, port, {
              useGateway: true,
              gatewayPort,
              globalViaGateway: true
            })
          }
        }
      },
      () => logProxyResult("set global+gateway")
    );
    return;
  }

  chrome.proxy.settings.set(
    {
      scope: "regular",
      value: {
        mode: "fixed_servers",
        rules: {
          singleProxy: {
            scheme: "socks5",
            host: PROXY_HOST,
            port
          }
        }
      }
    },
    () => logProxyResult("set global")
  );
}

async function ensureGatewayForProxy(mode, settings, tunnelMap) {
  const enforce =
    settings.dnsEnforce !== false &&
    Boolean(settings.dnsEnabled) &&
    Boolean(settings.sessionDesiredDns);
  const normalizedMode = normalizeMode(mode);

  if (!enforce || normalizedMode === "direct") {
    await sendNativeMessage({ action: "gatewayStop" });
    lastGatewayPort = null;
    return { useGateway: false, gatewayPort: null };
  }

  const dnsStatus = await sendNativeMessage({ action: "dnsStatus" });

  if (dnsStatus?.state !== "running" || !dnsStatus.dns?.port) {
    await sendNativeMessage({ action: "gatewayStop" });
    lastGatewayPort = null;
    return { useGateway: false, gatewayPort: null, reason: "dns not running" };
  }

  const map = tunnelMap || {};
  const routes = enabledRoutes(settings.routes);
  const defaultHostAlias = normalizeHostAlias(settings.defaultHostAlias || settings.hostAlias);
  const routesFallback = normalizeRoutesFallback(settings.routesFallback);

  const gatewayRules = routes
    .filter((route) => Number.isInteger(map[route.hostAlias]))
    .map((route) => ({
      hostPattern: route.hostPattern,
      pathPrefix: route.pathPrefix || "",
      socksPort: map[route.hostAlias]
    }));

  let fallbackSocksPort = 0;

  if (normalizedMode === "global") {
    fallbackSocksPort = map[defaultHostAlias] || 0;
  } else if (routesFallback === "default") {
    fallbackSocksPort = map[defaultHostAlias] || 0;
  }

  if (normalizedMode === "global" && !fallbackSocksPort) {
    return { useGateway: false, gatewayPort: null, reason: "no global socks" };
  }

  if (normalizedMode === "routes" && !gatewayRules.length && !fallbackSocksPort) {
    return { useGateway: false, gatewayPort: null, reason: "no route socks" };
  }

  const response = await sendNativeMessage({
    action: "gatewayStart",
    listenPort: DEFAULT_GATEWAY_PORT,
    dnsPort: dnsStatus.dns.port,
    mode: normalizedMode === "global" ? "global" : "routes",
    rules: gatewayRules,
    fallbackSocksPort
  });

  if (!response?.ok || !response.gateway?.port) {
    appendLog(`Gateway start failed: ${response?.message || "unknown"}`);
    lastGatewayPort = null;
    return { useGateway: false, gatewayPort: null, reason: response?.message || "gateway failed" };
  }

  lastGatewayPort = response.gateway.port;
  appendLog(`Gateway ready on ${PROXY_HOST}:${lastGatewayPort}`);
  return { useGateway: true, gatewayPort: lastGatewayPort };
}

async function applyProxy(mode, settings, tunnelMap) {
  const normalizedMode = normalizeMode(mode);
  const routes = enabledRoutes(settings.routes);
  const defaultHostAlias = normalizeHostAlias(settings.defaultHostAlias || settings.hostAlias);
  const routesFallback = normalizeRoutesFallback(settings.routesFallback);
  const map = tunnelMap || {};
  const gatewayInfo = await ensureGatewayForProxy(normalizedMode, settings, map);

  if (normalizedMode === "global") {
    const port = map[defaultHostAlias];

    if (!Number.isInteger(port)) {
      clearProxy();
      return;
    }

    setGlobalProxy(port, gatewayInfo);
    return;
  }

  if (normalizedMode === "routes") {
    if (!routes.length || !Object.keys(map).length) {
      appendLog(
        `Proxy routes skipped: enabledRoutes=${routes.length} tunnelMap=${Object.keys(map).join(",") || "(empty)"}`
      );
      clearProxy();
      return;
    }

    const rulesWithPort = routes.filter((route) => Number.isInteger(map[route.hostAlias]));
    const fallbackPort =
      routesFallback === "default" && Number.isInteger(map[defaultHostAlias])
        ? map[defaultHostAlias]
        : null;
    appendLog(
      `Proxy routes apply: ${rulesWithPort.length}/${routes.length} rules, fallback=${
        fallbackPort ? `default:${fallbackPort}` : "direct"
      }, gateway=${gatewayInfo.useGateway ? gatewayInfo.gatewayPort : "off"}, hosts=${Object.keys(map).join(",")}`
    );
    setRoutesProxy(routes, map, fallbackPort, gatewayInfo);
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
        hostAlias: "",
        defaultHostAlias: "",
        routes: [],
        sessionDesired: false,
        routesFallback: DEFAULT_ROUTES_FALLBACK,
        dnsEnabled: false,
        sessionDesiredDns: false,
        dnsListenPort: DEFAULT_DNS_LISTEN_PORT,
        dnsDefaultNameserver: DEFAULT_DNS_NAMESERVER,
        dnsDefaultNameserverPort: 53,
        dnsRules: [],
        dnsInstallResolverStubs: false,
        dnsEnforce: true
      },
      (items) => {
        const error = chrome.runtime.lastError;

        if (error) {
          console.error(`Webhole settings load failed: ${error.message}`);
          resolve(
            migrateSettings({
              mode: DEFAULT_MODE,
              defaultHostAlias: "",
              routes: [],
              hostAlias: "",
              sessionDesired: false,
              routesFallback: DEFAULT_ROUTES_FALLBACK
            })
          );
          return;
        }

        resolve(migrateSettings(items));
      }
    );
  });
}

function buildDnsNativePayload(settings) {
  const enforce = settings.dnsEnforce !== false;

  return {
    listenPort: settings.dnsListenPort || DEFAULT_DNS_LISTEN_PORT,
    defaultNameserver: settings.dnsDefaultNameserver || DEFAULT_DNS_NAMESERVER,
    defaultNameserverPort: settings.dnsDefaultNameserverPort || 53,
    rules: enabledDnsRules(settings.dnsRules),
    enforce,
    autoInstallResolver: enforce
  };
}

function setSecureDnsMode(mode) {
  return new Promise((resolve) => {
    if (!chrome.privacy?.network?.secureDNSMode) {
      resolve({ ok: false, message: "chrome.privacy.network.secureDNSMode unavailable" });
      return;
    }

    chrome.privacy.network.secureDNSMode.set({ value: mode }, () => {
      const error = chrome.runtime.lastError;

      if (error) {
        resolve({ ok: false, message: error.message });
        return;
      }

      resolve({ ok: true, mode });
    });
  });
}

function getSecureDnsMode() {
  return new Promise((resolve) => {
    if (!chrome.privacy?.network?.secureDNSMode) {
      resolve({ ok: false, levelOfControl: "not_controllable", value: null });
      return;
    }

    chrome.privacy.network.secureDNSMode.get({}, (details) => {
      const error = chrome.runtime.lastError;

      if (error) {
        resolve({ ok: false, message: error.message, value: null });
        return;
      }

      resolve({
        ok: true,
        value: details?.value ?? null,
        levelOfControl: details?.levelOfControl || ""
      });
    });
  });
}

async function enforceDisableSecureDns() {
  const current = await getSecureDnsMode();

  if (!current.ok) {
    return {
      ok: false,
      message: current.message || "Cannot read Secure DNS setting",
      secureDns: current
    };
  }

  if (previousSecureDnsMode == null && current.value != null) {
    previousSecureDnsMode = current.value;
  }

  if (current.value === "off") {
    return { ok: true, message: "Secure DNS already off", secureDns: current };
  }

  const setResult = await setSecureDnsMode("off");

  if (!setResult.ok) {
    return {
      ok: false,
      message: setResult.message || "Failed to disable Secure DNS (DoH)",
      secureDns: current
    };
  }

  appendLog("Secure DNS (DoH) set to off for DNS Enforce");
  return { ok: true, message: "Secure DNS disabled", secureDns: await getSecureDnsMode() };
}

async function restoreSecureDnsIfNeeded() {
  if (previousSecureDnsMode == null || previousSecureDnsMode === "off") {
    previousSecureDnsMode = null;
    return { ok: true, message: "No Secure DNS restore needed" };
  }

  const result = await setSecureDnsMode(previousSecureDnsMode);
  appendLog(`Secure DNS restored to ${previousSecureDnsMode}: ${result.ok ? "ok" : result.message}`);
  previousSecureDnsMode = null;
  return result;
}

function setDirectMode() {
  return new Promise((resolve) => {
    chrome.storage.local.set({ mode: DEFAULT_MODE, sessionDesired: false }, () => {
      const error = chrome.runtime.lastError;

      if (error) {
        console.error(`Webhole settings save failed: ${error.message}`);
      }

      clearProxy();
      resolve();
    });
  });
}

/** Per-action timeouts so a stuck native host cannot pin the service worker. */
const NATIVE_TIMEOUT_MS = {
  status: 8000,
  listHosts: 8000,
  disconnect: 20000,
  connect: 120000,
  reconcile: 120000,
  dnsStart: 120000,
  dnsStop: 20000,
  dnsStatus: 8000,
  dnsQuery: 15000,
  dnsInstallResolver: 120000,
  dnsUninstallResolver: 120000,
  gatewayStart: 30000,
  gatewayStop: 15000
};

function sendNativeMessage(message) {
  const action = message?.action || "unknown";
  const timeoutMs = NATIVE_TIMEOUT_MS[action] ?? 15000;

  return new Promise((resolve) => {
    let settled = false;

    const finish = (result) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const timer = setTimeout(() => {
      appendLog(`Native ${action} timed out after ${timeoutMs}ms`);
      finish({
        ok: false,
        state: "error",
        message: `Native ${action} timed out after ${timeoutMs}ms.`,
        tunnels: []
      });
    }, timeoutMs);

    try {
      chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
        const error = chrome.runtime.lastError;

        if (error) {
          appendLog(`Native ${action} failed: ${error.message}`);
          finish({
            ok: false,
            state: "error",
            message: error.message,
            tunnels: []
          });
          return;
        }

        const result = response || {
          ok: false,
          state: "error",
          message: "Empty native host response.",
          tunnels: []
        };
        appendLog(`Native ${action}: ${result.state}`);
        finish(result);
      });
    } catch (error) {
      finish({
        ok: false,
        state: "error",
        message: error instanceof Error ? error.message : String(error),
        tunnels: []
      });
    }
  });
}

function hostsNeededForMode(mode, settings) {
  const normalizedMode = normalizeMode(mode);
  const routes = enabledRoutes(settings.routes);
  const defaultHostAlias = normalizeHostAlias(settings.defaultHostAlias || settings.hostAlias);
  const routesFallback = normalizeRoutesFallback(settings.routesFallback);
  const hosts = [];

  if (normalizedMode === "global") {
    if (defaultHostAlias) {
      hosts.push(defaultHostAlias);
    }

    return hosts;
  }

  if (normalizedMode === "routes") {
    const seen = new Set();

    for (const route of routes) {
      if (seen.has(route.hostAlias)) {
        continue;
      }

      seen.add(route.hostAlias);
      hosts.push(route.hostAlias);
    }

    // Optional: unmatched traffic uses Default SSH Host as SOCKS fallback.
    if (routesFallback === "default" && defaultHostAlias && !seen.has(defaultHostAlias)) {
      hosts.push(defaultHostAlias);
    }

    return hosts;
  }

  return hosts;
}

function isTunnelConnected(response) {
  if (!response?.ok) {
    return false;
  }

  return response.state === "connected" || response.state === "partial" || response.state === "starting";
}

function activeHostAliases(response) {
  const tunnels = Array.isArray(response?.tunnels) ? response.tunnels : [];

  return tunnels
    .filter((tunnel) => tunnel && (tunnel.state === "connected" || tunnel.state === "starting"))
    .map((tunnel) => normalizeHostAlias(tunnel.hostAlias))
    .filter(Boolean);
}

function sameHostSet(left, right) {
  if (left.length !== right.length) {
    return false;
  }

  const a = left.slice().sort();
  const b = right.slice().sort();

  return a.every((value, index) => value === b[index]);
}

let reconcileTimer = 0;
let reconcileInFlight = false;
let suppressReconcileDepth = 0;
let pendingReconcile = false;

function beginSuppressReconcile() {
  suppressReconcileDepth += 1;
}

function endSuppressReconcile() {
  // Let storage.onChanged from our own writes settle before re-enabling.
  setTimeout(() => {
    suppressReconcileDepth = Math.max(0, suppressReconcileDepth - 1);

    if (suppressReconcileDepth === 0 && pendingReconcile) {
      pendingReconcile = false;
      scheduleReconcileSession();
    }
  }, 400);
}

async function runSuppressed(work) {
  beginSuppressReconcile();

  try {
    return await work();
  } finally {
    endSuppressReconcile();
  }
}

async function syncTunnelAndProxy() {
  const response = await sendNativeMessage({ action: "status" });
  const settings = await getStoredSettings();
  const tunnelMap = tunnelMapFromResponse(response);

  if (isTunnelConnected(response) && Object.keys(tunnelMap).length) {
    setActionIcon(true);
    await applyProxy(settings.mode, settings, tunnelMap);
    return response;
  }

  setActionIcon(false);
  clearProxy();
  return response;
}

/**
 * Keep tunnels aligned with mode / defaultHost / routes while the user
 * wants a session (sessionDesired) or tunnels are already up.
 * sessionDesired stays true across temporary "no enabled routes" so
 * re-enabling a route reconnects without pressing On again.
 */
async function reconcileSessionFromSettings() {
  if (reconcileInFlight || suppressReconcileDepth > 0) {
    pendingReconcile = true;
    return {
      ok: true,
      state: "pending",
      message: "Reconcile queued.",
      tunnels: []
    };
  }

  reconcileInFlight = true;

  try {
    const settings = await getStoredSettings();
    const mode = normalizeMode(settings.mode);
    const status = await sendNativeMessage({ action: "status" });
    const sessionActive = isTunnelConnected(status);
    let sessionDesired = Boolean(settings.sessionDesired);

    if (mode === "direct") {
      if (sessionActive) {
        appendLog("Background reconcile: mode=direct, disconnecting");
        await runSuppressed(async () => sendNativeMessage({ action: "disconnect" }));
      }

      if (sessionDesired) {
        await runSuppressed(async () => saveSettings({ sessionDesired: false }));
      }

      setActionIcon(false);
      clearProxy();
      return { ok: true, state: "disconnected", tunnels: [] };
    }

    if (!sessionDesired && !sessionActive) {
      setActionIcon(false);
      clearProxy();
      return status;
    }

    const needed = hostsNeededForMode(mode, settings);

    if (!needed.length) {
      if (sessionActive) {
        appendLog("Background reconcile: no enabled hosts/routes, disconnecting tunnels");
        await runSuppressed(async () => sendNativeMessage({ action: "disconnect" }));
      }

      setActionIcon(false);
      clearProxy();
      // Keep sessionDesired so re-enabling routes can auto-reconnect.
      return { ok: true, state: "disconnected", tunnels: [] };
    }

    const current = activeHostAliases(status);
    const tunnelMap = tunnelMapFromResponse(status);
    const hostsAligned =
      sameHostSet(needed, current) && needed.every((hostAlias) => Number.isInteger(tunnelMap[hostAlias]));

    const enabledCount = mode === "routes" ? enabledRoutes(settings.routes).length : needed.length;
    appendLog(
      `Background reconcile: mode=${mode} desired=${sessionDesired} active=${sessionActive} enabled=${enabledCount} needed=${needed.join(",") || "(none)"} current=${current.join(",") || "(none)"}`
    );

    if (hostsAligned) {
      setActionIcon(true);
      await applyProxy(mode, settings, tunnelMap);
      return status;
    }

    appendLog(`Background reconcile connect: ${needed.join(", ")} (${mode})`);

    const response = await runSuppressed(async () =>
      sendNativeMessage({
        action: "connect",
        hostAliases: needed
      })
    );
    const nextMap = tunnelMapFromResponse(response);

    if (isTunnelConnected(response) && Object.keys(nextMap).length) {
      setActionIcon(true);
      await applyProxy(mode, settings, nextMap);
    } else {
      setActionIcon(false);
      clearProxy();
      appendLog(`Background reconcile connect failed: ${response.message || response.state}`);
    }

    return response;
  } finally {
    reconcileInFlight = false;

    if (pendingReconcile && suppressReconcileDepth === 0) {
      pendingReconcile = false;
      scheduleReconcileSession();
    }
  }
}

function scheduleReconcileSession() {
  if (suppressReconcileDepth > 0 || reconcileInFlight) {
    pendingReconcile = true;
    return;
  }

  clearTimeout(reconcileTimer);
  reconcileTimer = setTimeout(() => {
    if (suppressReconcileDepth > 0 || reconcileInFlight) {
      pendingReconcile = true;
      return;
    }

    reconcileSessionFromSettings().catch((error) => {
      console.error(`Webhole reconcile failed: ${error.message}`);
      appendLog(`Reconcile failed: ${error.message}`);
    });
  }, 350);
}

async function handleTunnelMessage(message) {
  const settings = await getStoredSettings();
  const mode = normalizeMode(message.mode || settings.mode);
  const defaultHostAlias = normalizeHostAlias(
    message.defaultHostAlias || message.hostAlias || settings.defaultHostAlias || settings.hostAlias
  );
  const routes = normalizeRoutes(message.routes || settings.routes);
  const routesFallback = normalizeRoutesFallback(
    message.routesFallback != null ? message.routesFallback : settings.routesFallback
  );

  if (message.action === "status") {
    return sendNativeMessage({ action: "status" });
  }

  if (message.action === "listHosts") {
    return sendNativeMessage({ action: "listHosts" });
  }

  if (message.action === "reconcile") {
    // Explicit UI request (All on / enable toggle) — do not drop under debounce alone.
    clearTimeout(reconcileTimer);
    return reconcileSessionFromSettings();
  }

  if (message.action === "connect") {
    const nextSettings = {
      mode,
      defaultHostAlias,
      routes,
      hostAlias: defaultHostAlias,
      routesFallback
    };
    const hostAliases = hostsNeededForMode(mode, nextSettings);

    appendLog(`Background connect: ${hostAliases.join(", ") || "(no hosts)"} (${mode})`);

    if (mode === "routes" && routesFallback === "default" && !defaultHostAlias) {
      return {
        ok: false,
        state: "error",
        message: "Select Default SSH Host when unmatched traffic uses Default.",
        tunnels: []
      };
    }

    if (!hostAliases.length) {
      return {
        ok: false,
        state: "error",
        message:
          mode === "routes"
            ? "Enable at least one complete route (pattern + SSH Host)."
            : "Select a default SSH Host for Global mode.",
        tunnels: []
      };
    }

    return runSuppressed(async () => {
      const response = await sendNativeMessage({
        action: "connect",
        hostAliases
      });
      const tunnelMap = tunnelMapFromResponse(response);

      if (isTunnelConnected(response) && Object.keys(tunnelMap).length) {
        setActionIcon(true);
        await saveSettings({
          ...nextSettings,
          sessionDesired: true
        });
        await applyProxy(mode, nextSettings, tunnelMap);
      } else {
        setActionIcon(false);
      }

      return response;
    });
  }

  if (message.action === "disconnect") {
    appendLog("Background disconnect");

    return runSuppressed(async () => {
      await sendNativeMessage({ action: "gatewayStop" });
      const response = await sendNativeMessage({ action: "disconnect" });

      setActionIcon(false);
      await setDirectMode();

      return response;
    });
  }

  return {
    ok: false,
    state: "error",
    message: "Unknown tunnel action."
  };
}

/** Independent popup window (survives Chrome action-popup focus bugs). */
let webholeWindowId = null;

let dnsReconcileTimer = 0;
let dnsReconcileInFlight = false;
let pendingDnsReconcile = false;

async function reconcileDnsSessionFromSettings() {
  if (dnsReconcileInFlight) {
    pendingDnsReconcile = true;
    return sendNativeMessage({ action: "dnsStatus" });
  }

  dnsReconcileInFlight = true;

  try {
    const settings = await getStoredSettings();
    const desired = Boolean(settings.sessionDesiredDns) && Boolean(settings.dnsEnabled);

    if (!desired) {
      const status = await sendNativeMessage({ action: "dnsStatus" });

      if (status?.state === "running") {
        appendLog("Background DNS reconcile: stopping");
        await sendNativeMessage({ action: "gatewayStop" });
        const stopped = await sendNativeMessage({ action: "dnsStop" });
        await restoreSecureDnsIfNeeded();
        // Re-apply proxy without gateway if tunnels still up.
        await syncTunnelAndProxy();
        return stopped;
      }

      return status || { ok: true, state: "stopped", dns: null };
    }

    const payload = buildDnsNativePayload(settings);
    appendLog(
      `Background DNS reconcile start: port=${payload.listenPort} rules=${payload.rules.length} enforce=${payload.enforce}`
    );

    const response = await sendNativeMessage({
      action: "dnsStart",
      ...payload
    });

    let secureDns = { ok: true };

    if (response?.ok && payload.enforce) {
      secureDns = await enforceDisableSecureDns();
      if (!secureDns.ok) {
        appendLog(`DNS Enforce warning: ${secureDns.message}`);
      }
    }

    if (response?.ok) {
      appendLog(response.message || "DNS started");
      // Tunnel PAC may need gateway now that DNS is up.
      await syncTunnelAndProxy();
    } else {
      appendLog(`DNS start failed: ${response?.message || "unknown"}`);
    }

    return {
      ...response,
      secureDns,
      enforce: payload.enforce
    };
  } finally {
    dnsReconcileInFlight = false;

    if (pendingDnsReconcile) {
      pendingDnsReconcile = false;
      setTimeout(() => {
        reconcileDnsSessionFromSettings().catch((error) => {
          appendLog(`DNS reconcile failed: ${error.message}`);
        });
      }, 0);
    }
  }
}

function scheduleReconcileDnsSession() {
  if (dnsReconcileInFlight) {
    pendingDnsReconcile = true;
    return;
  }

  clearTimeout(dnsReconcileTimer);
  dnsReconcileTimer = setTimeout(() => {
    reconcileDnsSessionFromSettings().catch((error) => {
      console.error(`Webhole DNS reconcile failed: ${error.message}`);
      appendLog(`DNS reconcile failed: ${error.message}`);
    });
  }, 350);
}

async function handleDnsMessage(message) {
  const settings = await getStoredSettings();
  const next = {
    ...settings,
    dnsEnabled: message.dnsEnabled != null ? Boolean(message.dnsEnabled) : settings.dnsEnabled,
    sessionDesiredDns:
      message.sessionDesiredDns != null ? Boolean(message.sessionDesiredDns) : settings.sessionDesiredDns,
    dnsListenPort:
      message.dnsListenPort != null ? normalizeDnsListenPort(message.dnsListenPort) : settings.dnsListenPort,
    dnsDefaultNameserver:
      message.dnsDefaultNameserver != null
        ? isValidIpv4(message.dnsDefaultNameserver)
          ? String(message.dnsDefaultNameserver).trim()
          : settings.dnsDefaultNameserver
        : settings.dnsDefaultNameserver,
    dnsDefaultNameserverPort:
      message.dnsDefaultNameserverPort != null
        ? Number(message.dnsDefaultNameserverPort) || settings.dnsDefaultNameserverPort
        : settings.dnsDefaultNameserverPort,
    dnsRules: message.dnsRules != null ? normalizeDnsRules(message.dnsRules) : settings.dnsRules,
    dnsInstallResolverStubs:
      message.dnsInstallResolverStubs != null
        ? Boolean(message.dnsInstallResolverStubs)
        : settings.dnsInstallResolverStubs
  };

  if (message.action === "dnsStatus") {
    return sendNativeMessage({ action: "dnsStatus" });
  }

  if (message.action === "dnsReconcile") {
    clearTimeout(dnsReconcileTimer);
    return reconcileDnsSessionFromSettings();
  }

  if (message.action === "dnsStart") {
    const enforce = message.dnsEnforce != null ? Boolean(message.dnsEnforce) : next.dnsEnforce !== false;

    await saveSettings({
      dnsEnabled: true,
      sessionDesiredDns: true,
      dnsListenPort: next.dnsListenPort,
      dnsDefaultNameserver: next.dnsDefaultNameserver,
      dnsDefaultNameserverPort: next.dnsDefaultNameserverPort,
      dnsRules: next.dnsRules,
      dnsEnforce: enforce
    });

    const payload = buildDnsNativePayload({
      ...next,
      dnsEnabled: true,
      dnsEnforce: enforce
    });

    appendLog(`Background DNS On: rules=${payload.rules.length} enforce=${enforce}`);
    const response = await sendNativeMessage({ action: "dnsStart", ...payload });
    let secureDns = { ok: true };

    if (response?.ok && enforce) {
      secureDns = await enforceDisableSecureDns();
    }

    if (response?.ok) {
      await syncTunnelAndProxy();
    }

    return {
      ...response,
      secureDns,
      enforce,
      enforceWarnings: [
        !response?.ok ? response?.message : "",
        response?.ok && !response?.dns?.resolverInstalled && payload.rules.length
          ? response?.dns?.resolverMessage || "resolver not installed"
          : "",
        secureDns.ok ? "" : secureDns.message
      ].filter(Boolean)
    };
  }

  if (message.action === "dnsStop") {
    await saveSettings({ sessionDesiredDns: false, dnsEnabled: false });
    appendLog("Background DNS Off");
    await sendNativeMessage({ action: "gatewayStop" });
    const response = await sendNativeMessage({ action: "dnsStop" });
    await restoreSecureDnsIfNeeded();
    await syncTunnelAndProxy();
    return response;
  }

  if (message.action === "dnsEnforceStatus") {
    const dnsStatus = await sendNativeMessage({ action: "dnsStatus" });
    const secureDns = await getSecureDnsMode();
    // Prefer live flag from native state; fall back to settings preference.
    const resolverInstalled =
      dnsStatus?.dns?.resolverInstalled != null
        ? Boolean(dnsStatus.dns.resolverInstalled)
        : Boolean(next.dnsInstallResolverStubs);

    return {
      ok: true,
      enforce: next.dnsEnforce !== false,
      dns: dnsStatus?.dns
        ? { ...dnsStatus.dns, resolverInstalled }
        : null,
      dnsState: dnsStatus?.state || "stopped",
      secureDns,
      gateway: dnsStatus?.dns?.gateway || null,
      resolverInstalled
    };
  }

  if (message.action === "dnsQuery") {
    return sendNativeMessage({
      action: "dnsQuery",
      name: message.name,
      type: message.type || "A"
    });
  }

  if (message.action === "dnsInstallResolver") {
    const payload = buildDnsNativePayload(next);
    await saveSettings({
      dnsInstallResolverStubs: true,
      dnsRules: next.dnsRules,
      dnsListenPort: next.dnsListenPort,
      dnsDefaultNameserver: next.dnsDefaultNameserver,
      dnsDefaultNameserverPort: next.dnsDefaultNameserverPort
    });

    if (!payload.rules.length) {
      return {
        ok: false,
        state: "error",
        message: "No enabled complete DNS rules to install."
      };
    }

    // Reinstall after uninstall is useless if stub is down (macOS falls back to corp DNS).
    if (message.ensureDnsRunning !== false) {
      const status = await sendNativeMessage({ action: "dnsStatus" });

      if (status?.state !== "running") {
        appendLog("Reinstall resolver: starting DNS stub first (no nested auto-install)");
        const started = await sendNativeMessage({
          action: "dnsStart",
          ...payload,
          autoInstallResolver: false,
          enforce: payload.enforce
        });

        if (!started?.ok) {
          return {
            ok: false,
            state: "error",
            message: started?.message || "DNS stub failed to start; press DNS On then Reinstall.",
            stubRunning: false
          };
        }

        await saveSettings({ dnsEnabled: true, sessionDesiredDns: true });
      }
    }

    return sendNativeMessage({
      action: "dnsInstallResolver",
      ...payload,
      force: Boolean(message.force) || Boolean(message.forceInstall),
      forceInstall: Boolean(message.force) || Boolean(message.forceInstall)
    });
  }

  if (message.action === "dnsUninstallResolver") {
    await saveSettings({ dnsInstallResolverStubs: false });
    return sendNativeMessage({ action: "dnsUninstallResolver" });
  }

  return {
    ok: false,
    state: "error",
    message: "Unknown DNS action."
  };
}

function scheduleStartupSync() {
  // Defer so SW install/startup is not blocked by native messaging.
  setTimeout(() => {
    syncTunnelAndProxy().catch((error) => {
      appendLog(`Startup sync failed: ${error instanceof Error ? error.message : String(error)}`);
    });
    reconcileDnsSessionFromSettings().catch((error) => {
      appendLog(`Startup DNS sync failed: ${error instanceof Error ? error.message : String(error)}`);
    });
  }, 0);
}

async function openWebholeWindow() {
  ensureActionPopup();

  if (webholeWindowId != null) {
    try {
      await chrome.windows.get(webholeWindowId);
      await chrome.windows.update(webholeWindowId, { focused: true });
      appendLog("Focused existing Webhole window");
      return webholeWindowId;
    } catch {
      webholeWindowId = null;
    }
  }

  try {
    const win = await chrome.windows.create({
      url: `${chrome.runtime.getURL(POPUP_PATH)}?src=window`,
      type: "popup",
      width: 380,
      height: 640,
      focused: true
    });
    webholeWindowId = typeof win?.id === "number" ? win.id : null;
    appendLog(`Opened Webhole window id=${webholeWindowId ?? "?"}`);
    return webholeWindowId;
  } catch (error) {
    appendLog(`Open Webhole window failed: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

chrome.runtime.onInstalled.addListener(() => {
  ensureActionPopup();
  scheduleStartupSync();
});

chrome.runtime.onStartup.addListener(() => {
  ensureActionPopup();
  scheduleStartupSync();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") {
    return false;
  }

  if (message.type === "webhole:openWindow") {
    openWebholeWindow()
      .then((id) => sendResponse({ ok: true, windowId: id }))
      .catch((error) =>
        sendResponse({
          ok: false,
          message: error instanceof Error ? error.message : String(error)
        })
      );
    return true;
  }

  if (message.type === "webhole:dns") {
    handleDnsMessage(message).then(sendResponse);
    return true;
  }

  if (message.type !== "webhole:tunnel") {
    return false;
  }

  handleTunnelMessage(message).then(sendResponse);
  return true;
});

chrome.commands.onCommand.addListener((command) => {
  if (command === "open-webhole") {
    void openWebholeWindow();
  }
});

if (chrome.windows?.onRemoved) {
  chrome.windows.onRemoved.addListener((windowId) => {
    if (windowId === webholeWindowId) {
      webholeWindowId = null;
    }
  });
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") {
    return;
  }

  if (
    changes.mode ||
    changes.routes ||
    changes.defaultHostAlias ||
    changes.hostAlias ||
    changes.sessionDesired ||
    changes.routesFallback
  ) {
    scheduleReconcileSession();
  }

  if (
    changes.dnsEnabled ||
    changes.sessionDesiredDns ||
    changes.dnsRules ||
    changes.dnsListenPort ||
    changes.dnsDefaultNameserver ||
    changes.dnsDefaultNameserverPort ||
    changes.dnsEnforce
  ) {
    scheduleReconcileDnsSession();
  }
});

ensureActionPopup();
scheduleStartupSync();
