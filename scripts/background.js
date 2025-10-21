const extensionApi = typeof browser !== "undefined" ? browser : (typeof chrome !== "undefined" ? chrome : null);

if (!extensionApi) {
    throw new Error("WebExtension APIs not available.");
}

let myWindowId = null
const handledHtaccessRequests = new Set();

const PROXY_TEST_URL = "https://example.com/";
const hasProxySupport = !!(extensionApi && extensionApi.proxy && extensionApi.proxy.settings);
let activeProxyCredentials = null;
let activeProxyState = { enabled: false };
let lastProxyError = null;
let lastProxyWarning = null;

function rememberHtaccessRequest(requestId) {
    if (!requestId) {
        return false;
    }
    if (handledHtaccessRequests.has(requestId)) {
        return false;
    }
    handledHtaccessRequests.add(requestId);
    setTimeout(() => handledHtaccessRequests.delete(requestId), 30000);
    return true;
}

function cloneAuthCredentials(credentials) {
    if (!credentials) {
        return null;
    }
    return {
        username: credentials.username,
        password: credentials.password
    };
}

function normalizeProxyInput(input) {
    if (!input || typeof input !== "object") {
        throw new Error("No proxy configuration provided.");
    }

    const scheme = (typeof input.scheme === "string" && input.scheme.trim()) || "http";
    let host = String(input.host ?? "").trim();
    if (!host) {
        throw new Error("Proxy host must not be empty.");
    }
    host = host.replace(/^\s*https?:\/\//i, "");
    if (host.includes("/")) {
        host = host.split("/")[0];
    }
    if (!host) {
        throw new Error("Proxy host is invalid.");
    }

    const portValue = String(input.port ?? "").trim();
    const port = Number.parseInt(portValue, 10);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
        throw new Error("Proxy port must be between 1 and 65535.");
    }

    const username = typeof input.username === "string" ? input.username.trim() : "";
    const password = typeof input.password === "string" ? input.password : "";
    const bypassList = Array.isArray(input.bypassList)
        ? input.bypassList
            .filter(entry => typeof entry === "string" && entry.trim())
            .map(entry => entry.trim())
        : [];
    const testUrl = typeof input.testUrl === "string" && input.testUrl.trim()
        ? input.testUrl.trim()
        : PROXY_TEST_URL;

    return {
        enabled: true,
        scheme,
        host,
        port,
        username,
        password,
        bypassList,
        testUrl
    };
}

async function persistProxyState(state) {
    try {
        await extensionApi.storage.local.set({ proxySettings: state });
    } catch (_) {
        // persist is best-effort
    }
}

async function setLastProxyError(message) {
    lastProxyError = message || null;
    try {
        await extensionApi.storage.local.set({ proxyLastError: lastProxyError });
    } catch (_) {
        // ignore storage errors
    }
}

async function setLastProxyWarning(message) {
    lastProxyWarning = message || null;
    try {
        await extensionApi.storage.local.set({ proxyLastWarning: lastProxyWarning });
    } catch (_) {
        // ignore storage errors
    }
}

async function flushProxySettings() {
    if (extensionApi.webRequest && typeof extensionApi.webRequest.handlerBehaviorChanged === "function") {
        try {
            const maybePromise = extensionApi.webRequest.handlerBehaviorChanged();
            if (maybePromise && typeof maybePromise.catch === "function") {
                await maybePromise.catch(() => {});
            }
        } catch (_) {
            // ignore
        }
    }
}

function callProxySetting(method, details) {
    if (!hasProxySupport) {
        return Promise.reject(new Error("Proxy interface is not supported in this browser."));
    }

    const target = extensionApi.proxy.settings[method];
    if (typeof target !== "function") {
        return Promise.reject(new Error(`Proxy setting ${method} is unavailable.`));
    }

    if (target.length <= 1) {
        try {
            const maybePromise = target.call(extensionApi.proxy.settings, details);
            if (maybePromise && typeof maybePromise.then === "function") {
                return maybePromise;
            }
            return Promise.resolve(maybePromise);
        } catch (error) {
            return Promise.reject(error);
        }
    }

    return new Promise((resolve, reject) => {
        const callback = value => {
            const err = extensionApi.runtime && extensionApi.runtime.lastError;
            if (err) {
                reject(new Error(err.message));
            } else {
                resolve(value);
            }
        };

        try {
            if (method === "get") {
                target.call(extensionApi.proxy.settings, details, callback);
            } else {
                target.call(extensionApi.proxy.settings, details, () => callback(undefined));
            }
        } catch (error) {
            reject(error);
        }
    });
}

function proxySettingsGet() {
    return callProxySetting("get", {});
}

function proxySettingsSet(value) {
    return callProxySetting("set", { value, scope: "regular" });
}

function proxySettingsClear() {
    return callProxySetting("clear", { scope: "regular" });
}

function buildProxyConfig(normalized) {
    const bypass = normalized.bypassList.length ? normalized.bypassList : ["<local>"];
    const location = `${normalized.host}:${normalized.port}`;
    const config = {
        mode: "fixed_servers",
        rules: {
            singleProxy: {
                scheme: normalized.scheme,
                host: normalized.host,
                port: normalized.port
            },
            bypassList: bypass
        },
        proxyType: "manual",
        passthrough: bypass.join(",")
    };

    const scheme = (normalized.scheme || "").toLowerCase();
    if (scheme.startsWith("socks")) {
        config.socks = location;
        config.socksVersion = scheme.endsWith("5") ? 5 : 4;
    } else {
        config.http = location;
        config.ssl = location;
        config.ftp = location;
        config.httpProxyAll = true;
    }

    return config;
}

function buildDirectConfig(bypass = []) {
    const passthrough = Array.isArray(bypass) && bypass.length ? bypass.join(",") : "<local>";
    return {
        mode: "direct",
        proxyType: "none",
        passthrough
    };
}

async function restoreProxyValue(previousValue) {
    if (!hasProxySupport) {
        return;
    }
    if (!previousValue || typeof previousValue !== "object" || previousValue.value === undefined) {
        await proxySettingsClear().catch(() => {});
        await flushProxySettings();
        return;
    }
    await proxySettingsSet(previousValue.value).catch(() => {});
    await flushProxySettings();
}

function formatProxyError(error) {
    if (!error) {
        return "Unknown error during proxy test.";
    }
    if (typeof error === "string") {
        return error;
    }
    if (error.name === "AbortError") {
        return "Proxy test aborted because of timeout.";
    }
    if (error.message) {
        return error.message;
    }
    return String(error);
}

async function testProxyConnection(testUrl = PROXY_TEST_URL, timeoutMs = 8000) {
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const startedAt = Date.now();

    let timeoutId = null;
    if (controller) {
        timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    }

    try {
        const response = await fetch(testUrl, {
            cache: "no-store",
            redirect: "follow",
            credentials: "omit",
            signal: controller ? controller.signal : undefined
        });

        if (timeoutId) {
            clearTimeout(timeoutId);
        }

        const status = typeof response.status === "number" ? response.status : null;
        const statusText = typeof response.statusText === "string" ? response.statusText : "";

        if (status === 407) {
            throw new Error("Proxy requires valid credentials (HTTP 407).");
        }
        if (status !== null && status >= 500) {
            throw new Error(`Proxy responded with HTTP ${status}.`);
        }

        let warning = null;
        if (status !== null && status >= 400) {
            const suffix = statusText ? ` (${statusText})` : "";
            warning = `Proxy responded with HTTP ${status}${suffix}.`;
        }

        // Consume a small portion to surface errors early
        await response.text();

        return {
            success: true,
            latency: Date.now() - startedAt,
            status,
            statusText,
            warning
        };
    } catch (error) {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
        return {
            success: false,
            error: formatProxyError(error)
        };
    }
}

async function applyProxyState(rawState, options = {}) {
    if (!hasProxySupport) {
        throw new Error("Proxy interface is unavailable.");
    }

    const { runTest = true, persist = true } = options;
    const previousValue = await proxySettingsGet().catch(() => null);
    const previousCredentials = cloneAuthCredentials(activeProxyCredentials);
    const previousState = { ...activeProxyState };

    if (!rawState || rawState.enabled === false) {
        const fallbackHost = typeof rawState?.host === "string" && rawState.host.trim()
            ? rawState.host.trim()
            : (typeof previousState.host === "string" ? previousState.host : "");
        const fallbackScheme = typeof rawState?.scheme === "string" && rawState.scheme.trim()
            ? rawState.scheme.trim()
            : (typeof previousState.scheme === "string" && previousState.scheme.trim()
                ? previousState.scheme.trim()
                : "http");
        const fallbackPort = (() => {
            if (rawState && rawState.port !== undefined && rawState.port !== null && rawState.port !== "") {
                const parsed = Number.parseInt(rawState.port, 10);
                if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) {
                    return parsed;
                }
            }
            if (typeof previousState.port === "number") {
                return previousState.port;
            }
            return null;
        })();
        const fallbackBypass = Array.isArray(rawState?.bypassList)
            ? rawState.bypassList
                .filter(entry => typeof entry === "string" && entry.trim())
                .map(entry => entry.trim())
            : Array.isArray(previousState.bypassList)
                ? [...previousState.bypassList]
                : [];

        await proxySettingsSet(buildDirectConfig(fallbackBypass)).catch(() => proxySettingsClear().catch(() => {}));
        await flushProxySettings();
        activeProxyCredentials = null;

        activeProxyState = {
            enabled: false,
            scheme: fallbackScheme,
            host: fallbackHost,
            port: fallbackPort,
            username: typeof rawState?.username === "string" ? rawState.username : (previousState.username || ""),
            password: typeof rawState?.password === "string" ? rawState.password : "",
            bypassList: fallbackBypass
        };

        if (persist) {
            await persistProxyState(activeProxyState);
        }
        await setLastProxyError(null);
        await setLastProxyWarning(null);
        return { tested: false, latency: null, state: { ...activeProxyState } };
    }

    const normalized = normalizeProxyInput(rawState);

    try {
        await proxySettingsSet(buildProxyConfig(normalized));
        await flushProxySettings();
    } catch (error) {
        activeProxyCredentials = previousCredentials;
        activeProxyState = previousState;
        const formatted = formatProxyError(error);
        await setLastProxyError(formatted);
        await setLastProxyWarning(null);
        throw new Error(formatted);
    }

    activeProxyCredentials = normalized.username
        ? { username: normalized.username, password: normalized.password }
        : null;

    let latency = null;
    let warning = null;
    let status = null;
    if (runTest) {
        const testResult = await testProxyConnection(normalized.testUrl);
        if (!testResult.success) {
            await restoreProxyValue(previousValue);
            activeProxyCredentials = previousCredentials;
            activeProxyState = previousState;
            await setLastProxyError(testResult.error);
            await setLastProxyWarning(null);
            throw new Error(testResult.error);
        }
        latency = testResult.latency;
        warning = testResult.warning || null;
        status = typeof testResult.status === "number" ? testResult.status : null;
        await setLastProxyWarning(warning);
    } else {
        await setLastProxyWarning(null);
    }

    activeProxyState = {
        enabled: true,
        scheme: normalized.scheme,
        host: normalized.host,
        port: normalized.port,
        username: normalized.username,
        password: normalized.password,
        bypassList: [...normalized.bypassList]
    };

    if (persist) {
        await persistProxyState(activeProxyState);
    }

    await setLastProxyError(null);
    return { tested: runTest, latency, state: { ...activeProxyState }, warning, status };
}

async function restoreProxyStateOnStartup() {
    if (!hasProxySupport) {
        return;
    }
    try {
        const stored = await extensionApi.storage.local.get(["proxySettings", "proxyLastError", "proxyLastWarning"]);
        const storedState = stored && stored.proxySettings;
        if (!storedState) {
            lastProxyError = stored?.proxyLastError ?? null;
            lastProxyWarning = stored?.proxyLastWarning ?? null;
            return;
        }
        if (storedState.enabled) {
            try {
                await applyProxyState(storedState, { runTest: true, persist: false });
            } catch (error) {
                const message = formatProxyError(error);
                await proxySettingsClear().catch(() => {});
                activeProxyCredentials = null;
                const fallbackPort = (() => {
                    const value = storedState.port;
                    const parsed = Number.parseInt(value, 10);
                    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) {
                        return parsed;
                    }
                    return null;
                })();

                activeProxyState = {
                    enabled: false,
                    scheme: typeof storedState.scheme === "string" && storedState.scheme.trim() ? storedState.scheme.trim() : "http",
                    host: typeof storedState.host === "string" ? storedState.host : "",
                    port: fallbackPort,
                    username: typeof storedState.username === "string" ? storedState.username : "",
                    password: "",
                    bypassList: Array.isArray(storedState.bypassList) ? [...storedState.bypassList] : []
                };
                await persistProxyState(activeProxyState);
                await setLastProxyError(message);
                await setLastProxyWarning(null);
            }
        } else {
            await applyProxyState(storedState, { runTest: false, persist: false });
            if (typeof stored.proxyLastError === "string" && stored.proxyLastError.trim()) {
                await setLastProxyError(stored.proxyLastError);
            } else {
                await setLastProxyError(null);
            }
            if (typeof stored.proxyLastWarning === "string" && stored.proxyLastWarning.trim()) {
                await setLastProxyWarning(stored.proxyLastWarning);
            } else {
                await setLastProxyWarning(null);
            }
        }
    } catch (_) {
        // still continue without proxy restore
    }
}

extensionApi.runtime.onMessage.addListener((message) => {
    if (!message || typeof message !== "object") {
        return undefined;
    }

    if (message.type === "proxy:update") {
        if (!hasProxySupport) {
            return Promise.resolve({ ok: false, error: "Proxy support is not available in this browser." });
        }
        return applyProxyState(message.payload || {}, { runTest: true, persist: true })
            .then(result => ({
                ok: true,
                tested: result.tested,
                latency: result.latency,
                state: { ...activeProxyState },
                error: lastProxyError,
                warning: lastProxyWarning,
                status: typeof result.status === "number" ? result.status : null
            }))
            .catch(async error => {
                const formatted = formatProxyError(error);
                await setLastProxyError(formatted);
                await setLastProxyWarning(null);
                return {
                    ok: false,
                    error: formatted
                };
            });
    }

    if (message.type === "proxy:disable") {
        if (!hasProxySupport) {
            return Promise.resolve({ ok: false, error: "Proxy support is not available in this browser." });
        }
        return applyProxyState({ enabled: false }, { runTest: false, persist: true })
            .then(result => ({
                ok: true,
                tested: result.tested,
                latency: result.latency,
                state: { ...activeProxyState },
                error: lastProxyError,
                warning: lastProxyWarning,
                status: typeof result.status === "number" ? result.status : null
            }))
            .catch(async error => {
                const formatted = formatProxyError(error);
                await setLastProxyError(formatted);
                await setLastProxyWarning(null);
                return {
                    ok: false,
                    error: formatted
                };
            });
    }

    if (message.type === "proxy:test") {
        if (!hasProxySupport) {
            return Promise.resolve({ ok: false, error: "Proxy support is not available in this browser." });
        }
        return (async () => {
            const previousValue = await proxySettingsGet().catch(() => null);
            const previousCredentials = cloneAuthCredentials(activeProxyCredentials);
            const previousState = { ...activeProxyState };
            try {
                const normalized = normalizeProxyInput(message.payload || {});
                await proxySettingsSet(buildProxyConfig(normalized));
                await flushProxySettings();
                activeProxyCredentials = normalized.username
                    ? { username: normalized.username, password: normalized.password }
                    : null;
                const testResult = await testProxyConnection(normalized.testUrl);
                await restoreProxyValue(previousValue);
                activeProxyCredentials = previousCredentials;
                activeProxyState = previousState;
                if (!testResult.success) {
                    throw new Error(testResult.error);
                }
                return {
                    ok: true,
                    latency: testResult.latency,
                    status: typeof testResult.status === "number" ? testResult.status : null,
                    warning: testResult.warning || null
                };
            } catch (error) {
                await restoreProxyValue(previousValue);
                activeProxyCredentials = previousCredentials;
                activeProxyState = previousState;
                return {
                    ok: false,
                    error: formatProxyError(error)
                };
            }
        })();
    }

    if (message.type === "proxy:getState") {
        return Promise.resolve({
            ok: true,
            state: { ...activeProxyState },
            error: lastProxyError,
            warning: lastProxyWarning
        });
    }

    return undefined;
});

restoreProxyStateOnStartup().catch(() => {});

function nhc_toggleNinjaHackerDog() {
    extensionApi.tabs.query({ windowId: myWindowId })
        .then(async tabs => {
            let found = false
            for (let tab of tabs) {
                if (tab.title
                    && (tab.title == "\u{1F43E} Active Ninja Hacker Dog" ||
                        tab.title == "\u{1F634} Sleeping Ninja Hacker Dog")) {
                    found = true
                }
            }
            if (!found) {
                extensionApi.tabs.create(
                    {
                        index: 0,
                        url: "/panel.html",
                        active: true
                    }
                )
                extensionApi.browserAction.setIcon({
                    path: {
                        16: "/images/dog-default.png",
                        32: "/images/dog-default.png"
                    }
                })
            }
        })
}

function notifyHtaccessFinding(finding) {
    extensionApi.storage.local.get("htaccess_findings")
        .then((result) => {
            const findings = Array.isArray(result.htaccess_findings) ? result.htaccess_findings : [];
            findings.push(finding);
            return extensionApi.storage.local.set({ htaccess_findings: findings });
        })
        .catch(() => { /* ignore storage errors */ });

    extensionApi.runtime.sendMessage({ type: "htaccess-finding", finding })
        .catch(() => { /* no active listeners */ });
}

function handleHtaccessResponse(details) {
    if (details.statusCode !== 401) {
        return;
    }

    const authHeader = (details.responseHeaders || []).find(
        header => header?.name?.toLowerCase() === "www-authenticate"
    );

    if (!authHeader) {
        return;
    }

    if (handledHtaccessRequests.has(details.requestId)) {
        if (details.type === "main_frame") {
            return { cancel: true };
        }
        return;
    }

    rememberHtaccessRequest(details.requestId);

    const schemeMatch = authHeader.value?.split(/\s+/)[0] ?? "";
    const realmMatch = authHeader.value?.match(/realm="?([^"]+)"?/i);
    const realm = realmMatch ? realmMatch[1] : null;

    const finding = {
        id: details.requestId,
        url: details.url,
        title: "HTAccess Protected Page",
        detectedBy: ".htaccess",
        critLevel: 0,
        dog: "dog-default",
        description: "A .htaccess protected page was found. The request was cancelled to avoid authentication prompts.",
        timeStamp: details.timeStamp,
        request: {
            method: details.method || "GET"
        },
        scheme: schemeMatch || "Basic",
        realm,
        challenger: details.ip || null,
        host: (() => {
            try {
                return new URL(details.url).host;
            } catch {
                return null;
            }
        })(),
        authenticateHeader: authHeader.value || null
    };

    notifyHtaccessFinding(finding);

    if (details.type === "main_frame") {
        return { cancel: true };
    }
}

function handleAuthRequired(details) {
    if (!details || typeof details !== "object") {
        return undefined;
    }

    if (details.isProxy) {
        if (!activeProxyCredentials || details.retry) {
            return undefined;
        }
        return {
            authCredentials: {
                username: activeProxyCredentials.username,
                password: activeProxyCredentials.password
            }
        };
    }

    const htaccessChallenge = Boolean(details.scheme || details.realm);
    if (!htaccessChallenge) {
        return undefined;
    }

    const isBrowserTab = typeof details.tabId === "number" && details.tabId >= 0;
    const isMainFrame = details.frameId === 0 || details.parentFrameId === -1;
    const shouldCancel = isBrowserTab && isMainFrame;

    let added = false;
    if (shouldCancel) {
        added = rememberHtaccessRequest(details.requestId);
    }
    if (added && shouldCancel) {
        const challengerHost = (() => {
            if (!details.challenger || !details.challenger.host) {
                return null;
            }
            if (details.challenger.port && details.challenger.port !== -1) {
                return `${details.challenger.host}:${details.challenger.port}`;
            }
            return details.challenger.host;
        })();

        const scheme = (details.scheme || "").trim();
        const finding = {
            id: details.requestId,
            url: details.url,
            title: "HTAccess Protected Page",
            detectedBy: ".htaccess",
            critLevel: 0,
            dog: "dog-default",
            description: "A .htaccess protected page was found. The request was cancelled to avoid authentication prompts.",
            timeStamp: details.timeStamp,
            request: {
                method: details.method || "GET"
            },
            scheme: scheme ? (scheme.charAt(0).toUpperCase() + scheme.slice(1).toLowerCase()) : "Basic",
            realm: details.realm || null,
            challenger: challengerHost,
            host: (() => {
                try {
                    return new URL(details.url).host;
                } catch {
                    return null;
                }
            })(),
            authenticateHeader: null
        };

        notifyHtaccessFinding(finding);
    }

    if (shouldCancel) {
        return { cancel: true };
    }

    return undefined;
}

extensionApi.windows.getCurrent({ populate: true }).then((windowInfo) => {
    myWindowId = windowInfo.id
})

extensionApi.browserAction.onClicked.addListener(nhc_toggleNinjaHackerDog);

extensionApi.webRequest.onHeadersReceived.addListener(
    handleHtaccessResponse,
    { urls: ["<all_urls>"] },
    ["blocking", "responseHeaders"]
);

if (extensionApi.webRequest && extensionApi.webRequest.onAuthRequired) {
    try {
        extensionApi.webRequest.onAuthRequired.addListener(
            handleAuthRequired,
            { urls: ["<all_urls>"] },
            ["blocking"]
        );
    } catch (_) {
        // ignore registration issues
    }
}

if (extensionApi.webRequest && extensionApi.webRequest.handlerBehaviorChanged) {
    try {
        const maybePromise = extensionApi.webRequest.handlerBehaviorChanged();
        if (maybePromise && typeof maybePromise.catch === "function") {
            maybePromise.catch(() => {});
        }
    } catch (_) {
        // ignore
    }
}
















