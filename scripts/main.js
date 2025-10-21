import { leakUrls } from "../rules/leak-urls.js";
import { poc } from "../rules/poc.js";
import { web } from "../rules/web.js";
import { newWeb } from "../rules/new-web.js";
import { passiveChecks } from "../rules/passive-checks.js";
import { activeChecks } from "../rules/active-checks.js";
import { tags } from "../engine/tags.js"
import { fuzzing } from "../rules/fuzzing.js"
import { versions } from "../rules/versions.js"
import { htaccess } from "../rules/htaccess.js";
import { sqlInjection } from "../rules/sql-injection.js";

import { engine } from "../engine/engine.js"
import { fuzzing_engine } from "../engine/fuzzing.js"
import { detection } from "../engine/detection.js";
import { clearCurrentlyScanning } from "../engine/helper.js";

let myWindowId;
const check_automatically = document.querySelector("#autoRequest");
const alertToolsEl = document.getElementById('alert-tools');
const alertFilterInput = document.getElementById('alert-filter');
const exportAlertsButton = document.getElementById('export-alerts');
const resetLink = document.getElementById('reset');
const domainContainerEl = document.getElementById('domain-container');

const proxyEnabledEl = document.getElementById('proxyEnabled');
const proxyHostEl = document.getElementById('proxyHost');
const proxyPortEl = document.getElementById('proxyPort');
const proxyUserEl = document.getElementById('proxyUser');
const proxyPassEl = document.getElementById('proxyPass');
const proxySaveButton = document.getElementById('saveProxy');
const proxyTestButton = document.getElementById('proxyTest');
const proxyStatusEl = document.getElementById('proxyStatus');
let proxyBusy = false;
let suppressProxyEvents = false;

// Global abort controller and scan identifier
let abortController = new AbortController();
let currentScanId = 0;
let activeScanState = null;

// Central cancellation routine for scans
function cancelScan() {
    cancelActiveScan();
    try { abortController.abort(); } catch (_) {}
    abortController = new AbortController();
    currentScanId++; // invalidate running scans

    const skipBtn = document.getElementById('skip-scan');
    if (skipBtn) skipBtn.classList.add('hidden');

    const cur = document.getElementById('currently-scanning');
    if (cur) clearCurrentlyScanning();

    if (Array.isArray(window.nhc_requestedUrls)) {
        window.nhc_requestedUrls.length = 0;
    }
    if (typeof window.nhc_requestGapTimer === "number") {
        window.nhc_requestGapTimer = 0;
    }
    if (Array.isArray(window.nhc_globalRequests)) {
        window.nhc_globalRequests.length = 0;
    }
}

function cancelActiveScan() {
    const state = activeScanState;
    activeScanState = null;
    window.nhc_activeScanTracking = null;
    if (!state) {
        return;
    }
    const { controller, requestIds } = state;
    try {
        controller.abort();
    } catch (_) {}
    if (Array.isArray(window.nhc_requestedUrls) && requestIds && requestIds.size) {
        for (const id of requestIds) {
            const index = window.nhc_requestedUrls.indexOf(id);
            if (index !== -1) {
                window.nhc_requestedUrls.splice(index, 1);
            }
        }
        requestIds.clear();
    }
}

function linkAbortSignals(...signals) {
    const validSignals = signals.filter(Boolean);
    if (validSignals.length === 0) {
        return { signal: undefined, cleanup: () => {} };
    }
    if (validSignals.length === 1) {
        return { signal: validSignals[0], cleanup: () => {} };
    }
    if (typeof AbortSignal !== "undefined" && typeof AbortSignal.any === "function") {
        try {
            const linked = AbortSignal.any(validSignals);
            return { signal: linked, cleanup: () => {} };
        } catch (_) {
            // ignore and use manual fallback
        }
    }

    const controller = new AbortController();
    const listeners = [];

    const cleanup = () => {
        while (listeners.length) {
            const { target, handler } = listeners.pop();
            target.removeEventListener("abort", handler);
        }
    };

    const abort = () => {
        if (!controller.signal.aborted) {
            controller.abort();
        }
        cleanup();
    };

    for (const sig of validSignals) {
        if (sig.aborted) {
            abort();
            return { signal: controller.signal, cleanup };
        }
        const handler = () => abort();
        listeners.push({ target: sig, handler });
        sig.addEventListener("abort", handler, { once: true });
    }

    return { signal: controller.signal, cleanup };
}

// Persist checkbox states
function saveCheckboxStates() {
    const states = {};
    document.querySelectorAll('#sidebar input[type="checkbox"]').forEach(cb => {
        states[cb.id] = cb.checked;
    });
    localStorage.setItem('checkboxStates', JSON.stringify(states));
}

function restoreCheckboxStates() {
    const saved = localStorage.getItem('checkboxStates');
    if (!saved) return;
    const states = JSON.parse(saved);
    document.querySelectorAll('#sidebar input[type="checkbox"]').forEach(cb => {
        if (states.hasOwnProperty(cb.id)) {
            cb.checked = states[cb.id];
        }
    });
}
restoreCheckboxStates();

function hasAlerts() {
    return !!(domainContainerEl && domainContainerEl.querySelector('.message'));
}

function applyAlertFilter() {
    if (!alertFilterInput || !domainContainerEl) {
        return;
    }
    const query = alertFilterInput.value.trim().toLowerCase();
    domainContainerEl.querySelectorAll('.domain-wrapper').forEach(wrapper => {
        let visibleMessages = 0;
        wrapper.querySelectorAll('.message').forEach(messageEl => {
            const searchable = [
                messageEl.dataset.title || '',
                messageEl.dataset.url || '',
                messageEl.dataset.detectedBy || '',
                messageEl.dataset.description || ''
            ].join(' ').toLowerCase();
            const matches = query === '' || searchable.includes(query);
            messageEl.classList.toggle('hidden', !matches);
            if (matches) {
                visibleMessages += 1;
            }
        });
        wrapper.classList.toggle('hidden', visibleMessages === 0);
    });
}

function updateAlertToolsVisibility() {
    const alertsPresent = hasAlerts();
    if (alertToolsEl) {
        alertToolsEl.classList.toggle('hidden', !alertsPresent);
    }
    if (resetLink) {
        resetLink.classList.toggle('hidden', !alertsPresent);
    }
    if (!alertsPresent && alertFilterInput) {
        alertFilterInput.value = '';
    }
    applyAlertFilter();
}

function collectAlertData() {
    if (!domainContainerEl) {
        return [];
    }
    const filterActive = !!(alertFilterInput && alertFilterInput.value.trim());
    const alerts = [];
    domainContainerEl.querySelectorAll('.domain-wrapper').forEach(wrapper => {
        const domainHeader = wrapper.querySelector('.domain-header');
        const domainName = (domainHeader?.textContent || wrapper.id || '').trim();
        const messages = [];
        wrapper.querySelectorAll('.message').forEach(messageEl => {
            if (filterActive && messageEl.classList.contains('hidden')) {
                return;
            }
            const sizeRaw = messageEl.dataset.size || messageEl.querySelector('.size_number')?.textContent || '';
            const sizeValue = Number.parseInt(sizeRaw, 10);
            const critRaw = messageEl.dataset.critLevel || '0';
            const critValue = Number.parseInt(critRaw, 10);
            messages.push({
                title: messageEl.dataset.title || messageEl.querySelector('.title')?.textContent || '',
                url: messageEl.dataset.url || messageEl.querySelector('.url')?.href || '',
                detectedBy: messageEl.dataset.detectedBy || messageEl.querySelector('.detectedBy')?.textContent || '',
                size: Number.isNaN(sizeValue) ? null : sizeValue,
                critLevel: Number.isNaN(critValue) ? 0 : critValue,
                description: messageEl.dataset.description || ''
            });
        });
        if (messages.length) {
            alerts.push({ domain: domainName, messages });
        }
    });
    return alerts;
}

function logHtaccessFinding(rawFinding) {
    if (!rawFinding) {
        return;
    }
    if (document.querySelector("#checkboxHtaccess")?.checked === false) {
        return;
    }
    if (!rawFinding.url) {
        return;
    }
    const notes = [];
    if (rawFinding.realm) {
        notes.push(`Realm: ${rawFinding.realm}`);
    }
    if (rawFinding.scheme) {
        notes.push(`Scheme: ${rawFinding.scheme}`);
    }
    if (rawFinding.challenger) {
        notes.push(`Host: ${rawFinding.challenger}`);
    }
    if (rawFinding.host && rawFinding.host !== rawFinding.challenger) {
        notes.push(`Origin: ${rawFinding.host}`);
    }
    const noteText = notes.length ? `\n\n${notes.join(" | ")}` : "";
    const rule = {
        title: rawFinding.title || "HTAccess Protected Page",
        detectedBy: rawFinding.detectedBy || ".htaccess",
        dog: rawFinding.dog || "dog-default",
        critLevel: rawFinding.critLevel ?? 0,
        description: (rawFinding.description || "A .htaccess protected page was found. The request was cancelled to avoid authentication prompts.") + noteText,
        detectStatusCodes: ["401"]
    };
    const response = {
        status: 401,
        headers: new Map()
    };
    if (rawFinding.authenticateHeader) {
        response.headers.set("www-authenticate", rawFinding.authenticateHeader);
    }
    if (rawFinding.scheme) {
        response.headers.set("x-nhd-auth-scheme", rawFinding.scheme);
    }
    if (rawFinding.challenger) {
        response.headers.set("x-nhd-auth-host", rawFinding.challenger);
    }
    const requestInfo = rawFinding.request && typeof rawFinding.request === 'object'
        ? { ...rawFinding.request }
        : { method: rawFinding.method || "GET" };
    if (!requestInfo.method) {
        requestInfo.method = rawFinding.method || "GET";
    }
    detection(rawFinding.url, rule, response, "", rule.detectedBy, requestInfo);
}

function exportAlertsToJson(event) {
    event?.preventDefault?.();
    const alerts = collectAlertData();
    if (alerts.length === 0) {
        console.info("No alerts available to export.");
        return;
    }
    const generatedAt = new Date().toISOString();
    const payload = {
        generatedAt,
        filter: alertFilterInput ? alertFilterInput.value.trim() || null : null,
        alerts
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `ninja-hacker-dog-alerts-${generatedAt.replace(/[:.]/g, "-")}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(downloadUrl), 2000);
}

if (alertFilterInput) {
    alertFilterInput.addEventListener('input', applyAlertFilter);
}

if (exportAlertsButton) {
    exportAlertsButton.addEventListener('click', exportAlertsToJson);
}

window.applyAlertFilter = applyAlertFilter;
window.updateAlertToolsVisibility = updateAlertToolsVisibility;

updateAlertToolsVisibility();

browser.runtime.onMessage.addListener((message) => {
    if (message?.type === "htaccess-finding") {
        logHtaccessFinding(message.finding);
        if (message.finding?.id) {
            browser.storage.local.get("htaccess_findings")
                .then((result) => {
                    const findings = Array.isArray(result.htaccess_findings) ? result.htaccess_findings : [];
                    const filtered = findings.filter(f => f.id !== message.finding.id);
                    if (filtered.length !== findings.length) {
                        return browser.storage.local.set({ htaccess_findings: filtered });
                    }
                    return undefined;
                })
                .catch(() => { /* ignore storage errors */ });
        }
    }
});

function setProxyStatus(message, kind = "info") {
    if (!proxyStatusEl) {
        return;
    }
    proxyStatusEl.textContent = message;
    proxyStatusEl.classList.remove('hidden', 'info', 'error', 'success');
    const cssClass = kind === "error" ? "error" : (kind === "success" ? "success" : "info");
    proxyStatusEl.classList.add(cssClass);
}

function hideProxyStatus() {
    if (!proxyStatusEl) {
        return;
    }
    proxyStatusEl.textContent = "";
    proxyStatusEl.classList.add('hidden');
    proxyStatusEl.classList.remove('info', 'error', 'success');
}

function setProxyFormDisabled(disabled) {
    const fields = [proxyEnabledEl, proxyHostEl, proxyPortEl, proxyUserEl, proxyPassEl, proxySaveButton, proxyTestButton]
        .filter(Boolean);
    fields.forEach(field => {
        if (disabled) {
            field.dataset.proxyPrevDisabled = field.disabled ? "1" : "";
            field.disabled = true;
        } else if (field.dataset.proxyPrevDisabled !== undefined) {
            field.disabled = field.dataset.proxyPrevDisabled === "1";
            delete field.dataset.proxyPrevDisabled;
        }
    });
}

function collectProxyInput() {
    return {
        enabled: proxyEnabledEl ? proxyEnabledEl.checked : false,
        host: proxyHostEl ? proxyHostEl.value.trim() : "",
        port: proxyPortEl ? proxyPortEl.value.trim() : "",
        username: proxyUserEl ? proxyUserEl.value.trim() : "",
        password: proxyPassEl ? proxyPassEl.value : ""
    };
}

function applyProxyStateToInputs(state) {
    if (!state) {
        return;
    }
    suppressProxyEvents = true;
    try {
        if (typeof state.enabled === "boolean" && proxyEnabledEl) {
            proxyEnabledEl.checked = state.enabled;
        }
    } finally {
        suppressProxyEvents = false;
    }
    if (proxyHostEl) {
        proxyHostEl.value = typeof state.host === "string" ? state.host : "";
    }
    if (proxyPortEl) {
        if (state.port === undefined || state.port === null || state.port === "") {
            proxyPortEl.value = "";
        } else {
            proxyPortEl.value = String(state.port);
        }
    }
    if (proxyUserEl) {
        proxyUserEl.value = typeof state.username === "string" ? state.username : "";
    }
    if (proxyPassEl) {
        proxyPassEl.value = typeof state.password === "string" ? state.password : "";
    }
    saveCheckboxStates();
}

async function loadProxyState(options = {}) {
    const { silent = false } = options;
    if (!proxyEnabledEl) {
        return;
    }
    try {
        const response = await browser.runtime.sendMessage({ type: "proxy:getState" });
        if (response?.ok && response.state) {
            applyProxyStateToInputs(response.state);
            if (!silent) {
                if (response.error) {
                    setProxyStatus(response.error, "error");
                } else if (response.state.enabled) {
                    const warningText = typeof response.warning === "string" ? response.warning.trim() : "";
                    const message = warningText
                        ? `Proxy enabled. Note: ${warningText}`
                        : "Proxy enabled.";
                    setProxyStatus(message, "info");
                } else if (typeof response.warning === "string" && response.warning.trim()) {
                    setProxyStatus(response.warning.trim(), "info");
                } else {
                    hideProxyStatus();
                }
            }
            return;
        }
        if (!silent && response?.error) {
            setProxyStatus(response.error, "error");
        } else if (!silent && typeof response?.warning === "string" && response.warning.trim()) {
            setProxyStatus(response.warning.trim(), "info");
        }
    } catch (_) {
        // fallback to storage if message fails
    }
    try {
        const stored = await browser.storage.local.get(["proxySettings", "proxyLastError", "proxyLastWarning"]);
        if (stored?.proxySettings) {
            const state = stored.proxySettings;
            applyProxyStateToInputs(state);
            if (!silent) {
                if (typeof stored.proxyLastError === "string" && stored.proxyLastError.trim()) {
                    setProxyStatus(stored.proxyLastError, "error");
                } else if (state.enabled) {
                    const warningText = typeof stored.proxyLastWarning === "string" ? stored.proxyLastWarning.trim() : "";
                    const message = warningText
                        ? `Proxy enabled. Note: ${warningText}`
                        : "Proxy enabled.";
                    setProxyStatus(message, "info");
                } else if (typeof stored.proxyLastWarning === "string" && stored.proxyLastWarning.trim()) {
                    setProxyStatus(stored.proxyLastWarning.trim(), "info");
                } else {
                    hideProxyStatus();
                }
            }
            return;
        }
        if (!silent && typeof stored?.proxyLastError === "string" && stored.proxyLastError.trim()) {
            setProxyStatus(stored.proxyLastError, "error");
        } else if (!silent && typeof stored?.proxyLastWarning === "string" && stored.proxyLastWarning.trim()) {
            setProxyStatus(stored.proxyLastWarning.trim(), "info");
        }
    } catch (_) {
        // ignore storage errors
    }
}

async function handleProxySave() {
    if (!proxyEnabledEl || proxyBusy) {
        return;
    }
    const currentConfig = collectProxyInput();
    if (currentConfig.enabled && (!currentConfig.host || !currentConfig.port)) {
        setProxyStatus("Please provide proxy host and port.", "error");
        await loadProxyState({ silent: true }).catch(() => {});
        return;
    }
    proxyBusy = true;
    setProxyFormDisabled(true);
    setProxyStatus(currentConfig.enabled ? "Testing proxy connection..." : "Disabling proxy...", "info");
    try {
        const response = await browser.runtime.sendMessage({
            type: "proxy:update",
            payload: { ...currentConfig }
        });
        if (!response?.ok) {
            throw new Error(response?.error || "Failed to save proxy settings.");
        }
        if (response.state) {
            applyProxyStateToInputs(response.state);
        }
        if (response.error) {
            setProxyStatus(response.error, "error");
            await loadProxyState({ silent: true }).catch(() => {});
            return;
        }
        const latencyText = typeof response.latency === "number"
            ? `Latency: ${response.latency} ms.`
            : "";
        const warningText = typeof response.warning === "string" ? response.warning.trim() : "";
        let message = response.state?.enabled ? "Proxy enabled." : "Proxy disabled.";
        if (latencyText) {
            message += ` ${latencyText}`;
        }
        if (warningText) {
            message += ` Note: ${warningText}`;
        }
        setProxyStatus(message, "success");
    } catch (error) {
        const message = error?.message || "Failed to save proxy settings.";
        setProxyStatus(message, "error");
        await loadProxyState({ silent: true }).catch(() => {});
    } finally {
        proxyBusy = false;
        setProxyFormDisabled(false);
    }
}

async function handleProxyTest() {
    if (proxyBusy) {
        return;
    }
    const config = collectProxyInput();
    if (!config.host || !config.port) {
        setProxyStatus("Please provide proxy host and port.", "error");
        return;
    }
    proxyBusy = true;
    setProxyFormDisabled(true);
    setProxyStatus("Testing proxy connection...", "info");
    try {
        const response = await browser.runtime.sendMessage({
            type: "proxy:test",
            payload: { ...config, enabled: true }
        });
        if (!response?.ok || response?.error) {
            throw new Error(response?.error || "Proxy test failed.");
        }
        const latencyInfo = typeof response.latency === "number" ? ` (${response.latency} ms)` : "";
        const warningText = typeof response.warning === "string" ? response.warning.trim() : "";
        const message = warningText
            ? `Proxy test succeeded${latencyInfo}. Note: ${warningText}`
            : `Proxy test succeeded${latencyInfo}.`;
        setProxyStatus(message, "success");
    } catch (error) {
        setProxyStatus(error?.message || "Proxy test failed.", "error");
    } finally {
        proxyBusy = false;
        setProxyFormDisabled(false);
    }
}

if (proxySaveButton) {
    proxySaveButton.addEventListener('click', (event) => {
        event.preventDefault();
        handleProxySave().catch(() => {});
    });
}

if (proxyTestButton) {
    proxyTestButton.addEventListener('click', (event) => {
        event.preventDefault();
        handleProxyTest().catch(() => {});
    });
}

if (proxyEnabledEl) {
    loadProxyState().catch(() => {});
}

function updateCheckboxesState() {
	const enabled = check_automatically.checked;

	// Toolbar title and icon state
	document.title = enabled ? "\u{1F43E} Active Ninja Hacker Dog" : "\u{1F634} Sleeping Ninja Hacker Dog";
	try {
		browser.browserAction.setIcon({
			path: enabled
				? { 16: "/images/dog-default.png", 32: "/images/dog-default.png" }
				: { 16: "/images/dog-default-grey.png", 32: "/images/dog-default-grey.png" }
		});
	} catch (e) {}

	document.querySelectorAll(".checkbox-rules").forEach(el => {
		el.classList.toggle("checkbox-deactivated", !enabled);
	});

	document.querySelectorAll('#sidebar input[type="checkbox"]').forEach(cb => {
		if (cb.id !== "autoRequest") cb.disabled = !enabled;
	});

	if (!enabled) cancelScan();
	saveCheckboxStates();
}

// Listener for the global auto-request toggle
document.querySelector("#autoRequest").addEventListener("change", (event) => {
    const checked = event.target.checked;
    if (!checked) {
        cancelScan();
    }
    updateCheckboxesState();
    if (checked && window.nhc_requestedUrls) {
        window.nhc_requestedUrls.length = 0;
    }
});

// Listener for individual rule checkboxes
document.querySelectorAll('#sidebar input[type="checkbox"]').forEach(cb => {
    if (cb.id === 'autoRequest') return;
    cb.addEventListener('change', (e) => {
        if (!e.target.checked) {
            if (cb.id === 'checkboxActive') {
                cancelActiveScan();
            } else {
                cancelScan();
            }
        }
        if (cb === proxyEnabledEl) {
            if (!suppressProxyEvents) {
                handleProxySave().catch(() => {});
            }
            saveCheckboxStates();
            return;
        }
        saveCheckboxStates();
        if (cb.id === 'checkboxHtaccess' && e.target.checked) {
            loadHtaccessFindings();
        }
    });
});

updateCheckboxesState();

// Skip button cancels the active scan
document.getElementById('skip-scan').addEventListener('click', cancelScan);

// Global counters and caches
window.nhc_requestCounter = 0
window.nhc_requestGapTimer = 0
window.nhc_currentCritLevel = 0
window.nhc_requestedUrls = []
window.nhc_activeScanTracking = null;

async function main(requestDetails) {
	if (!check_automatically.checked) return;

    const scanId = ++currentScanId;
	browser.tabs.query({ windowId: myWindowId, active: true }).then(async tabs => {
		if (tabs?.length == 0 || !tabs[0].url) return;

		let active_tab_url = tabs[0].url;
		let active_domain = new URL(active_tab_url).hostname;
		let current_request_url = requestDetails.url;
		let current_domain = new URL(current_request_url).hostname;

		if (active_domain !== current_domain) return;
		if (active_tab_url.indexOf('about:') === 0) return;

		abortController = new AbortController();
		const signal = abortController.signal;
        const guard = () => signal.aborted || scanId !== currentScanId;

        document.getElementById('skip-scan').classList.remove('hidden');

        try {
            if (guard()) return;
            const detectedTags = await tags(current_request_url, { signal });
            if (guard()) return;

            let allPassiveChecks = [];
            if (document.querySelector("#checkboxWeb").checked)
                allPassiveChecks = allPassiveChecks.concat(web, newWeb, passiveChecks);
            if (document.querySelector("#checkboxLeaks").checked)
                allPassiveChecks = allPassiveChecks.concat(leakUrls);
            if (document.querySelector("#checkboxHtaccess").checked)
                allPassiveChecks = allPassiveChecks.concat(htaccess);
            if (document.querySelector("#checkboxVersions").checked)
                allPassiveChecks = allPassiveChecks.concat(versions);

            if (guard()) return;
            await engine(allPassiveChecks, detectedTags, current_request_url, { signal });

            if (guard()) return;
            if (document.querySelector("#checkboxCritPOC").checked)
                await engine(poc, detectedTags, current_request_url, { signal });

            if (guard()) return;
            if (document.querySelector("#checkboxFuzzing").checked) {
                let allFuzzingRules = fuzzing.concat(sqlInjection);
                await fuzzing_engine(allFuzzingRules, requestDetails, { signal });
            }

            if (guard()) return;
            if (document.querySelector("#checkboxActive")?.checked) {
                cancelActiveScan();
                const localActiveController = new AbortController();
                const localActiveRequests = new Set();
                activeScanState = { controller: localActiveController, requestIds: localActiveRequests };
                window.nhc_activeScanTracking = localActiveRequests;
                const linked = linkAbortSignals(signal, localActiveController.signal);
                try {
                    await engine(activeChecks, detectedTags, current_request_url, { signal: linked.signal });
                } finally {
                    linked.cleanup();
                    localActiveRequests.clear();
                    if (window.nhc_activeScanTracking === localActiveRequests) {
                        window.nhc_activeScanTracking = null;
                    }
                    if (activeScanState && activeScanState.controller === localActiveController) {
                        activeScanState = null;
                    }
                }
            }
        } catch (err) {
            if (!(err && err.name === 'AbortError')) console.warn("scan error:", err);
        } finally {
            // Only reset the UI if this scan is still current
            if (scanId === currentScanId) {
                document.getElementById('skip-scan').classList.add('hidden');
                clearCurrentlyScanning();
            }
        }
	});
}

// --- WebRequest interception ---
const globalRequests = Array.isArray(window.nhc_globalRequests) ? window.nhc_globalRequests : [];
window.nhc_globalRequests = globalRequests;

browser.webRequest.onBeforeRequest.addListener(
	request => {
        if (!check_automatically.checked) {
            delete globalRequests[request.requestId];
            return;
        }
		globalRequests[request.requestId] = request;
		if (request?.requestBody?.raw) {
			globalRequests[request.requestId].requestBodyString = decodeURIComponent(
				String.fromCharCode.apply(null,
					new Uint8Array(request.requestBody.raw[0].bytes))
			);
		}
		if (globalRequests[request.requestId].requestBodyString) {
			try {
				globalRequests[request.requestId].requestBodyJSON = JSON.parse(
					globalRequests[request.requestId].requestBodyString
				);
			} catch {
				console.warn("JSON parser failed:", request.url);
			}
		}
	},
	{ urls: ["<all_urls>"] },
	["requestBody"]
);

browser.webRequest.onBeforeSendHeaders.addListener(
	request => {
        const stored = globalRequests[request.requestId];
        if (!stored) {
            return;
        }
		stored.requestHeaders = request.requestHeaders
	},
	{ urls: ["<all_urls>"], types: ["main_frame", "xmlhttprequest"] },
	["requestHeaders"]
);

browser.webRequest.onHeadersReceived.addListener(
	request => {
        const stored = globalRequests[request.requestId];
        if (!stored) {
            return;
        }
		stored.responseHeaders = request.responseHeaders
	},
	{ urls: ["<all_urls>"], types: ["main_frame", "xmlhttprequest"] },
	["responseHeaders"]
);

browser.webRequest.onCompleted.addListener(
	request => {
		let currentRequest = globalRequests[request.requestId];
        delete globalRequests[request.requestId];
        if (!check_automatically.checked || !currentRequest) {
            return;
        }
		let dog_header = currentRequest.requestHeaders
			?.find(h => h.name === "X-Requested-With" && h.value === "Ninja Hacker Dog");
		if (!dog_header) main(currentRequest);
	},
	{ urls: ["<all_urls>"], types: ["main_frame", "xmlhttprequest"] }
);

browser.windows.getCurrent({ populate: true }).then(w => { myWindowId = w.id; });
document.querySelector('#dog-default').style.display = 'block';

// Reset the UI and stored findings
if (resetLink) {
    resetLink.addEventListener('click', (event) => {
        event.preventDefault();
        document.querySelectorAll('.avatar').forEach(a => a.style.display = 'none');
        document.querySelector('#dog-default').style.display = 'block';
        window.nhc_currentCritLevel = 0;
        window.nhc_requestCounter = 0;
        window.nhc_requestedUrls = [];
        if (domainContainerEl) {
            while (domainContainerEl.firstChild) {
                domainContainerEl.removeChild(domainContainerEl.firstChild);
            }
        }
        updateAlertToolsVisibility();
    });
}

// Collapse and manage domain result blocks
if (domainContainerEl) {
    domainContainerEl.addEventListener('click', (event) => {
        if (event.target.classList.contains('delete-message')) {
            const message = event.target.closest('.message');
            const domainMessages = message?.parentElement;
            message?.remove();
            if (domainMessages && domainMessages.querySelectorAll('.message').length === 0) {
                domainMessages.parentElement.remove();
            }
            updateAlertToolsVisibility();
        } else if (event.target.classList.contains('details-button')) {
            event.target.nextElementSibling.classList.toggle('hidden');
        } else if (event.target.classList.contains('domain-header')) {
            const domainMessages = event.target.nextElementSibling;
            domainMessages.classList.toggle('hidden');
            event.target.classList.toggle('open');
        }
    });
}

function loadHtaccessFindings() {
    if (document.querySelector("#checkboxHtaccess")?.checked === false) {
        return;
    }
    browser.storage.local.get("htaccess_findings")
        .then((result) => {
            const findings = Array.isArray(result.htaccess_findings) ? result.htaccess_findings : [];
            for (const finding of findings) {
                logHtaccessFinding(finding);
            }
            if (findings.length > 0) {
                return browser.storage.local.set({ htaccess_findings: [] });
            }
            return undefined;
        })
        .catch(() => { /* ignore storage errors */ });
}
loadHtaccessFindings();



