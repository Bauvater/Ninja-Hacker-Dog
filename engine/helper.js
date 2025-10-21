function createAbortError() {
    if (typeof DOMException === "function") {
        return new DOMException("Aborted", "AbortError");
    }
    const error = new Error("Aborted");
    error.name = "AbortError";
    return error;
}

function delay(ms, signal) {
    if (!signal) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    return new Promise((resolve, reject) => {
        if (signal.aborted) {
            reject(createAbortError());
            return;
        }

        const timer = setTimeout(() => {
            signal.removeEventListener("abort", onAbort);
            resolve();
        }, ms);

        const onAbort = () => {
            clearTimeout(timer);
            signal.removeEventListener("abort", onAbort);
            reject(createAbortError());
        };

        signal.addEventListener("abort", onAbort, { once: true });
    });
}

function getScanningElement() {
    return document.getElementById('currently-scanning');
}

export function setCurrentlyScanning(message) {
    const element = getScanningElement();
    if (!element) {
        return;
    }
    element.textContent = message;
}

export function clearCurrentlyScanning() {
    setCurrentlyScanning('');
}

export function countRequests() {
    window.nhc_requestCounter += 1
    document.querySelector("#stats").textContent = window.nhc_requestCounter + " Requests"
}

export async function request(request_url, headers = null, method = "GET", data = null, json = null, requestOptions = [], options = {}) {
    options.method = method;
    if (options.signal) {
        options.signal.throwIfAborted();
    }

    // add headers if needed
    options.headers = {}
    if (headers) {
        options.headers = headers
    }

    // mark all automatic requests with "ninja hacker dog"
    options.headers["X-Requested-With"] = "Ninja Hacker Dog"
    options.headers["Cache"] = "no-cache"

    // send body data
    if (data) {
        options.data = data
    }
    if (json) {
        options.headers["Content-Type"] = "application/json"
        options.data = JSON.stringify(json)
    }

    // dont request the same res twice
    const tracker = window.nhc_activeScanTracking;
    let id;
    try {
        id = request_url + JSON.stringify(options);
    } catch (_) {
        id = `${request_url}|${options.method || "GET"}`;
    }
    if (window.nhc_requestedUrls.includes(id)) {
        return false;
    } else {
        window.nhc_requestedUrls.push(id);
        if (tracker && typeof tracker.add === "function") {
            tracker.add(id);
        }
    }

    // run request
    if (!requestOptions.includes("nowait")) {
        // this sets a global timegap for parallel requests
        window.nhc_requestGapTimer += 400;
        try {
            await delay(window.nhc_requestGapTimer, options.signal);
        } finally {
            window.nhc_requestGapTimer = Math.max(0, window.nhc_requestGapTimer - 400);
        }

        if (options.signal) {
            options.signal.throwIfAborted();
        }
    }
    


    let response = await fetch(request_url, { ...options, signal: options.signal })
    let body = await response.text()
    countRequests()

    return {
        request: options,
        response: response,
        body: body
    }
}
