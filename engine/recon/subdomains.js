import { readCache, writeCache } from "../cache.js";
import { mapInBatches } from "../async-utils.js";
import { countRequests, setCurrentlyScanning } from "../helper.js";

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const CACHE_PREFIX = "subdomains:";
const MAX_PROBED_HOSTS = 40;
const PROBE_BATCH_SIZE = 5;

const PROVIDERS = [
    {
        name: "crt.sh",
        async fetch(domain, signal) {
            const url = `https://crt.sh/?q=%25.${domain}&output=json`;
            const response = await fetch(url, {
                headers: {
                    Accept: "application/json",
                    "User-Agent": "Ninja-Hacker-Dog/1.0 (+subdomain-recon)"
                },
                signal
            });
            if (!response.ok) {
                throw new Error(`crt.sh responded ${response.status}`);
            }
            const text = await response.text();
            let data;
            try {
                data = JSON.parse(text);
            } catch (_) {
                data = [];
            }
            const result = [];
            for (const entry of data) {
                const name = typeof entry?.name_value === "string" ? entry.name_value : "";
                if (!name) {
                    continue;
                }
                const fragments = name.split(/\s+/);
                for (const fragment of fragments) {
                    result.push(fragment.trim());
                }
            }
            return result;
        }
    },
    {
        name: "HackerTarget",
        async fetch(domain, signal) {
            const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
            const response = await fetch(url, {
                headers: {
                    Accept: "text/plain",
                    "User-Agent": "Ninja-Hacker-Dog/1.0 (+subdomain-recon)"
                },
                signal
            });
            if (!response.ok) {
                throw new Error(`HackerTarget responded ${response.status}`);
            }
            const text = await response.text();
            const textLower = text.toLowerCase();
            if (textLower.includes("error") || textLower.includes("api rate limit")) {
                throw new Error("HackerTarget rate limited");
            }
            return text
                .split("\n")
                .map(line => line.split(",")[0]?.trim())
                .filter(Boolean);
        }
    },
    {
        name: "BufferOver",
        async fetch(domain, signal) {
            const url = `https://dns.bufferover.run/dns?q=.${domain}`;
            const response = await fetch(url, {
                headers: {
                    Accept: "application/json",
                    "User-Agent": "Ninja-Hacker-Dog/1.0 (+subdomain-recon)"
                },
                signal
            });
            if (!response.ok) {
                throw new Error(`BufferOver responded ${response.status}`);
            }
            let data = {};
            const raw = await response.text();
            try {
                data = JSON.parse(raw);
            } catch (_) {
                if (raw && raw.toLowerCase().includes("throttle")) {
                    throw new Error("BufferOver throttled the request");
                }
                data = {};
            }
            const aggregate = [];
            for (const key of ["FDNS_A", "RDNS"]) {
                const values = Array.isArray(data?.[key]) ? data[key] : [];
                for (const value of values) {
                    if (typeof value !== "string") {
                        continue;
                    }
                    const host = value.split(",")[1] || value.split(",")[0];
                    if (host) {
                        aggregate.push(host.trim());
                    }
                }
            }
            return aggregate;
        }
    }
];

function normalizeHostname(value) {
    if (typeof value !== "string") {
        return null;
    }
    const lower = value
        .trim()
        .toLowerCase()
        .replace(/\s+/g, "")
        .replace(/\.*$/, "");
    if (!lower) {
        return null;
    }
    return lower;
}

function isRelatedSubdomain(host, domain) {
    if (!host || !domain) {
        return false;
    }
    return host === domain || host.endsWith(`.${domain}`);
}

function buildCacheKey(domain) {
    return `${CACHE_PREFIX}${domain}`;
}

async function probeHost(host, options) {
    const { signal } = options || {};
    const protocols = ["https://", "http://"];
    let lastError = null;
    for (const base of protocols) {
        if (signal?.aborted) {
            throw signal.reason || new DOMException("Aborted", "AbortError");
        }
        try {
            const response = await fetch(`${base}${host}`, {
                method: "GET",
                redirect: "manual",
                headers: {
                    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "User-Agent": "Ninja-Hacker-Dog/1.0 (+host-probe)",
                    "X-Requested-With": "Ninja Hacker Dog"
                },
                signal
            });
            const status = response.status;
            const text = await response.text();
            countRequests();
            const titleMatch = text.match(/<title[^>]*>([^<]{0,200})<\/title>/i);
            return {
                host,
                url: `${base}${host}`,
                status,
                server: response.headers.get("server") || null,
                title: titleMatch ? titleMatch[1].trim() : null
            };
        } catch (error) {
            if (error?.name === "AbortError") {
                throw error;
            }
            lastError = error;
        }
    }
    return {
        host,
        url: null,
        status: null,
        server: null,
        title: null,
        error: lastError ? String(lastError.message || lastError) : "Unknown error"
    };
}

async function probeHosts(hosts, options) {
    if (!Array.isArray(hosts) || hosts.length === 0) {
        return [];
    }
    const limited = hosts.slice(0, Math.min(hosts.length, options?.probeLimit ?? MAX_PROBED_HOSTS));
    const batchSize = options?.probeBatchSize ?? PROBE_BATCH_SIZE;
    setCurrentlyScanning(`Recon:\nProbing ${limited.length} host(s)`);
    try {
        return await mapInBatches(limited, batchSize, async host => {
            const result = await probeHost(host, options);
            return result;
        });
    } finally {
        setCurrentlyScanning("");
    }
}

export async function performSubdomainRecon(domain, options = {}) {
    const normalizedDomain = normalizeHostname(domain);
    if (!normalizedDomain) {
        return {
            domain: null,
            fetchedAt: Date.now(),
            subdomains: [],
            sources: {},
            probed: [],
            cached: false
        };
    }

    const cacheKey = buildCacheKey(normalizedDomain);
    if (options?.signal?.aborted) {
        throw options.signal.reason || new DOMException("Aborted", "AbortError");
    }
    if (!options.forceRefresh) {
        const cached = await readCache(cacheKey);
        if (cached) {
            return { ...cached, cached: true };
        }
    }

    setCurrentlyScanning(`Recon:\nEnumerating *.${normalizedDomain}`);

    const aggregate = new Set();
    const sources = {};

    try {
        const providerPromises = PROVIDERS.map(async provider => {
            try {
                const entries = await provider.fetch(normalizedDomain, options.signal);
                const normalized = [];
                for (const entry of entries) {
                    const host = normalizeHostname(entry);
                    if (!host || host.includes("*") || !isRelatedSubdomain(host, normalizedDomain)) {
                        continue;
                    }
                    aggregate.add(host);
                    normalized.push(host);
                }
                sources[provider.name] = normalized.length;
            } catch (error) {
                sources[provider.name] = 0;
                if (options?.logErrors && error) {
                    console.warn(`[Recon] ${provider.name} failed`, error);
                }
            }
        });

        await Promise.allSettled(providerPromises);
    } finally {
        setCurrentlyScanning("");
    }

    const subdomains = Array.from(aggregate).sort();

    let probed = [];
    if (options?.signal?.aborted) {
        throw options.signal.reason || new DOMException("Aborted", "AbortError");
    }
    if (subdomains.length && options.includeProbe !== false) {
        probed = await probeHosts(subdomains, options);
    }

    const payload = {
        domain: normalizedDomain,
        fetchedAt: Date.now(),
        subdomains,
        sources,
        probed,
        cached: false
    };

    await writeCache(cacheKey, payload, options.ttl ?? CACHE_TTL_MS);
    return payload;
}
