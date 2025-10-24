const STORAGE_PREFIX = "nhd_cache:";

function buildKey(key) {
    return `${STORAGE_PREFIX}${key}`;
}

async function removeIfExpired(storageKey, payload) {
    if (!payload) {
        return null;
    }
    if (typeof payload !== "object" || payload === null) {
        return payload;
    }
    const { value, expiresAt } = payload;
    if (expiresAt && Date.now() > expiresAt) {
        try {
            await browser.storage.local.remove(storageKey);
        } catch (_) {
            // ignore storage failures on cleanup
        }
        return null;
    }
    return value;
}

export async function readCache(key) {
    const storageKey = buildKey(key);
    try {
        const payload = await browser.storage.local.get(storageKey);
        return await removeIfExpired(storageKey, payload[storageKey]);
    } catch (_) {
        return null;
    }
}

export async function writeCache(key, value, ttlMs) {
    const storageKey = buildKey(key);
    const expiresAt = ttlMs ? Date.now() + ttlMs : null;
    const payload = { value, expiresAt };
    try {
        await browser.storage.local.set({ [storageKey]: payload });
    } catch (_) {
        // ignore storage write failures
    }
    return value;
}

export async function clearCache(key) {
    const storageKey = buildKey(key);
    try {
        await browser.storage.local.remove(storageKey);
    } catch (_) {
        // ignore storage remove failures
    }
}

