"use strict";
let ROOT_HASH = "";
let ROOT_PATH = "";
let CACHE_NAME = 'trustRoot-cache-';
let hashCache;
self.addEventListener('install', (event) => {
    event.waitUntil(self.skipWaiting());
});
self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});
self.addEventListener('message', async (event) => {
    try {
        if (event.data && event.data.type === 'SET_ROOT_HASH') {
            let newRootHash = event.data.rootHash;
            if (newRootHash.startsWith('/')) {
                newRootHash = newRootHash.substring(1);
            }
            let parts = newRootHash.split('/sha256-');
            if (parts.length === 2) {
                ROOT_PATH = `/${parts[0]}/`;
                ROOT_HASH = 'sha256-' + parts[1];
            }
            else {
                ROOT_PATH = '/';
                ROOT_HASH = newRootHash;
            }
            if (ROOT_HASH !== newRootHash) {
                CACHE_NAME = `trustRoot-cache-${ROOT_HASH}`;
                hashCache = await caches.open(CACHE_NAME);
                clearOldCaches(ROOT_HASH);
            }
        }
        ;
    }
    catch (err) {
        console.error('Error in message event:', err);
    }
});
async function clearOldCaches(newRootHash) {
    const cacheKeys = await caches.keys();
    for (const key of cacheKeys) {
        if (key.startsWith('trustRoot-cache') && key !== `trustRoot-cache-${newRootHash}`) {
            await caches.delete(key);
        }
    }
}
let externalDomainWhitelist = ["https://maps.googleapis.com/**/*"];
function isUrlWhitelisted(url) {
    let parsedUrl;
    try {
        parsedUrl = new URL(url);
    }
    catch {
        return false;
    }
    const urlWithoutQuery = parsedUrl.origin + parsedUrl.pathname;
    function globToRegex(pattern) {
        if (!/^https?:\/\//.test(pattern)) {
            throw new Error(`Invalid whitelist pattern: ${pattern} must include domain name`);
        }
        let regexStr = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
        regexStr = regexStr
            .replace(/\\\*\\\*/g, '___GLOBSTAR___')
            .replace(/\*\*/g, '___GLOBSTAR___')
            .replace(/\*/g, '[^/]*')
            .replace(/___GLOBSTAR___/g, '.*')
            .replace(/\\\//g, '/');
        return new RegExp(`^${regexStr}(\\?.*)?$`, 'i');
    }
    return externalDomainWhitelist.some(pattern => {
        try {
            const patternUrl = new URL(pattern);
            if (!pattern.includes('*')) {
                return (patternUrl.origin.toLowerCase() === parsedUrl.origin.toLowerCase() &&
                    patternUrl.pathname === parsedUrl.pathname);
            }
            else if (patternUrl.origin.toLowerCase() != parsedUrl.origin.toLowerCase()) {
                return false;
            }
            const regex = globToRegex(pattern);
            return regex.test(urlWithoutQuery);
        }
        catch {
            return false;
        }
    });
}
function broadcastMessage(message) {
    self.clients.matchAll().then((clients) => {
        clients.forEach((client) => {
            client.postMessage(message);
        });
    });
}
function updateGlobalWhitelist(trootData) {
    if (Array.isArray(trootData.whitelist)) {
        externalDomainWhitelist = trootData.whitelist.filter((pattern) => pattern.startsWith('https://'));
        externalDomainWhitelist.forEach((pattern) => {
            if (!externalDomainWhitelist.includes(pattern)) {
                externalDomainWhitelist.push(pattern);
            }
        });
    }
}
async function fetchFileHash(filePath) {
    try {
        if (!filePath.startsWith('/')) {
            filePath = `/${filePath}`;
        }
        const normalizedPath = filePath.substring(ROOT_PATH.length);
        const pathParts = normalizedPath.split('/');
        let currentUrl = self.location.origin;
        if (currentUrl.endsWith('/')) {
            currentUrl = currentUrl.slice(0, -1);
        }
        currentUrl += ROOT_PATH;
        let currentHashes = { files: {}, directories: {}, whitelist: [] };
        if (!hashCache)
            hashCache = await caches.open(CACHE_NAME);
        let hashesUrl = `${currentUrl}.troot.json`;
        let response = await hashCache.match(hashesUrl);
        let cached = true;
        if (!response) {
            response = await fetch(hashesUrl, {
                integrity: ROOT_HASH,
                cache: 'no-cache'
            });
            if (!response.ok) {
                let message = `Failed to fetch .troot.json at ${hashesUrl}`;
                broadcastMessage({ type: 'ERROR', message });
                return;
            }
            ;
            cached = false;
            await hashCache.put(hashesUrl, response.clone());
        }
        try {
            currentHashes = await response.json();
            if (!cached)
                updateGlobalWhitelist(currentHashes);
        }
        catch (err) {
            if (err instanceof Error) {
                broadcastMessage({ type: 'ERROR', message: `Failed to parse .troot.json at ${hashesUrl}: ${err.message}` });
                return;
            }
            else {
                broadcastMessage({ type: 'ERROR', message: `Failed to parse .troot.json at ${hashesUrl}: Unknown error` });
                return;
            }
        }
        for (let i = 0; i < pathParts.length; i++) {
            const part = pathParts[i];
            if (i === pathParts.length - 1) {
                if (currentHashes.files[part]) {
                    return currentHashes.files[part];
                }
                ;
                broadcastMessage({ type: 'ERROR', message: `File ${part} not found in .troot.json at ${currentUrl}` });
                return;
            }
            else {
                if (!currentHashes.directories[part]) {
                    broadcastMessage({ type: 'ERROR', message: `Directory ${part} not found in .troot.json at ${currentUrl}` });
                    return;
                }
                currentUrl = `${currentUrl}${part}/`;
                hashesUrl = `${currentUrl}.troot.json`;
                response = await hashCache.match(hashesUrl);
                cached = true;
                if (!response) {
                    response = await fetch(hashesUrl, {
                        integrity: currentHashes.directories[part],
                        cache: 'no-cache'
                    });
                    if (!response.ok) {
                        broadcastMessage({ type: 'ERROR', message: `Failed to fetch .troot.json at ${hashesUrl}` });
                        return;
                    }
                    cached = false;
                    await hashCache.put(hashesUrl, response.clone());
                }
                try {
                    currentHashes = await response.json();
                    if (!cached)
                        updateGlobalWhitelist(currentHashes);
                }
                catch (err) {
                    if (err instanceof Error) {
                        broadcastMessage({ type: 'ERROR', message: `Failed to parse .troot.json at ${hashesUrl}: ${err.message}` });
                        return;
                    }
                    else {
                        broadcastMessage({ type: 'ERROR', message: `Failed to parse .troot.json at ${hashesUrl}: Unknown error` });
                        return;
                    }
                }
            }
        }
        broadcastMessage({ type: 'ERROR', message: `File ${filePath} not found in .troot.json` });
    }
    catch (err) {
        broadcastMessage({ type: 'ERROR', message: `Error in fetchFileHash: ${err}` });
        return undefined;
    }
}
self.addEventListener('fetch', (event) => {
    if (!ROOT_HASH || event.request.method !== 'GET') {
        event.respondWith(fetch(event.request));
        return;
    }
    event.respondWith((async () => {
        try {
            const url = new URL(event.request.url);
            const isSameOrigin = url.origin === self.location.origin;
            if (!isSameOrigin) {
                if (isUrlWhitelisted(event.request.url)) {
                    return fetch(event.request);
                }
                else if (event.request.destination === 'script' || event.request.destination === 'style') {
                    const message = `Blocked external ${event.request.destination} file`;
                    broadcastMessage({ type: 'ERROR', message });
                    return new Response(message, { status: 403, statusText: 'Forbidden' });
                }
                else
                    return fetch(event.request);
            }
            const filePath = url.pathname;
            if (!filePath || filePath == '/' || filePath == '/index.html' || filePath == '/troot.js') {
                return fetch(event.request);
            }
            let hash = ROOT_HASH;
            if (filePath != `${ROOT_PATH}.troot.json`) {
                hash = await fetchFileHash(filePath) || '';
            }
            if (!hash) {
                const lastSegment = filePath.split('/').pop() || '';
                const ext = lastSegment.includes('.') ? lastSegment.split('.').pop() || '' : '';
                if (!ext) {
                    return fetch(event.request);
                }
                else {
                    const message = `Hash not found for file: ${filePath}`;
                    broadcastMessage({ type: 'ERROR', message });
                    return new Response(message, { status: 404 });
                }
            }
            try {
                const response = await fetch(event.request, {
                    integrity: hash
                });
                return response;
            }
            catch (err) {
                broadcastMessage({ type: 'TAMPERED', message: `Integrity check failed for ${event.request.url}` });
                return new Response('Integrity check failed', { status: 403 });
            }
        }
        catch (err) {
            broadcastMessage({ type: 'ERROR', message: `Fetch failed for ${event.request.url}: ${err}` });
            return new Response(`Fetch failed for ${event.request.url}`, { status: 500 });
        }
    })());
});
