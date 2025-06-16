"use strict";
function updateServiceWorkerRootHash(rootHash) {
    if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({
            type: 'SET_ROOT_HASH',
            rootHash,
        });
    }
}
const RootServiceHash ="sha256-ePLgmQ8YwBGRdJGrXsV8DgEmizQIco34aJxSurIfPpE=";
const RootHash = (document.documentElement.getAttribute('troothash') || '');
let rootJsonHash = RootHash;
let rootJsonUrl = '/.troot.json';
;
function showSecurityWarning(message, state) {
    window.postMessage({ type: state, text: message }, "*");
    let elm = document.getElementById('securityWarningDialogDynamic');
    if (elm) {
        elm.style.display = 'block';
        return;
    }
    const dialog = document.createElement('div');
    dialog.id = 'securityWarningDialogDynamic';
    dialog.style.position = 'fixed';
    dialog.style.top = '20%';
    dialog.style.left = '50%';
    dialog.style.transform = 'translate(-50%, -50%)';
    dialog.style.backgroundColor = '#ff4d4d';
    dialog.style.color = 'white';
    dialog.style.padding = '20px';
    dialog.style.border = '2px solid #cc0000';
    dialog.style.borderRadius = '10px';
    dialog.style.fontFamily = 'Arial, sans-serif';
    dialog.style.boxShadow = '0 0 15px rgba(204, 0, 0, 0.7)';
    dialog.style.zIndex = '10000';
    dialog.style.width = '300px';
    dialog.style.textAlign = 'center';
    const title = document.createElement('h2');
    title.style.marginTop = '0';
    title.textContent = 'Security Warning';
    dialog.appendChild(title);
    const messageElm = document.createElement('p');
    messageElm.textContent = message;
    dialog.appendChild(messageElm);
    const button = document.createElement('button');
    button.style.backgroundColor = 'white';
    button.style.color = '#cc0000';
    button.style.border = 'none';
    button.style.padding = '10px 20px';
    button.style.borderRadius = '5px';
    button.style.cursor = 'pointer';
    button.style.fontWeight = 'bold';
    button.textContent = 'Dismiss';
    button.onclick = function () {
        dialog.style.display = 'none';
    };
    dialog.appendChild(button);
    document.body.appendChild(dialog);
}
const GRAPHQL_ENDPOINT = "https://sepolia.easscan.org/graphql";
const SCHEMA_UID = "0x591804346471218c4e9bae660974bd2654dc90df3ccba71bc0a5ab902132dd50";
function decodeAttestationData(data) {
    try {
        const hexData = data.startsWith("0x") ? data.slice(2) : data;
        const indexHash = "0x" + hexData.slice(0, 64);
        const assetsHash = "0x" + hexData.slice(64, 128);
        const stringOffset = parseInt(hexData.slice(128, 192), 16) * 2;
        const stringLength = parseInt(hexData.slice(stringOffset, stringOffset + 64), 16) * 2;
        const stringData = hexData.slice(stringOffset + 64, stringOffset + 64 + stringLength);
        const bytePairs = stringData.match(/.{1,2}/g);
        const commitUrl = bytePairs
            ? new TextDecoder().decode(Uint8Array.from(bytePairs.map(byte => parseInt(byte, 16))))
            : "";
        return { indexHash, assetsHash, commitUrl };
    }
    catch (error) {
        if (error instanceof Error) {
            console.error("Error decoding attestation data:", error.message);
        }
        else {
            console.error("Error decoding attestation data:", error);
        }
        return null;
    }
}
async function queryAttestation(indexHash, assetsHash) {
    const query = `
    query Attestations($schemaId: String!) {
      attestations(where: { schemaId: { equals: $schemaId } }, take: 100) {
        id
        attester
        recipient
        data
        time
        expirationTime
        revocationTime
        revocable
      }
    }
  `;
    try {
        const response = await fetch(GRAPHQL_ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "omit",
            cache: "no-cache",
            redirect: "follow",
            referrerPolicy: "no-referrer",
            body: JSON.stringify({
                query,
                variables: { schemaId: SCHEMA_UID },
            }),
        });
        const result = await response.json();
        if (result.errors) {
            console.error("GraphQL errors:", JSON.stringify(result.errors));
        }
        const attestations = result.data.attestations;
        let revoked = undefined;
        for (const attestation of attestations) {
            const decoded = decodeAttestationData(attestation.data);
            if (decoded) {
                if (indexHash.toLowerCase() === decoded.indexHash.toLowerCase() && assetsHash.toLowerCase() === decoded.assetsHash.toLowerCase()) {
                    if (attestation.revocationTime) {
                        revoked = {
                            id: attestation.id,
                            attester: attestation.attester,
                            recipient: attestation.recipient,
                            data: decoded,
                            time: attestation.time,
                            expirationTime: attestation.expirationTime,
                            revocationTime: attestation.revocationTime,
                            revocable: attestation.revocable
                        };
                    }
                    else {
                        return {
                            id: attestation.id,
                            attester: attestation.attester,
                            recipient: attestation.recipient,
                            data: decoded,
                            time: attestation.time,
                            expirationTime: attestation.expirationTime,
                            revocationTime: attestation.revocationTime,
                            revocable: attestation.revocable
                        };
                    }
                }
            }
            else {
                console.warn("Failed to decode attestation data for attestation:", attestation);
            }
        }
        return revoked;
    }
    catch (error) {
        console.error("Error in verifyAttestation:", error);
        return;
    }
}
function normalizeHtmlForHashing(html) {
    html = html.replace(/^\s*<!doctype[^>]*>\s*/i, '');
    html = html.replace(/<!--[\s\S]*?-->/g, '');
    html = html.replace(/<([a-zA-Z0-9\-]+)([^>]*)>/g, (_, tag, attrs) => {
        tag = tag.toLowerCase();
        const attrMap = {};
        if (attrs) {
            const attrRegex = /\s*([a-zA-Z0-9\-_:\.]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*)))?/gi;
            let attrMatch;
            while ((attrMatch = attrRegex.exec(attrs))) {
                const [, name, quoted1, quoted2, unquoted] = attrMatch;
                const value = quoted1 ?? quoted2 ?? unquoted ?? null;
                attrMap[name.toLowerCase()] = value;
            }
        }
        const sortedAttrs = Object.keys(attrMap)
            .sort()
            .map((key) => attrMap[key] === null ? key : `${key}="${attrMap[key]}"`)
            .join(' ');
        return `<${tag}${sortedAttrs ? ' ' + sortedAttrs : ''}>`;
    });
    html = html.replace(/\s+/g, '');
    html = html.replace(/\r?\n/g, '');
    html = html.replace(/'/g, '"');
    html = html.toLocaleLowerCase();
    return html;
}
async function computeHash(data) {
    const encoder = new TextEncoder();
    const buffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return '0x' + hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sha256To0xHash(value) {
    let binaryString;
    try {
        binaryString = atob(value);
    }
    catch (error) {
        throw new Error("Failed to decode base64 string");
    }
    const hashBuffer = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        hashBuffer[i] = binaryString.charCodeAt(i);
    }
    if (hashBuffer.length !== 32) {
        throw new Error("Invalid SHA-256 hash: must be 32 bytes");
    }
    const hexHash = Array.from(hashBuffer)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    return `0x${hexHash}`;
}
async function registerServiceWorker() {
    try {
        if (!RootHash || !('serviceWorker' in navigator))
            return { success: true };
        const parts = RootHash.split('/sha256-');
        if (parts.length === 2) {
            rootJsonUrl = `/${parts[0]}/.troot.json`;
            rootJsonHash = 'sha256-' + parts[1];
        }
        navigator.serviceWorker.addEventListener('message', (event) => {
            const message = event.data;
            if (message.type === 'UPDATE') {
                const customEvent = new CustomEvent('trustRootUpdate', {
                    detail: message.message,
                });
                window.dispatchEvent(customEvent);
            }
            else if (message.type === 'ERROR') {
                const customEvent = new CustomEvent('trustRootError', {
                    detail: message.message,
                });
                window.dispatchEvent(customEvent);
            }
            else if (message.type === 'TAMPERED') {
                const customEvent = new CustomEvent('trustRootTampering', {
                    detail: message.message,
                });
                window.dispatchEvent(customEvent);
                showSecurityWarning(message.message, 'TAMPERED');
            }
        });
        let scope = '/';
        let registeredService = await navigator.serviceWorker.getRegistration(scope);
        if (registeredService) {
            if (navigator.serviceWorker.controller) {
                updateServiceWorkerRootHash(RootHash);
                return { success: true };
            }
            else {
                await registeredService.unregister();
            }
        }
        if (!RootServiceHash) {
            throw new Error(`Service worker hash not found`);
        }
        let response = await fetch('/troot.js', {
            integrity: RootServiceHash,
            cache: 'no-cache',
        });
        if (!response.ok) {
            throw new Error(`Failed to fetch service worker script: ${response.status} ${response.statusText}`);
        }
        await navigator.serviceWorker.register('/troot.js', { scope });
        if (!navigator.serviceWorker.controller) {
            let timeout = setTimeout(() => {
                window.location.reload();
            }, 10);
            await new Promise((resolve) => {
                const onControllerChange = () => {
                    clearTimeout(timeout);
                    navigator.serviceWorker.removeEventListener('controllerchange', onControllerChange);
                    resolve();
                };
                navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);
            });
        }
        updateServiceWorkerRootHash(RootHash);
        return { success: true };
    }
    catch (error) {
        return { success: false, error: error.message || 'Unknown error' };
    }
}
function appendScript(src, integrity) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        if (integrity) {
            script.integrity = integrity;
            script.crossOrigin = 'anonymous';
            script.async = true;
        }
        script.onload = () => {
            resolve();
        };
        script.onerror = () => {
            reject(new Error(`Failed to load script: ${src}`));
        };
        document.body.appendChild(script);
    });
}
async function loadLibs() {
    const response = await fetch(rootJsonUrl, {
        integrity: rootJsonHash,
        cache: 'no-cache',
    });
    if (!response.ok) {
        throw new Error(`Failed to fetch .troot.json: ${response.status} ${response.statusText}`);
    }
    const hashes = await response.json();
    let libs = hashes.libs;
    if (Array.isArray(libs)) {
        for (const lib of libs) {
            if (lib.script) {
                const scriptElm = document.createElement('script');
                scriptElm.innerHTML = lib.script;
                document.body.appendChild(scriptElm);
            }
            else if (lib.src) {
                await appendScript(lib.src, lib.integrity);
            }
        }
    }
}
window.addEventListener('DOMContentLoaded', async () => {
    try {
        let result = await registerServiceWorker();
        if (result.success) {
            if (RootHash) {
                let assetHash = await sha256To0xHash(RootHash.split('sha256-')[1]);
                let indexHash = await computeHash(normalizeHtmlForHashing(document.documentElement.outerHTML));
                let attestation = await queryAttestation(indexHash, assetHash);
                if (attestation && attestation.revocationTime) {
                    showSecurityWarning(`This page has been revoked by the attester!`, 'REVOKED');
                    return;
                }
            }
            await loadLibs();
        }
    }
    catch (error) {
        console.error('Error registering TrustRoot service worker:', error);
    }
});
