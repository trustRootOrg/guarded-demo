# TrustRoot Guard Service Worker

The service worker module provides background verification, message handling, and security enforcement for the TrustRoot Guard browser extension and dApps.

## Features
- Listens for registry queries and attestation requests
- Verifies Secure Enclave attestations in the background
- Handles signed requests and responses for agent/oracle interactions
- Provides DDoS protection by filtering unverified traffic
- Integrates with browser extension and CLI for unified security
- Monitors fetch events, verifies file integrity, and proxies requests with integrity attributes

## Usage
The service worker runs automatically as part of the browser extension or can be integrated into dApps for additional security.

Add the following code to your project to register the service worker:

```javascript
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/troot.js').then(() => {
        console.log('Service Worker registered successfully.');
    }).catch((error) => {
        console.error('Service Worker registration failed:', error);
    });
}
```
