# TrustRoot Guard Extension

The TrustRoot Guard browser extension provides real-time verification of agents, oracles, and Web3 services directly in the browser. It integrates with the TrustRoot registries and Secure Enclave attestations to ensure users interact only with trusted, tamper-proof services.

## Features
- Verifies website and dApp integrity using source code hashes
- Displays TrustRoot Certification status in the browser UI
- Warns users of unverified or tampered services
- Integrates with Nostr and EAS registries for attestation lookups
- Supports Chrome, Firefox, and Chromium-based browsers
- Verifies the root hash of `index.html` for enhanced security

## Getting Started
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `cli/extension` folder.

Click the TrustRoot Guard icon to view verification status and details. Use the popup to inspect registry attestations and certification proofs.
