# 5. Value Proposition

## 5.1 Key Benefits
- **Verifiable Trust:** Immutable registries ensure transparency and authenticity, eliminating blind trust in agent interactions.
- **Enhanced Security:** Secure Enclave technology provides tamper-proof execution, surpassing SSL/TLS capabilities.
- **DDoS Protection:** Signed requests via Nostr key pairs filter unverified traffic, ensuring reliability.
- **Incentivized Accountability:** $TROOT staking and the insurance fund align incentives for quality and trust.
- **Ecosystem Scalability:** As a protocol-only layer, TrustRoot enables third-party projects to build diverse solutions, from DeFi oracles to gaming agents.

## 5.2 Use Cases

### 5.2.1 TrustRoot Oracles: Secure DeFI Price Feeds
**Overview:** TrustRoot Oracles, built by third-party projects leveraging the TrustRoot protocol, provide secure, transparent price feeds for DeFi protocols, addressing critical vulnerabilities in existing solutions like manipulation risks and lack of transparency. While high-value oracles are registered on the EAS Registry for maximum security, lower-value oracles can use the Nostr Registry for cost efficiency.

**Use Case Description:**
- **Scenario:** A DeFi lending protocol (e.g., similar to Aave) requires an ETH/USD price feed to calculate collateral ratios for loans. The protocol wants a price feed that is secure, tamper-proof, and verifiable to protect users from oracle manipulation, which caused over $100M in losses in 2023.
- **Third-Party Project:** A project called “TrustOracle” builds a TrustRoot Oracle to deliver the ETH/USD price feed, leveraging TrustRoot’s protocol for certification and security.

**How TrustRoot Enables This:**
- **Development and Auditing:** TrustOracle’s developers build the oracle, which aggregates ETH/USD price data from multiple sources (e.g., premium APIs) and runs in a Secure Enclave. They pay TrustRoot Auditors 500 $TROOT for code review, ensuring compliance with TrustRoot’s standards.
- **Certification:** Given the high-value nature of a DeFi price feed, the developers and auditors stake 500 $TROOT each and pay an ETH fee to register the oracle in the EAS Registry on Optimism, achieving TrustRoot Certification. (For a lower-value oracle, they could stake 100 $TROOT each and register on the Nostr Registry, incurring no ETH fee.) The oracle generates a Nostr key pair in the Secure Enclave for signed requests.
- **Hosting:** A hosting provider runs the certified oracle in a Secure Enclave, earning 1,000 $TROOT during the Launch Period (months 1-6). TrustOracle shares 10% of its user fees with the provider, ensuring sustainability.
- **Usage by DeFi Protocol:** The lending protocol queries the TrustRoot Oracle for ETH/USD prices, paying TrustOracle in its native token ($TORC) and a small $TROOT fee (10 $TROOT per 1,000 queries) to access the EAS Registry. TrustOracle offers a 20% discount on fees if paid in $TROOT, encouraging cross-token integration.
- **Verification:** The protocol uses the Attestation Query Interface to verify the oracle’s TrustRoot Certification, confirming its source code hash, Secure Enclave attestation, and community validation. End-users can also verify the oracle via the TrustRoot Browser Extension, ensuring transparency.
- **Rewards and Accountability:** The oracle’s usage (e.g., 10,000 queries in a month) generates $TROOT rewards for TrustOracle’s developers and auditors (60% usage, 30% stake, 10% governance votes). The staked $TROOT acts as an insurance fund: if the oracle delivers inaccurate data (e.g., >5% deviation), governance can slash the stake and compensate affected users.

**Benefits:**
- **Security:** Secure Enclave ensures tamper-proof execution, reducing manipulation risks compared to existing oracles like Chainlink, which rely on node operator trust.
- **Transparency:** The EAS Registry provides an immutable record of the oracle’s source code hash and attestations, verifiable by protocols and users, while the Nostr Registry offers a cost-effective alternative for less critical use cases.
- **DDoS Protection:** Signed requests via Nostr key pairs filter unverified traffic, ensuring reliability under high load.
- **Trust and Accountability:** $TROOT staking and the insurance fund align incentives, giving users confidence in the oracle’s reliability, with higher stakes for EAS-registered oracles providing greater assurance.
- **Impact:** TrustRoot Oracles enable DeFi protocols to operate with greater security and trust, protecting users from oracle-related exploits. The dual-registry approach ensures accessibility for a wide range of use cases, fostering adoption of TrustRoot-based solutions.

### 5.2.2 Privacy-Preserving Feeds
**Overview:** TrustRoot enables encrypted data feeds for institutional DeFi, ensuring privacy and verifiability, addressing the gap in public oracle solutions.

### 5.2.3 Autonomous Agents
**Overview:** Agents for trading, governance, or social moderation interact only with certified counterparties, eliminating blind trust.

### 5.2.4 Cross-Chain Interoperability
**Overview:** TrustRoot facilitates secure data delivery across blockchains, leveraging Nostr relays for fast, tamper-proof communication.
