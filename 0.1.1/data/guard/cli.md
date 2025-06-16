# TrustRoot Guard CLI

The TrustRoot Guard CLI is a command-line tool for interacting with the TrustRoot protocol, verifying agent and oracle attestations, and managing developer workflows.

## Features
- Query EAS and Nostr registries for agent/oracle attestations
- Verify source code hashes and Secure Enclave attestations
- Register new agents/oracles
- Audit and validate registry entries
- Integration with TrustRoot SDK for advanced operations
- Hashes a root folder and generates a `.troot.json` file with SHA-256 hashes

## Usage
```sh
npx @trustroot/guard <directory or file path> [--generateHash] [--refreshHash]
```

#### Options:
- `<directory or file path>`: Path to the directory or file you want to hash.
- `--generateHash`: Generates a `.troot.json` file with hash values (default: `false`).
- `--refreshHash`: Recalculates hash values for the specified directory or file (default: `false`).

#### Examples:
1. **Hash a directory**:
   ```bash
   npx @trustroot/guard ./my-directory
   ```

2. **Hash a file**:
   ```bash
   npx @trustroot/guard ./my-file.txt
   ```

3. **Generate a `.troot.json` file for a directory**:
   ```bash
   npx @trustroot/guard ./my-directory --generateHash
   ```

4. **Refresh hash values in `.troot.json`**:
   ```bash
   npx @trustroot/guard ./my-directory --refreshHash
   ```

See the CLI source or run `npx @trustroot/guard --help` for more details and advanced commands.
