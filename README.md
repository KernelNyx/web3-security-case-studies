# 🛡️ Web3 Security Research & Vulnerability 

**Researcher:** `KernelNyx`  
**Focus:** Web3

---

## 👋 Overview 

This repository contains anonymized **Web3 security research case studies** and standalone **Foundry (`forge test`)** proof-of-concept reproductions derived from production protocol reviews.

Every vulnerability documented here has been stripped of target-identifying details (protocol names, chain IDs, deployed addresses, and live transaction hashes) in compliance with responsible disclosure standards, while preserving **100% of the root-cause mechanics, storage-slot math, invariant violations, and verified remediations**.

---

## 📂 Featured Case Studies & Reproducible PoCs

### 01. [Cross-Chain Bridge Withdrawal Message Replay](./01-cross-chain-bridge-withdrawal-replay/WRITEUP.md) (`Critical`)
* **Vulnerability:** Missing on-chain replay protection breaking the core `1 deposit = 1 payout` accounting invariant.
* **Root Cause:** `receiveTokens()` emits a caller-supplied `externalId` without recording it in storage (`usedExternalIds` absent), allowing transient relayer retries or reverting recipient `receive()` hooks to drain funds or mint unbacked tokens up to the 24-hour rolling daily limit.
* **Reproduction:** [`PoC.t.sol`](./01-cross-chain-bridge-withdrawal-replay/PoC.t.sol)

### 02. [L2 Lending Oracle Staleness & Unset `PriceOracleSentinel`](./02-l2-oracle-staleness-and-unset-sentinel/WRITEUP.md) (`High`)
* **Vulnerability:** Stale oracle price execution paired with a disabled L2 sequencer liveness guard.
* **Root Cause:** An unverified oracle wrapper returns `latestRoundData()` without checking `updatedAt` or deviation bounds, while `PoolAddressesProvider.getPriceOracleSentinel()` is left at `address(0)`—short-circuiting borrow and liquidation liveness checks during feed stalls.
* **Reproduction:** [`PoC.t.sol`](./02-l2-oracle-staleness-and-unset-sentinel/PoC.t.sol)

### 03. [Cross-Build UUPS Storage Layout Collision (ERC-7201 vs. Linear)](./03-cross-build-erc7201-storage-collision/WRITEUP.md) (`Medium / High`)
* **Vulnerability:** Upgradeable proxy storage collision causing an irreversible proxy brick.
* **Root Cause:** Two build trees for the same UUPS contract mix OpenZeppelin `v5.4.0` (ERC-7201 namespaced `AccessControl`, 0 linear slots) and `v4.9.6` (linear `AccessControl`, 50 slots), shifting every state variable by **50 slots** and permanently bricking `_authorizeUpgrade` across builds.
* **Reproduction:** [`PoC.t.sol`](./03-cross-build-erc7201-storage-collision/PoC.t.sol)

---

## ⚡ Quickstart: Running All PoCs Locally

All reproductions are self-contained and require **no external RPC URLs, API keys, or mainnet forks**.

```bash
git clone https://github.com
cd smart-contract-security-research
forge test -vv


### Expected Output
```text
[PASS] test_ExploitReproduces()  // Case Study 01: Duplicate withdrawal payout from single deposit
[PASS] test_FixPreventsExploit() // Case Study 01: usedExternalIds blocks replay
[PASS] test_ExploitReproduces()  // Case Study 02: Wrongful liquidation & bad debt on stale feed
[PASS] test_FixPreventsExploit() // Case Study 02: updatedAt freshness & sentinel checks revert
[PASS] test_ExploitReproduces()  // Case Study 03: 50-slot shift bricks UUPS upgrade permanently
[PASS] test_FixPreventsExploit() // Case Study 03: IStorageLayout guard blocks incompatible upgrade
```

---

