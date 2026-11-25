# Cross-Chain Token Bridge — Incompatible UUPS Storage Layouts Across Two Build Trees



---

## 1. Summary & Severity

A cross-chain token bridge was deployed to two execution environments from a
**single repository containing two independent build trees** for the same
contracts — same contract names, same ABIs, same events, **different storage
layouts**.

The two trees resolve different major versions of OpenZeppelin's
`AccessControlUpgradeable`:

| Build | Dependency resolution | Compiler | `AccessControlUpgradeable` storage |
|---|---|---|---|
| A | npm-managed, OZ `^4.9.5` | solc 0.8.30 | **linear** — 1 slot + `__gap[49]` = 50 slots |
| B | vendored sources, OZ `5.4.0` | solc 0.8.24 | **namespaced (ERC-7201)** — 0 linear slots |

Because `AccessControlUpgradeable` sits in the inheritance chain **before**
`ReentrancyGuardUpgradeable` and before every bridge state variable, the entire
bridge state on Build B is shifted **exactly 50 slots** relative to Build A.

Behind a UUPS proxy, the two builds are therefore **not interchangeable**. An
upgrade across the boundary silently succeeds and then orphans the role registry
and every state pointer. `_authorizeUpgrade` itself is role-gated, so once roles
are orphaned **the proxy can never be upgraded again** — an unrecoverable freeze
of all assets held by the contract.

**Severity: Medium.** The impact is total and irreversible (permanent lock of
all bridge-held assets), but the trigger is a privileged administrative action.
There is no unprivileged path to reach the broken state, and both deployments were
internally consistent at the time of reporting. Rated Medium rather than High on
that basis: severity follows the trigger surface, not the blast radius alone.

---

## 2. Root Cause Analysis

### 2.1 Two build trees, one contract

The repository shipped two independent build trees. They compiled **the same**
`Bridge.sol` and `Mapper.sol` sources, with identical inheritance chains:

```solidity
contract Bridge is Initializable, UUPSUpgradeable, AccessControlUpgradeable,
                    ReentrancyGuardUpgradeable, IBridge
```

Tree A resolved OpenZeppelin from npm (`^4.9.5`). Tree B vendored its
dependencies as source files — and while *everything else* vendored was 4.9.x
(`Initializable` 4.9.0, `UUPSUpgradeable` 4.9.x, `ERC1967UpgradeUpgradeable`
4.9.x, `ReentrancyGuardUpgradeable` 4.9.x), the two
`AccessControlUpgradeable.sol` copies were silently replaced with **v5.4.0**.

Tree B therefore mixed **one** 5.x dependency into an otherwise 4.9 dependency
set. That single file is the entire root cause.

### 2.2 The OpenZeppelin storage divergence

OZ 4.9 `AccessControlUpgradeable` stores roles linearly:

```solidity
mapping(bytes32 => RoleData) private _roles;   // 1 slot
uint256[49] private __gap;                     // 49 slots
```

**Total: 50 linear slots.**

OZ 5.x `AccessControlUpgradeable` relocates the same data to an ERC-7201
namespaced location:

```solidity
bytes32 private constant AccessControlStorageLocation =
    0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

struct AccessControlStorage { mapping(bytes32 => RoleData) _roles; }

function _layout() private pure returns (AccessControlStorage storage $) {
    assembly { $.slot := AccessControlStorageLocation }
}
```

**Total: 0 linear slots.** The namespaced slot is derived from
`keccak256("openzeppelin.storage.AccessControl") - 1`, masked to clear the low
byte, and cannot collide with sequentially-assigned storage.

### 2.3 The 50-slot offset (compiler output)

Both variants were compiled and `storageLayout` was dumped.

**Build A** — solc 0.8.30, OZ 4.9.6:

```
_initialized            0   uint8          }
_initializing           0   bool           } slot 0
__gap                   1   uint256[50]    } ContextUpgradeable
__gap                  51   uint256[50]    } ERC165Upgradeable
__gap                 101   uint256[50]    } ERC1967UpgradeUpgradeable
__gap                 151   uint256[50]    } UUPSUpgradeable
_roles                201   mapping        <-- LINEAR AccessControl
__gap                 202   uint256[49]
_status               251   uint256        <-- ReentrancyGuard
__gap                 252   uint256[49]
gasAccumulated        301   uint256
Mapper                302   address
usedHashes            303   mapping
dailyLimits           304   mapping
dailyVolumes          305   mapping
__gap                 306   uint256[50]
```

**Build B** — solc 0.8.24, vendored OZ 5.4 AccessControl:

```
_initialized            0   uint8
_initializing           0   bool
__gap                   1   uint256[50]
__gap                  51   uint256[50]
__gap                 101   uint256[50]
__gap                 151   uint256[50]
                        <- AccessControl is NAMESPACED: consumes ZERO slots
_status               201   uint256        <-- ReentrancyGuard shifts DOWN 50
__gap                 202   uint256[49]
gasAccumulated        251   uint256
Mapper                252   address
usedHashes            253   mapping
dailyLimits           254   mapping
dailyVolumes          255   mapping
__gap                 256   uint256[50]
```

**Every variable declared after `AccessControlUpgradeable` is displaced by
exactly 50 slots.** Note that the commonly-assumed "one slot shift" is wrong by a
factor of 50: 4.9 contributes the mapping *and* its 49-slot gap.

`Mapper.sol` shifts identically — `mapCounter` is at 251 in Build A and 201 in
Build B.

### 2.4 Why inheritance order makes this fatal

`AccessControlUpgradeable` is inherited **before** `ReentrancyGuardUpgradeable`.
Solidity assigns storage to base contracts first (most-base-first along the C3
linearization), so anything inherited after AccessControl — including the
reentrancy guard — and anything declared in the contract body is offset by
whatever AccessControl consumed. Swapping AccessControl's storage model
therefore does not merely break role lookups; it **re-points every subsequent
variable** to a slot belonging to a different variable.

---

## 3. Broken Invariant & Attack Scenario

### 3.1 The invariant

> A UUPS implementation upgrade must preserve the meaning of every storage slot
> it and its successors read.

Both builds independently satisfy "my implementation reads the slots I wrote."
Neither satisfies the invariant **across** builds. The repository contained no
layout assertion, no CI diff, and no shared base to catch this.

### 3.2 Direction 1: namespaced proxy → linear implementation

An implementation compiled from Build A is installed on a proxy whose state was
written by Build B.

- `hasRole(MULTISIG_ROLE, …)` reads the `_roles` mapping at **slot 201**. On a
  Build-B proxy, slot 201 holds `ReentrancyGuard._status = 1`, and no role entry
  was ever written at `keccak256(role . 201)`. **`hasRole` returns `false`.**
- `_authorizeUpgrade` is guarded by `onlyRole(MULTISIG_ROLE)`. The role is
  orphaned, so **every subsequent upgrade reverts**. The proxy is permanently
  welded to a broken implementation.
- `Mapper` is read from **slot 302**, which is unused gap on a Build-B proxy.
  It resolves to `address(0)`; every `mapInfo()` call reverts.
- `gasAccumulated` is read from **slot 301**, likewise zero — accounting lost.
- `_status` (reentrancy guard) is read from **slot 251**, which holds the old
  `gasAccumulated` value. The guard is now poisoned with an arbitrary large
  integer, silently changing the contract's reentrancy semantics.

### 3.3 Direction 2: linear proxy → namespaced implementation

Symmetric and equally destructive:

- `Mapper` read from **slot 252** → unused gap → `address(0)` → bricked.
- `gasAccumulated` read from **slot 251** → holds `_status = 1` → corrupted.
- `_status` read from **slot 201** → bare mapping base → the guard is
  **uninitialised (0)** instead of the expected `NOT_ENTERED (1)`.

### 3.4 Why this is a design defect, not merely operator error

The obvious remediation *is* the trigger. Every other vendored dependency in
Tree B was already 4.9 — the 5.4 `AccessControlUpgradeable` was the single
outlier. The natural maintenance action, *"align the second tree to 4.9 like
everything else"*, is precisely the change that produces a layout-incompatible
artifact. Likewise, the repository ships two divergent trees for one contract
with nothing preventing an implementation from one tree being installed on a
proxy created from the other, so any future "sync the trees" or "unify the
build" change carries the same risk.

The trigger is therefore a **routine action performed correctly, producing an
irreversible outcome** — the defining shape of a design defect rather than a
mistake by an operator.

### 3.5 Who can reach the broken state

`_authorizeUpgrade` is `onlyRole(MULTISIG_ROLE)`. There is **no** unprivileged
path in the codebase: no public `delegatecall`, no arbitrary-call entry point, no
unprotected `upgradeTo`. The defect is only reachable by the role holder.

This is stated explicitly because it bounds the severity: a privileged actor can
already harm the system deliberately, but the powers they hold are either
**reversible** (`setMapper`, `setDailyLimit`) or require **malicious intent**
(deploying a hostile implementation). This defect is the one path where a
*routine, correct* action yields an **irreversible** loss with **zero recovery**,
because `_authorizeUpgrade` reverts forever once the roles are orphaned.
Accidental-and-irreversible is a distinct risk class from
deliberate-and-unilateral.

---

## 4. Verification Methodology

All verification was read-only: no transactions were signed, no state was
modified.

### 4.1 Source

Vendored dependency headers were inspected directly. Tree B's
`AccessControlUpgradeable.sol` carried the header
`// OpenZeppelin Contracts (last updated v5.4.0) (access/AccessControl.sol)` and
defined `AccessControlStorageLocation` as the ERC-7201 constant. Every sibling
dependency in the same directory was 4.9.x. Tree A imported from the npm
package.

### 4.2 Compiler storage layouts

Both `Bridge.sol` variants and both `Mapper.sol` variants were compiled with
their respective solc versions, requesting the `storageLayout` output. The
resulting tables (§2.3) are compiler-emitted — not hand-derived. This step is
essential: hand-derivation had initially under-estimated the offset by 50x
because the 49-slot `__gap` inside 4.9's AccessControl was omitted from the
mental model.

### 4.3 Deployed bytecode markers

The ERC-7201 storage-location constant is embedded in deployed runtime code only
when a contract was compiled against a 5.x AccessControl. Grepping the deployed
bytecode for `02dd7bc7…626800`:

- Build B Bridge + Mapper implementations: **present**
- Build A Bridge + Mapper implementations: **absent**

Runtime sizes also differed (14892/9059 vs 14889/9052), consistent with the
source-level divergence.

### 4.4 Live slot reads

The EIP-1967 implementation slot was read from each proxy to confirm which
implementation was actually serving traffic, then identical slot indices were
read from both Bridge proxies:

| slot | meaning under Build A | Build A value | meaning under Build B | Build B value |
|---|---|---|---|---|
| 201 | `_roles` (mapping base) | 0 | `_status` | 1 |
| 251 | `_status` | 1 | `gasAccumulated` | live value |
| 252 | unused gap | 0 | `Mapper` | populated address |
| 301 | `gasAccumulated` | live value | unused gap | 0 |
| 302 | `Mapper` | populated address | unused gap | 0 |

The decisive observation: **slot 252 holds a populated Mapper address on one
chain and zero on the other, while slot 302 does the exact reverse.** The same
slot index cannot simultaneously be "where Mapper lives" and "empty" under a
shared layout. This is direct, non-inferential evidence of divergence, and it
requires no upgrade to observe.

### 4.5 Upgrade history

To establish that the failure had not already occurred:

- **Build B target:** the event index returns exactly **one** `Upgraded` event
  per proxy — emitted at deployment — and in both cases the address in that event
  is identical to the currently installed implementation. Deploy and initialise
  happened in a single transaction (the `Upgraded` log is immediately followed by
  `RoleGranted`).
- **Build A target:** a full-chain `eth_getLogs` scan for the `Upgraded(address)`
  topic from genesis to head (~2.57M blocks, chunked to the RPC's 100k max range,
  zero failed requests) returned **zero** events for either proxy. The only two
  `Upgraded` events on the entire chain belonged to unrelated contracts. The
  EIP-1967 implementation slot was additionally confirmed byte-identical at
  genesis and at head.

Conclusion: **the collision had never fired.** The divergence exists at deploy
time, not from any upgrade. Stated plainly in the report rather than omitted —
it is what makes the severity assessment honest.

### 4.6 Local proof of concept

`PoC.t.sol` reproduces the entire failure mode offline, with no fork and no RPC:
two minimal implementations that mirror the two compiler-emitted layouts, a UUPS
proxy, and a test that performs the cross-layout upgrade and asserts every
consequence (orphaned roles, `Mapper == address(0)`, lost accounting, poisoned
guard, permanent unupgradability, stranded balance). A second test installs a
layout-version guard and proves the incompatible upgrade is rejected with state
fully intact.

---

## 5. Remediation

### 5.1 Make the build trees agree

Pin **one** OpenZeppelin major version across every tree. If the deployed
contract is currently on the 4.9 (linear) layout, the 5.4 vendored copy must be
reverted to 4.9.x — not upgraded, and not "aligned upward". Upgrading a live
proxy to 5.x requires a deliberate storage migration, not a dependency bump.

### 5.2 Eliminate the duplicate-source problem

A vendored dependency tree that can silently diverge from the npm-managed tree is
the underlying enabler. Either:

- consume OpenZeppelin from a single package manager for every target, or
- vendor with a checksum lockfile and a CI job that diffs vendored files against
  the pinned upstream release.

### 5.3 Enforce layout compatibility in CI

Add a gate that fails any change which alters the storage layout of an
upgradeable contract:

```bash
forge inspect Bridge storage-layout --pretty > /tmp/new.txt
diff -u .storage-layout/bridge.txt /tmp/new.txt
```

The OpenZeppelin Upgrades plugin performs an equivalent check
(`validateUpgrade`) for Hardhat-based trees. Additionally, record the compiled
layout for each deployment alongside its deployment artifact so a future upgrade
can be validated against the *deployed* layout, not the current source.

### 5.4 Add a runtime layout guard

Belt-and-braces: have `_authorizeUpgrade` refuse implementations that declare a
different storage-layout identifier (demonstrated in `test_FixPreventsExploit`):

```solidity
function upgradeTo(address newImpl) external {
    require(hasRole(MULTISIG_ROLE, msg.sender), "missing role");
    require(
        IStorageLayout(newImpl).STORAGE_LAYOUT_ID() == STORAGE_LAYOUT_ID(),
        "incompatible storage layout"
    );
    _setImplementation(newImpl);
}
```

This converts a silent, permanent brick into a loud, recoverable revert.

### 5.5 If a cross-major migration is genuinely required

Do not upgrade the proxy in place. Deploy a new proxy on the target layout under
the 5.x build, migrate state through a one-shot migration contract that reads
each variable at its **documented source slot** and writes it to its destination
slot, pause the old proxy, and retire it. The migration must be rehearsed against
a fork or a state snapshot before execution.

---

## Appendix — Repository layout

```
port_1/
├── WRITEUP.md   this document
└── PoC.t.sol    self-contained Foundry test (no RPC, no fork)
```

Run the PoC:

```bash
forge init --force layout-poc && cd layout-poc
cp ../PoC.t.sol test/PoC.t.sol
forge test -vv
```

---

## Verification status

Compiled and executed with Foundry 1.10.0 / solc 0.8.24 — no fork, no RPC:

```
Compiler run successful!
[PASS] test_ExploitReproduces()  (gas: 387834)
[PASS] test_FixPreventsExploit() (gas: 941883)
2 tests passed, 0 failed
```

`forge inspect` on the mocks reproduces the documented offsets exactly:

```
BridgeNamespaced  -> _status 201, __gapGuard 202, gasAccumulated 251, Mapper 252
BridgeLinear      -> _roles  201, __gapAccessControl 202, _status 251,
                     __gapGuard 252, gasAccumulated 301, Mapper 302
```

The 50-slot displacement between `_status` (201 vs 251) and between
`gasAccumulated`/`Mapper` (251/252 vs 301/302) is therefore confirmed by both the
original production builds and the offline reproduction.
