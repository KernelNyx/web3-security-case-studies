# Cross-Chain Bridge: Withdrawal Message Replay

**A missing message-consumption check allowed a single inbound bridge message to be
paid out repeatedly. Confirmed in production: one deposit produced two payouts.**

---

## 1. Summary & Severity

**Target.** A multi-chain cross-chain token bridge. Two smart contracts make up the core:

- a **route registry** that stores one-directional token routes between chains
  (origin chain, target chain, deposit type, withdraw type, origin token, target token), and
- a **bridge** that holds value and executes both sides of a transfer: it locks or burns
  the user's asset on the source chain, and unlocks or mints the corresponding asset on the
  destination chain.

The bridge is deployed as a **UUPS proxy** with a shared implementation, and is deployed at
the **same deterministic address on every supported EVM chain**. Access is split across three
roles: `MULTISIG_ROLE` (upgrades, routing changes, liquidity), `EMERGENCY_ROLE` (pause,
gas sweep, liquidity top-ups) and `RELAYER_ROLE` (executes inbound messages on the
destination chain).

**Severity: Critical.**

- Direct, repeatable loss of contract-held user funds.
- Violates the defining safety property of a lock/mint bridge (**one message, one payout**).
- **Already realised in production**: a single deposit was paid out twice, verifiable from
  public chain state alone.
- Not size-limited by the trigger. The ceiling is the per-relayer daily cap, and one route
  type (`WithdrawType.Mint`) **creates tokens that were never collateralised**.
- Remediation is a small, well-understood mapping plus a one-line storage-gap adjustment.

**Why it matters more than the demonstrated amount.** The observed loss was one
test-sized transfer. The *mechanism* is unbounded: the same call executed as many times as
the daily cap allows, reset every 24 hours, on every chain the bridge is deployed to. On the
mint route there is no collateral to run out of — the bridge simply issues new supply.

---

## 2. Root Cause Analysis

### 2.1 The asymmetry

The deposit path is correctly protected against replay. Every deposit is reduced to a unique
hash and marked single-use before any external call:

```solidity
bytes32 _hash = _validateECDSA({ ... });
usedHashes[_hash] = true;                 // deposit is single-use
```

The withdrawal path has **no equivalent mechanism**. The inbound message carries an
`externalId`, which is:

- accepted as an arbitrary caller-supplied `bytes32`,
- written into the `Withdrawal` event,
- **never stored, never checked, never consumed.**

There is no `usedExternalIds` mapping, no nonce, no executed-bitmap. Idempotency of the
payout is delegated entirely to off-chain backend bookkeeping.

### 2.2 The vulnerable function

```solidity
function receiveTokens(ReceiveTokensParams calldata receiveTokensParams)
    external
    nonReentrant
    onlyRole(RELAYER_ROLE)
{
    address relayer = _msgSender();
    IMapper.MapInfo memory _mapInfo = _getMapInfo({ mapId: receiveTokensParams.mapId });

    require(_mapInfo.isAllowed, "route disabled");
    require(_mapInfo.depositType == IMapper.DepositType.None, "not a payout route");

    bytes32 tokenAddress = _mapInfo.isCoin ? bytes32(0) : _mapInfo.targetTokenAddress;
    _checkAndUpdateDailyLimit(tokenAddress, relayer, receiveTokensParams.amount);

    // payout: native coin, safeTransfer, or mint()
    if (_mapInfo.withdrawType == IMapper.WithdrawType.Mint) {
        IERC20Mintable(...).mint({ to: recipient, amount: receiveTokensParams.amount });
    } else {
        _executeTokenTransfer({ ... });
    }

    emit Withdrawal({
        ...
        externalId: receiveTokensParams.externalId,   // <- used ONLY here
        ...
    });
}
```

The `externalId` performs no security function. Nothing in this function records that
*this* message has already been executed, so every subsequent submission passes every check
and pays out again.

### 2.3 Why the existing guards do not cover it

- **`onlyRole(RELAYER_ROLE)`** constrains *who* may call, not *how many times* a given
  message may be executed. It is the only gate on this function.
- **`nonReentrant`** prevents nested calls inside a single transaction. It says nothing about
  sequential replays across separate transactions, which is the actual attack.
- **`_checkAndUpdateDailyLimit`** caps *volume per day*, so a replay is throttled — but it is
  still profitable, and the cap resets every 24 hours.
- **`usedHashes`** protects the deposit hash only. Withdrawals have no analogue.
- **Off-chain deduplication** is an operational assumption, not a contract guarantee —
  and production data shows it already failed.

### 2.4 Storage layout and why the fix is upgrade-safe

The bridge inherits a standard upgradeable stack. Actual slot assignment:

```
slot 0        uint8  _initialized  |  bool _initializing        (packed)
slot 1        mapping(bytes32 => RoleData) _roles
slot 2        uint256 _status
slots 3..51   uint256[49] __gap                                  (reentrancy guard tail)
--- application state ---
slot 52       uint256 gasAccumulated
slot 53       IRouteRegistry registry
slot 54       mapping(bytes32 => bool) usedHashes
slot 55       mapping(bytes32 => uint256) dailyLimit
slots 56..105 uint256[50] __gap
```

Adding a new mapping *after* `dailyLimit` and reducing the application gap from 50 to 49
keeps the total footprint identical (still ends at slot 105) and leaves slots 0 through 55
untouched, so an in-place proxy upgrade preserves all existing state:

```
slots 0..55   unchanged
slot 56       mapping(bytes32 => bool) usedExternalIds   (NEW)
slots 57..105 uint256[49] __gap                          (50 -> 49)
```

Omitting the gap reduction is the classic upgrade footgun: the contract would silently grow
by one slot and collide with anything appended in a later version.

---

## 3. Broken Invariant & Attack Scenario

### 3.1 The invariant

> **INV-1: one inbound bridge message results in exactly one payout on the destination chain.**

INV-1 is the defining safety property of a lock/mint bridge: destination-side supply must
never exceed source-side collateral. It is enforced nowhere on the withdrawal path.
In production it was violated twice within a single day.

### 3.2 The production incident

A single inbound message — one deposit on the source chain — was submitted for execution
three times on the destination chain:

- **attempt 1** reverted with the bridge's own `"Failed to send coins"` guard, because the
  recipient contract rejected the native transfer,
- **attempt 2** succeeded and emitted `Withdrawal`,
- **attempt 3** carried **byte-identical calldata** — same `externalId`, same amount, same
  sender and recipient — and **succeeded again**, emitting a second `Withdrawal` with the
  same `externalId`.

Balance deltas confirm the money moved twice:

- the recipient contract went `0.0 -> 0.1 -> 0.2` units,
- the bridge balance dropped by exactly the payout amount at each of the two successful
  executions, with no other movement in those blocks.

A query for **every** deposit to that recipient from **any** sender returned exactly one
entry. There is no second deposit that could justify a second payout.

Replaying that same calldata against current state — read-only, via `eth_call`, no
transaction submitted — still returns success, three times in a row. The message is not
consumed and remains executable indefinitely.

### 3.3 Attack scenario

The first (reverted) attempt is the lever. The payout step is:

```solidity
(bool success, ) = payable(address(uint160(uint256(receiveTokensParams.toAddress))))
    .call{value: amount}("");
require(success, "Failed to send coins");
```

Whether this succeeds is decided by the **recipient's own code**. That gives an external
party control over the condition that makes the operator retry:

1. Deploy a recipient contract `R` whose `receive()` reverts on the first attempt and accepts
   afterwards.
2. Bridge once, with the destination address set to `R`.
3. The operator's first attempt reverts. The backend treats that as a delivery failure and
   enqueues retries — production shows three attempts, two of which landed.
4. Because the message is never marked consumed, **every subsequent retry pays out again**.

The attacker never needs a privileged key. They control the recipient, therefore they
control the revert, therefore they control the retry. The only remaining ceiling is the
per-relayer daily cap, which resets every 24 hours.

The same primitive applies to the `WithdrawType.Mint` route, where the replay does not drain
existing collateral but **mints new supply** — the most severe variant, since there is no
pool to run dry.

---

## 4. Verification Methodology

All verification was read-only. No transactions were sent, no keys were used, and no state
was modified.

**Step 1 — establish the single backing deposit.**
Enumerate the destination chain's deposit events filtered on the recipient address across all
senders. Result: exactly one deposit, matching the amount and route of the message under
test.

**Step 2 — prove the submissions are the same message.**
Load all execution attempts and compare their calldata byte-for-byte. All three were
identical, 330 hex characters each. Two carried status `0x1`, one carried `0x0`.

**Step 3 — prove both successes paid out.**
Parse the receipt logs directly (without trusting any explorer), extract the `Withdrawal`
events, and confirm both carry the **same** `externalId`. The decoded event topic and data
words were checked against the ABI layout.

**Step 4 — prove funds moved twice.**
Read the recipient's native balance at each execution block and the bridge balance at
`block - 1` and at `block` for each payout. Each payout shows a single debit equal to the
payout amount, and the recipient balance steps up by the same amount each time.

**Step 5 — prove the message is still live.**
Replay the exact calldata through `eth_call` from the relayer address. Three consecutive
simulations all returned success. This is the cleanest demonstration that no consumption
state exists: the same message that was already paid twice still executes.

**Step 6 — control test.**
Send the same calldata from an unrelated address. It reverts with
`AccessControl: account ... is missing role ...`. This isolates the defect: the only gate is
the **role**, not the message.

**Falsification checks performed**, to rule out false positives:

- *Could there have been a second deposit?* Every deposit to the recipient, regardless of
  sender, was enumerated. Exactly one.
- *Could the attempts differ?* Byte comparison of all calldata. Identical.
- *Could the balance movement be unrelated?* Bridge balance read immediately before and at
  each payout block. One debit each, no other movement.
- *Does a hidden replay guard exist?* Live `eth_call` replay, three times, all successful.
- *Does deployed code differ from the audited repository?* The verified on-chain source was
  normalised (comments, imports and pragma stripped, whitespace collapsed) and diffed against
  the repository. Byte-identical, with identical `require`/`revert` string sets and an
  identical `abi.encodePacked` block.
- *Is this a permission bug rather than a replay bug?* Control call from an unauthorised
  address reverts on the role check, confirming the message itself is never validated.

**Local reproduction.** `PoC.t.sol` reimplements the architecture as self-contained mocks —
no RPC, no forking, no external dependencies — and runs four tests:

- `test_ExploitReproduces()` — one deposit, two payouts, collateral debited twice.
- `test_FixPreventsExploit()` — the same replay reverts, the user is paid exactly once, and
  the message is marked consumed.
- `test_DepositSideReplayIsBlocked()` — demonstrates the asymmetry: the deposit hash guard
  already works, so the missing withdrawal guard is an omission rather than a design choice.
- `test_StorageLayoutIsUpgradeSafe()` — reads slots 52 and 53 from both implementations with
  `vm.load` and asserts they are identical, proving the gap reduction keeps the layout stable.

```
forge test -vv
Ran 4 tests for PoC.t.sol:BridgeReplayPoC
[PASS] test_DepositSideReplayIsBlocked()
[PASS] test_ExploitReproduces()
[PASS] test_FixPreventsExploit()
[PASS] test_StorageLayoutIsUpgradeSafe()
Suite result: ok. 4 passed; 0 failed; 0 skipped
```

---

## 5. Remediation

### 5.1 The fix

Consume the message before any external interaction, mirroring the deposit-side pattern:

```solidity
/// @notice Inbound bridge messages already executed on this chain.
mapping(bytes32 externalId => bool isUsed) public usedExternalIds;

function receiveTokens(ReceiveTokensParams calldata receiveTokensParams)
    external nonReentrant onlyRole(RELAYER_ROLE)
{
    // ... route validation ...

    // Replay protection: a bridge message may be executed at most once.
    // Effects before interactions.
    require(!usedExternalIds[receiveTokensParams.externalId], "Message already processed");
    usedExternalIds[receiveTokensParams.externalId] = true;

    // ... payout (native transfer / safeTransfer / mint) ...
}
```

Three properties matter:

1. The flag is written **before** the payout. Any reentrancy or retry sees the message as
   already consumed.
2. It is written **after** route validation, so invalid routes cannot burn message ids.
3. The storage gap shrinks from `50` to `49` in the same change (see §2.4).

### 5.2 Hardening recommendations

- **Key on the full origin context.** If an `externalId` may legitimately recur across source
  chains, key on `keccak256(originChainId, externalId)`; otherwise a message from chain A can
  shadow one from chain B.
- **Index `externalId` in the event.** Makes off-chain reconciliation materially easier and
  gives monitoring something to alert on.
- **Add a monitoring invariant.** Alert if two `Withdrawal` events share an `externalId`, or
  if cumulative withdrawals for a route exceed cumulative deposits within a window. This
  detects the failure mode even if a future code path reintroduces it.
- **Make payout failures non-blocking.** A recipient contract that rejects a native transfer
  currently makes the whole execution revert, which is exactly the condition that drives
  retries. Consider crediting to an internal balance or allowing the recipient to withdraw,
  and treat "delivered but unclaimed" as a distinct state instead of a failure.
- **Apply the same guard to every future inbound executor.** Any function that consumes a
  message from another chain needs its own consumption record, not a shared assumption.
- **Add the regression test** in `PoC.t.sol` to CI so the invariant cannot silently regress.

### 5.3 Responsibility boundary

The trigger observed in production was an operator retry loop, but that does not move the
defect off-chain. The contract is the last line of defence for a value-moving operation, and
it had no line: the deposit path proves the team understood the requirement, and the
withdrawal path simply omitted it. A contract that pays out the same message twice is
independently defective regardless of what its off-chain caller does.

---

*This is a technical case study. All names, addresses, chain identifiers and transaction
references have been removed or genericised; the mechanics, the storage arithmetic, the
invariant and the remediation are preserved in full.*
