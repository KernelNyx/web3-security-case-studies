# Stale-Price Acceptance in an L2 Lending Protocol's Oracle Consumer

> **Portfolio case study.** All protocol, token, chain, platform and address
> identifiers have been removed. Contract names and constants are illustrative
> reconstructions that preserve the technical behaviour under review.

---

## Summary & Severity

| Field | Value |
|---|---|
| **Class** | Missing oracle freshness & deviation validation (consumer-side) |
| **Severity** | **High** |
| **Impact** | User funds — wrongful liquidation / unbacked borrowing |
| **Component** | Price oracle adapter (consumer) + deployment configuration |
| **Trigger** | Price feed ceases updating (keeper/sequencer liveness failure) |

### Overview

An L2 lending protocol's price oracle adapter returned the raw answer from its
upstream push-based aggregator. It performed **no verification of the answer's
timestamp** and applied **no deviation bound** to the value.

Separately, the protocol's own L2 price-sentinel — a guard authored in its
verified source specifically to suspend borrowing and liquidation during oracle
or sequencer downtime — was **left unset at `address(0)`**. Because the guard is
written as a short-circuit expression that begins with
`priceOracleSentinel == address(0) || ...`, the unset address causes the
protocol's own check to evaluate to `true` and never execute.

The combination removes every liveness control in the pricing path: the oracle
accepts arbitrarily stale values, and the protocol-level backstop that would
have compensated for this is disabled by configuration.

### Verified behaviour

The consumer returned an **identical price** with the upstream timestamp rewound
by **1 hour, 1 day, 30 days and 1 year**, and continued returning a price even
when the aggregator itself reverted. Doubling the reported answer caused the
consumer to return exactly double the value.

---

## Root Cause Analysis

### 1. Consumer ignores the timestamp field entirely

The aggregator exposes a full round structure:

```solidity
function latestRoundData()
    external
    view
    returns (uint80 roundId, int256 answer, uint256 startedAt,
             uint256 updatedAt, uint80 answeredInRound);
```

The consumer read only the answer. The strongest evidence of this is that when
the aggregator's `updatedAt` was forced to zero, the **aggregator reverted**
with its own round-validity error — while the **consumer still returned a
price**. The timestamp was structurally invisible to the consumer.

### 2. No deviation bound

A reported answer of `2x` the live value was returned verbatim. There was no
upper/lower guard, no circuit breaker, and no comparison against a previous
observation.

### 3. Protocol-authored L2 guard left unwired

The protocol's verified source contains a dedicated sentinel interface:

```solidity
interface IPriceOracleSentinel {
    event SequencerOracleUpdated(address newSequencerOracle);
    event GracePeriodUpdated(uint256 newGracePeriod);

    function isBorrowAllowed() external view returns (bool);
    function isLiquidationAllowed() external view returns (bool);
}
```

The borrow path enforces it:

```solidity
require(
    params.priceOracleSentinel == address(0) ||
        IPriceOracleSentinel(params.priceOracleSentinel).isBorrowAllowed(),
    Errors.PRICE_ORACLE_SENTINEL_CHECK_FAILED
);
```

The registry exposes both accessors:

```solidity
function getPriceOracleSentinel() external view returns (address);
function setPriceOracleSentinel(address newPriceOracleSentinel) external; // onlyOwner
```

The pool reads the value and threads it into validation:

```solidity
priceOracleSentinel: ADDRESSES_PROVIDER.getPriceOracleSentinel()
```

**On-chain, `getPriceOracleSentinel()` returned `address(0)`.** The guard the
protocol wrote, the setter the protocol wrote, and the wiring the protocol
wrote were all present — the deployment simply never configured the value.

> **Note on scope of the borrow path:** unlike the liquidation guard (which
> carries a health-factor escape hatch), the **borrow guard contains no
> exception**. During an oracle outage, borrowing is fully ungated.

---

## Broken Invariant & Attack Scenario

### Invariant

> **INV-1:** Collateral is valued using a price whose observation is no older
> than `MAX_STALENESS`, and whose magnitude is within `MAX_DEVIATION` of the
> last accepted observation.

### Violation

The consumer satisfies no clause of INV-1. Any answer, of any age, of any
magnitude, is accepted (the sole exception being an answer of exactly zero).

### Scenario A — wrongful liquidation (direct user loss)

An ETH feed stalls at `$1,000` while the market trades at `$1,724.31`.

A user holds `10 ETH` collateral (liquidation threshold `80%`) against
`8,000 USDC` debt.

```
stale health factor = (10 * 1,000 * 0.80) / 8,000 = 1.00
```

The position becomes liquidatable on a price that is `42%` below market.

```
liquidator repays            4,000 USDC
receives 4,000 * 1.05    =  $4,200 of stale value = 4.2 ETH
real value of 4.2 ETH    =   4.2 * 1,724.31 = $7,242
liquidator profit        ≈  $3,242   (user loses the same)
```

The user is liquidated on a position that was never genuinely unhealthy, and
the loss arises purely from the protocol's failure to validate price age.

### Scenario B — borrowing against phantom collateral (bad debt)

The staked-ETH feed stalls at `2x` (`$3,448`) against a real `$1,724`.

```
deposit 10 staked-ETH -> protocol values at $34,485
borrow 75% LTV        ->  $25,864
real collateral value ->  $17,243
protocol bad debt     ->  ~$8,621  (borne by suppliers)
```

### Amplifying configuration observed

- All reserves configured with `supplyCap = 0` / `borrowCap = 0` (unlimited)
- Correlated-asset mode: `LTV 90% / LT 95% / 5% bonus` on stable pairs
- Correlated-asset mode: `LTV 85% / LT 90% / 5% bonus` on the native pair
- Thin `5%` liquidation bonus slows liquidation throughput, deepening shortfall
- **All six aggregators reported an identical `roundId` and `updatedAt`** — one
  keeper pushed every price in a single batch, making the stall condition
  global rather than per-asset

---

## Verification Methodology

All testing was **read-only**. No transaction was signed or broadcast; no
on-chain state was modified.

### Constraint: the chain's VM is not EVM-equivalent

Local fork simulation was not viable — the target chain compiles to a
non-EVM bytecode format that halts immediately under standard EVM execution.
Verification therefore had to occur through RPC state simulation.

### Technique: `eth_call` with `stateDiff` override

The RPC accepted per-call storage overrides, allowing the aggregator's internal
state to be rewritten **for the duration of a single simulated call only**.

### Step 1 — recover the unverified aggregator's storage layout

The aggregator was unverified, so no source was available. Its layout was
recovered by differential slot probing:

```
slot 0  = decimals (8)
slot 1  = description string
slot 2  = latest roundId            (overriding it -> revert "No data present")
slot 4  = mapping(uint256 roundId => uint256 answer)
slot 5  = mapping(uint256 roundId => uint256 timestamp)
```

Mapping keys are derived conventionally:

```solidity
bytes32 key = keccak256(abi.encode(uint256(roundId), uint256(slot)));
```

Both mapping entries were confirmed by reading storage and matching the values
returned by `latestRoundData()`.

### Step 2 — confirm the override reaches the reported timestamp

```
baseline        startedAt = updatedAt = <live>
override slot 5 startedAt = updatedAt = 1,000,000   <- confirmed applied
```

### Step 3 — measure consumer behaviour under controlled states

```
case                          feed state                    consumer result
--------------------------------------------------------------------------------
baseline                      live                          <price>  (pass-through)
updatedAt = now - 1h          stale 1 hour                  <price>  unchanged
updatedAt = now - 1d          stale 1 day                   <price>  unchanged
updatedAt = now - 30d         stale 30 days                 <price>  unchanged
updatedAt = now - 365d        stale 1 year                  <price>  unchanged
updatedAt = 0                 aggregator reverts            <price>  still returned
answer = 2x                   doubled                       <price>  exactly 2x
answer = 0                    zero                          reverts "94"
```

### Step 4 — configuration check

```
registry.getPriceOracleSentinel() -> address(0)
```

### Reproducibility caveat

`roundId` advances on every push, and the storage key depends on it. Any
reproduction must re-read `roundId` and **verify the override applied** (by
re-reading the reported timestamp) before drawing a conclusion. A stale key
produces a valid-but-irrelevant write and a false negative.

---

## Remediation

### 1. Enforce freshness and sanity inside the consumer

```solidity
function getAssetPrice(address asset) external view returns (uint256) {
    IPriceFeed source = _sources[asset];

    (, int256 answer, , uint256 updatedAt, ) = source.latestRoundData();

    require(answer > 0, Errors.INVALID_PRICE);
    require(block.timestamp - updatedAt <= MAX_STALENESS, Errors.STALE_PRICE);

    int256 previous = _lastAccepted[asset];
    if (previous > 0) {
        uint256 delta = answer > previous
            ? uint256(answer - previous)
            : uint256(previous - answer);
        require(
            delta * 10_000 / uint256(previous) <= MAX_DEVIATION_BPS,
            Errors.PRICE_DEVIATION_TOO_LARGE
        );
    }

    return uint256(answer);
}
```

### 2. Configure the protocol's own L2 sentinel

```solidity
registry.setPriceOracleSentinel(address(sentinel));
// sentinel wired to the chain's sequencer-uptime feed + grace period
```

### 3. Decouple the feed update path

All reserves must not share a single timestamp or a single keeper. Independent
update paths prevent a global simultaneous stall.

### 4. Bound the blast radius on volatile collateral

Apply supply and borrow caps to staked/liquid-staking collateral and re-assess
the correlated-asset thresholds against the realistic worst-case depeg.

---

## Lessons for scoping

A correct finding that requires an external liveness failure is, for most
programs, a **hardening recommendation** rather than a payable vulnerability.
Before committing research time, answer:

> **Can I, as a researcher, author the transaction that causes the loss?**

If the answer is *no* — because the trigger lives in a keeper, a sequencer, or
an upstream feed — treat the finding as a risk report, not a bounty submission.
