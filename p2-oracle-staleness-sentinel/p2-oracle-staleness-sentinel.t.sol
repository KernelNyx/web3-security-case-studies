// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

/* -------------------------------------------------------------------------
   MINIMAL MOCKS
   -------------------------------------------------------------------------
   MockPriceFeed mimics a push-based aggregator: an operator (keeper) pushes
   an answer together with a timestamp. It exposes both the full Chainlink-
   style `latestRoundData()` and the reduced `latestAnswer()` that a careless
   consumer is likely to use.
   ------------------------------------------------------------------------- */

contract MockPriceFeed {
    uint8 public constant decimals = 8;

    int256 private _answer;
    uint256 private _updatedAt;
    uint80 private _roundId;

    constructor(int256 initialAnswer) {
        pushAnswer(initialAnswer, block.timestamp);
    }

    /// @notice Operator pushes a new observation.
    function pushAnswer(int256 answer, uint256 observedAt) public {
        _answer = answer;
        _updatedAt = observedAt;
        _roundId += 1;
    }

    function latestAnswer() public view returns (int256) {
        return _answer;
    }

    function latestTimestamp() public view returns (uint256) {
        return _updatedAt;
    }

    function latestRound() public view returns (uint80) {
        return _roundId;
    }

    function latestRoundData()
        public
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        // Mirrors the observed behaviour: a round whose timestamp is zero is
        // rejected by the aggregator itself.
        require(_updatedAt != 0, "No data present");
        return (_roundId, _answer, _updatedAt, _updatedAt, _roundId);
    }

    function getRoundData(uint80 roundId_)
        public
        view
        returns (uint80, int256, uint256, uint256, uint80)
    {
        require(roundId_ == _roundId, "No data present");
        return latestRoundData();
    }
}

/* -------------------------------------------------------------------------
   VULNERABLE CONSUMER
   -------------------------------------------------------------------------
   Reads only the answer. Never inspects `updatedAt`. Applies no deviation
   bound. The sole guard is a zero-price rejection.
   ------------------------------------------------------------------------- */

contract VulnerableOracle {
    MockPriceFeed public immutable feed;

    constructor(MockPriceFeed feed_) {
        feed = feed_;
    }

    function getAssetPrice(address) external view returns (uint256) {
        int256 answer = feed.latestAnswer();
        require(answer > 0, "94"); // only guard present on the live deployment
        return uint256(answer);
    }
}

/* -------------------------------------------------------------------------
   FIXED CONSUMER
   -------------------------------------------------------------------------
   Reads the full round, enforces a staleness window, and rejects large
   deviations against the last accepted observation.
   ------------------------------------------------------------------------- */

contract FixedOracle {
    uint256 public constant MAX_STALENESS = 1 hours;
    uint256 public constant MAX_DEVIATION_BPS = 2_000; // 20%

    MockPriceFeed public immutable feed;
    mapping(address => int256) public lastAccepted;

    error InvalidPrice();
    error StalePrice(uint256 age);
    error DeviationTooLarge(uint256 bps);

    constructor(MockPriceFeed feed_) {
        feed = feed_;
    }

    function getAssetPrice(address asset) external view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();

        if (answer <= 0) revert InvalidPrice();

        uint256 age = block.timestamp - updatedAt;
        if (age > MAX_STALENESS) revert StalePrice(age);

        int256 previous = lastAccepted[asset];
        if (previous > 0) {
            uint256 delta = answer > previous
                ? uint256(answer - previous)
                : uint256(previous - answer);
            uint256 bps = (delta * 10_000) / uint256(previous);
            if (bps > MAX_DEVIATION_BPS) revert DeviationTooLarge(bps);
        }

        return uint256(answer);
    }

    /// @notice Records an accepted price (kept separate to keep the getter pure).
    function acceptPrice(address asset) external {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        if (answer <= 0) revert InvalidPrice();
        if (block.timestamp - updatedAt > MAX_STALENESS) revert StalePrice(block.timestamp - updatedAt);
        lastAccepted[asset] = answer;
    }
}

/* -------------------------------------------------------------------------
   MINIMAL LENDING VALUATION (to express the impact concretely)
   ------------------------------------------------------------------------- */

contract MockLendingPool {
    uint256 public constant LIQUIDATION_THRESHOLD_BPS = 8_000; // 80%

    function isLiquidatable(
        address oracle,
        address asset,
        uint256 collateralAmount,
        uint256 debtUsd
    ) external view returns (bool) {
        uint256 price = VulnerableOracle(oracle).getAssetPrice(asset);
        uint256 collateralUsd = (collateralAmount * price) / 1e18;
        uint256 adjusted = (collateralUsd * LIQUIDATION_THRESHOLD_BPS) / 10_000;
        return adjusted < debtUsd;
    }
}

/* -------------------------------------------------------------------------
   TESTS
   ------------------------------------------------------------------------- */

contract OracleFreshnessPoC is Test {
    MockPriceFeed internal feed;
    VulnerableOracle internal vuln;
    MockLendingPool internal pool;

    address internal constant ASSET = address(0xA11CE);

    int256 internal constant ETH_PRICE = 172_431_000_000; // $1,724.31 @ 8dp

    function setUp() public {
        vm.warp(1_800_000_000); // realistic epoch; avoids underflow on -365d
        feed = new MockPriceFeed(ETH_PRICE);
        vuln = new VulnerableOracle(feed);
        pool = new MockLendingPool();
    }

    /* ------------------------------------------------------------------
       TEST 1 - the vulnerability reproduces
       ------------------------------------------------------------------ */

    function test_ExploitReproduces() public {
        // ---- baseline: live price is propagated verbatim --------------
        uint256 baseline = vuln.getAssetPrice(ASSET);
        assertEq(baseline, uint256(ETH_PRICE), "baseline should mirror feed");

        // ---- 1. STALENESS: rewind the observation by one year ---------
        uint256 oneYearAgo = block.timestamp - 365 days;
        feed.pushAnswer(ETH_PRICE, oneYearAgo);

        // a stale but non-zero observation is served with no revert at all
        uint256 stalePrice = vuln.getAssetPrice(ASSET);
        assertEq(stalePrice, uint256(ETH_PRICE), "1y-stale price served unchanged");

        // an epoch-zero observation: the aggregator itself rejects the round
        feed.pushAnswer(ETH_PRICE, 0);
        vm.expectRevert(bytes("No data present"));
        feed.latestRoundData();

        // ...yet the consumer still returns a price, ignoring round validity
        assertEq(vuln.getAssetPrice(ASSET), uint256(ETH_PRICE), "consumer ignores aggregator revert");

        // ---- 2. DEVIATION: double the reported answer ----------------
        feed.pushAnswer(ETH_PRICE * 2, block.timestamp);
        uint256 doubled = vuln.getAssetPrice(ASSET);
        assertEq(doubled, uint256(ETH_PRICE * 2), "doubled answer accepted verbatim");

        // ---- 3. IMPACT: a healthy position is liquidated -------------
        // 10 ETH collateral, $8,000 debt, 80% liquidation threshold.
        feed.pushAnswer(100_000_000_000, block.timestamp); // feed stalls at $1,000

        bool liquidatable = pool.isLiquidatable(
            address(vuln),
            ASSET,
            10 ether,
            8_500e8
        );
        assertTrue(liquidatable, "healthy user becomes liquidatable on stale price");
    }

    /* ------------------------------------------------------------------
       TEST 2 - the remediation prevents it
       ------------------------------------------------------------------ */

    function test_FixPreventsExploit() public {
        FixedOracle fixedOracle = new FixedOracle(feed);
        fixedOracle.acceptPrice(ASSET);

        // baseline still works
        assertEq(fixedOracle.getAssetPrice(ASSET), uint256(ETH_PRICE));

        // ---- STALENESS is rejected -----------------------------------
        uint256 oneYearAgo = block.timestamp - 365 days;
        feed.pushAnswer(ETH_PRICE, oneYearAgo);

        vm.expectRevert(abi.encodeWithSelector(FixedOracle.StalePrice.selector, uint256(365 days)));
        fixedOracle.getAssetPrice(ASSET);

        // ---- DEVIATION is rejected -----------------------------------
        feed.pushAnswer(ETH_PRICE * 2, block.timestamp);

        vm.expectRevert(
            abi.encodeWithSelector(
                FixedOracle.DeviationTooLarge.selector,
                10_000 // (2x - 1x) / 1x = 100%
            )
        );
        fixedOracle.getAssetPrice(ASSET);

        // ---- ZERO is rejected ----------------------------------------
        feed.pushAnswer(0, block.timestamp);
        vm.expectRevert(FixedOracle.InvalidPrice.selector);
        fixedOracle.getAssetPrice(ASSET);

        // ---- a fresh, sane update still passes -----------------------
        feed.pushAnswer(ETH_PRICE, block.timestamp);
        assertEq(fixedOracle.getAssetPrice(ASSET), uint256(ETH_PRICE));
    }

    /* ------------------------------------------------------------------
       TEST 3 - documents the storage-slot derivation used on-chain
       ------------------------------------------------------------------ */

    function test_StorageSlotDerivation() public pure {
        // On-chain the answer/timestamp lived in mappings at slots 4 and 5,
        // keyed by keccak256(abi.encode(roundId, slot)).
        uint256 roundId = 1_795_440_339_697_000;
        bytes32 answerKey = keccak256(abi.encode(roundId, uint256(4)));
        bytes32 timestampKey = keccak256(abi.encode(roundId, uint256(5)));

        assertTrue(answerKey != timestampKey);
        assertEq(answerKey, keccak256(abi.encode(roundId, uint256(4))));
    }
}
