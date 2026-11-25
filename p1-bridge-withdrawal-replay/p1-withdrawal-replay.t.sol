// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * ============================================================================
 *  Cross-Chain Token Bridge - Withdrawal Message Replay
 * ============================================================================
 *
 *  Reproduces a critical missing-message-consumption bug on the withdrawal
 *  (payout) path of a lock/unlock + lock/mint style bridge.
 *
 *  The deposit path marks every message single-use (`usedHashes`). The payout
 *  path accepts an arbitrary `externalId`, emits it, and never stores it, so
 *  the same payout message can be executed an unlimited number of times.
 *
 *  Broken invariant:  1 inbound message  =>  exactly 1 payout.
 *
 *  Self-contained: no forge-std, no RPC, no forking. Plain `forge test`.
 * ============================================================================
 */

// ---------------------------------------------------------------------------
// Minimal cheatcode surface (no forge-std dependency)
// ---------------------------------------------------------------------------
interface Vm {
    function prank(address sender) external;
    function deal(address account, uint256 balance) external;
    function load(address target, bytes32 slot) external view returns (bytes32);
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------
enum DepositType { None, Lock, Burn }
enum WithdrawType { None, Unlock, Mint }

interface IMintable {
    function mint(address to, uint256 amount) external;
}

// ---------------------------------------------------------------------------
// Minimal ERC20 mock
// ---------------------------------------------------------------------------
contract MockToken {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory n, string memory s, uint8 d) {
        name = n;
        symbol = s;
        decimals = d;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "MockToken: insufficient allowance");
        allowance[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "MockToken: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

// ---------------------------------------------------------------------------
// Route registry (the "mapper"): one direction per route
// ---------------------------------------------------------------------------
contract RouteRegistry {
    struct Route {
        uint256 originChainId;
        uint256 targetChainId;
        DepositType depositType;
        WithdrawType withdrawType;
        address originToken;
        address targetToken;
        bool isAllowed;
    }

    uint256 public routeCount;
    mapping(uint256 => Route) public routes;

    function registerRoute(Route calldata r) external returns (uint256 id) {
        id = ++routeCount;
        routes[id] = r;
        return id;
    }

    /// @notice struct accessor (the auto-generated getter returns a tuple)
    function getRoute(uint256 id) external view returns (Route memory) {
        return routes[id];
    }
}

// ---------------------------------------------------------------------------
// Storage-layout skeleton shared by both implementations.
//
//  slot 0      : uint8 _initialized + bool _initializing   (packed)
//  slot 1      : _roles mapping
//  slot 2      : _status
//  slots 3..51 : __gap[49]
//  ---- bridge ----
//  slot 52     : gasAccumulated
//  slot 53     : registry
//  slot 54     : usedHashes
//  slot 55     : dailyLimit
// ---------------------------------------------------------------------------
abstract contract InitializableMock {
    uint8 private _initialized;
    bool private _initializing;

    function _initializeOnce() internal {
        require(!_initializing && _initialized == 0, "already initialized");
        _initialized = 1;
    }
}

abstract contract AccessControlMock {
    mapping(bytes32 => mapping(address => bool)) private _roles;

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
    }

    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "AccessControl: missing role");
        _;
    }
}

abstract contract ReentrancyGuardMock {
    uint256 private _status;
    uint256[49] private __gap;

    modifier nonReentrant() {
        require(_status != 2, "ReentrancyGuard: reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    function _initGuard() internal {
        _status = 1;
    }
}

// ===========================================================================
// VULNERABLE IMPLEMENTATION
// ===========================================================================
contract BridgeVulnerable is InitializableMock, AccessControlMock, ReentrancyGuardMock {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    uint256 public gasAccumulated;                     // slot 52
    RouteRegistry public registry;                     // slot 53
    mapping(bytes32 => bool) public usedHashes;        // slot 54
    mapping(bytes32 => uint256) public dailyLimit;     // slot 55
    uint256[50] private __gap;                         // slots 56..105

    event Deposit(bytes32 indexed depositId, address indexed from, uint256 amount);
    event Withdrawal(bytes32 indexed externalId, address indexed to, uint256 amount);

    constructor(RouteRegistry registry_, address relayer_) {
        _initializeOnce();
        _initGuard();
        registry = registry_;
        _grantRole(RELAYER_ROLE, relayer_);
    }

    /// @notice test-harness helper (no access control in this mock)
    function setDailyLimit(address token, address relayer, uint256 limit) external {
        dailyLimit[keccak256(abi.encode(token, relayer))] = limit;
    }

    /// @notice DEPOSIT SIDE: replay protected.
    function depositTokens(bytes32 salt, uint256 routeId, uint256 amount) external payable {
        RouteRegistry.Route memory r = registry.getRoute(routeId);
        require(r.isAllowed, "route disabled");
        require(r.depositType != DepositType.None, "not a deposit route");
        require(r.withdrawType == WithdrawType.None, "not a deposit route");

        bytes32 depositId =
            keccak256(abi.encode(msg.sender, routeId, amount, salt, block.chainid));
        require(!usedHashes[depositId], "deposit already processed"); // <-- GUARD EXISTS
        usedHashes[depositId] = true;

        gasAccumulated += msg.value;
        require(
            MockToken(r.originToken).transferFrom(msg.sender, address(this), amount),
            "transferFrom failed"
        );

        emit Deposit(depositId, msg.sender, amount);
    }

    /// @notice WITHDRAWAL SIDE: NOT replay protected.
    function receiveTokens(bytes32 externalId, uint256 routeId, uint256 amount, address to)
        external
        nonReentrant
        onlyRole(RELAYER_ROLE)
    {
        RouteRegistry.Route memory r = registry.getRoute(routeId);
        require(r.isAllowed, "route disabled");
        require(r.depositType == DepositType.None, "not a payout route");
        require(r.withdrawType != WithdrawType.None, "not a payout route");

        bytes32 limitKey = keccak256(abi.encode(r.targetToken, msg.sender));
        require(amount <= dailyLimit[limitKey], "daily limit exceeded");

        // ❌ externalId is used ONLY in the event, never recorded or checked.
        //    Every replay of this call pays out again.
        if (r.withdrawType == WithdrawType.Unlock) {
            require(MockToken(r.targetToken).transfer(to, amount), "transfer failed");
        } else {
            IMintable(r.targetToken).mint(to, amount);
        }

        emit Withdrawal(externalId, to, amount);
    }
}

// ===========================================================================
// PATCHED IMPLEMENTATION
//   - adds usedExternalIds
//   - reduces __gap 50 -> 49 so pre-existing slots do not move
// ===========================================================================
contract BridgePatched is InitializableMock, AccessControlMock, ReentrancyGuardMock {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    uint256 public gasAccumulated;                     // slot 52  (unchanged)
    RouteRegistry public registry;                     // slot 53  (unchanged)
    mapping(bytes32 => bool) public usedHashes;        // slot 54  (unchanged)
    mapping(bytes32 => uint256) public dailyLimit;     // slot 55  (unchanged)

    mapping(bytes32 => bool) public usedExternalIds;   // slot 56  (NEW)
    uint256[49] private __gap;                         // slots 57..105 (50 -> 49)

    event Deposit(bytes32 indexed depositId, address indexed from, uint256 amount);
    event Withdrawal(bytes32 indexed externalId, address indexed to, uint256 amount);

    constructor(RouteRegistry registry_, address relayer_) {
        _initializeOnce();
        _initGuard();
        registry = registry_;
        _grantRole(RELAYER_ROLE, relayer_);
    }

    function setDailyLimit(address token, address relayer, uint256 limit) external {
        dailyLimit[keccak256(abi.encode(token, relayer))] = limit;
    }

    function depositTokens(bytes32 salt, uint256 routeId, uint256 amount) external payable {
        RouteRegistry.Route memory r = registry.getRoute(routeId);
        require(r.isAllowed, "route disabled");
        require(r.depositType != DepositType.None, "not a deposit route");
        require(r.withdrawType == WithdrawType.None, "not a deposit route");

        bytes32 depositId =
            keccak256(abi.encode(msg.sender, routeId, amount, salt, block.chainid));
        require(!usedHashes[depositId], "deposit already processed");
        usedHashes[depositId] = true;

        gasAccumulated += msg.value;
        require(
            MockToken(r.originToken).transferFrom(msg.sender, address(this), amount),
            "transferFrom failed"
        );

        emit Deposit(depositId, msg.sender, amount);
    }

    function receiveTokens(bytes32 externalId, uint256 routeId, uint256 amount, address to)
        external
        nonReentrant
        onlyRole(RELAYER_ROLE)
    {
        RouteRegistry.Route memory r = registry.getRoute(routeId);
        require(r.isAllowed, "route disabled");
        require(r.depositType == DepositType.None, "not a payout route");
        require(r.withdrawType != WithdrawType.None, "not a payout route");

        // ✅ FIX: consume the message BEFORE any external call.
        require(!usedExternalIds[externalId], "message already processed");
        usedExternalIds[externalId] = true;

        bytes32 limitKey = keccak256(abi.encode(r.targetToken, msg.sender));
        require(amount <= dailyLimit[limitKey], "daily limit exceeded");

        if (r.withdrawType == WithdrawType.Unlock) {
            require(MockToken(r.targetToken).transfer(to, amount), "transfer failed");
        } else {
            IMintable(r.targetToken).mint(to, amount);
        }

        emit Withdrawal(externalId, to, amount);
    }
}

// ===========================================================================
// TESTS
// ===========================================================================
contract BridgeReplayPoC {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant RELAYER = address(0xBEEF);
    address internal constant USER = address(0xA11CE);

    uint256 internal constant CHAIN_A = 1111;
    uint256 internal constant CHAIN_B = 2222;
    uint256 internal constant LOCKED = 10e18;

    bytes32 internal constant EXT_ID = keccak256("inbound-message-1");
    bytes32 internal constant SALT = keccak256("deposit-salt-1");

    MockToken internal lockToken;  // asset locked on chain A
    MockToken internal poolToken;  // asset released on chain B (collateral held by bridge)
    RouteRegistry internal registry;
    BridgeVulnerable internal v1;
    BridgePatched internal v2;

    uint256 internal depositRoute;
    uint256 internal payoutRoute;

    function setUp() public {
        lockToken = new MockToken("Locked Asset", "LOCK", 18);
        poolToken = new MockToken("Bridged Asset", "BRG", 18);

        registry = new RouteRegistry();

        depositRoute = registry.registerRoute(
            RouteRegistry.Route({
                originChainId: CHAIN_A,
                targetChainId: CHAIN_B,
                depositType: DepositType.Lock,
                withdrawType: WithdrawType.None,
                originToken: address(lockToken),
                targetToken: address(poolToken),
                isAllowed: true
            })
        );

        payoutRoute = registry.registerRoute(
            RouteRegistry.Route({
                originChainId: CHAIN_A,
                targetChainId: CHAIN_B,
                depositType: DepositType.None,
                withdrawType: WithdrawType.Unlock,
                originToken: address(lockToken),
                targetToken: address(poolToken),
                isAllowed: true
            })
        );

        v1 = new BridgeVulnerable(registry, RELAYER);
        v2 = new BridgePatched(registry, RELAYER);

        // user's wallet balance on chain A (they hold the asset they wish to bridge)
        lockToken.mint(USER, 100e18);

        // collateral that backs payouts on chain B
        poolToken.mint(address(v1), 100e18);
        poolToken.mint(address(v2), 100e18);

        // per-relayer daily cap: generous enough that the replay is not the blocker
        v1.setDailyLimit(address(poolToken), RELAYER, 100e18);
        v2.setDailyLimit(address(poolToken), RELAYER, 100e18);
    }

    // -----------------------------------------------------------------------
    // 1. The bug: one deposit, two payouts
    // -----------------------------------------------------------------------
    function test_ExploitReproduces() public {
        // chain A: user locks 10 tokens (the ONE backing deposit)
        vm.prank(USER);
        lockToken.approve(address(v1), LOCKED);

        vm.prank(USER);
        v1.depositTokens(SALT, depositRoute, LOCKED);

        // chain B: relayer pays the message out once (legitimate)
        vm.prank(RELAYER);
        v1.receiveTokens(EXT_ID, payoutRoute, LOCKED, USER);

        require(poolToken.balanceOf(USER) == LOCKED, "payout #1 failed");
        require(poolToken.balanceOf(address(v1)) == 90e18, "pool after payout #1");

        // chain B: the SAME message is submitted again -> pays out again
        vm.prank(RELAYER);
        v1.receiveTokens(EXT_ID, payoutRoute, LOCKED, USER);

        require(poolToken.balanceOf(USER) == 2 * LOCKED, "REPLAY: user paid twice");
        require(poolToken.balanceOf(address(v1)) == 80e18, "REPLAY: pool debited twice");
    }

    // -----------------------------------------------------------------------
    // 2. The fix: the replay is rejected
    // -----------------------------------------------------------------------
    function test_FixPreventsExploit() public {
        vm.prank(USER);
        lockToken.approve(address(v2), LOCKED);

        vm.prank(USER);
        v2.depositTokens(SALT, depositRoute, LOCKED);

        vm.prank(RELAYER);
        v2.receiveTokens(EXT_ID, payoutRoute, LOCKED, USER);

        require(poolToken.balanceOf(USER) == LOCKED, "payout #1 failed");

        // replay must now revert
        vm.prank(RELAYER);
        (bool ok,) = address(v2).call(
            abi.encodeCall(BridgePatched.receiveTokens, (EXT_ID, payoutRoute, LOCKED, USER))
        );
        require(!ok, "FIX FAILED: replay still executed");

        require(poolToken.balanceOf(USER) == LOCKED, "user must be paid exactly once");
        require(poolToken.balanceOf(address(v2)) == 90e18, "pool debited exactly once");
        require(v2.usedExternalIds(EXT_ID) == true, "message not consumed");
    }

    // -----------------------------------------------------------------------
    // 3. Asymmetry proof: the DEPOSIT side already had this guard
    // -----------------------------------------------------------------------
    function test_DepositSideReplayIsBlocked() public {
        vm.prank(USER);
        lockToken.approve(address(v1), 2 * LOCKED);

        vm.prank(USER);
        v1.depositTokens(SALT, depositRoute, LOCKED);

        vm.prank(USER);
        (bool ok,) = address(v1).call(
            abi.encodeCall(BridgeVulnerable.depositTokens, (SALT, depositRoute, LOCKED))
        );
        require(!ok, "deposit replay should revert (usedHashes guard)");
    }

    // -----------------------------------------------------------------------
    // 4. Upgrade safety: reducing __gap by one keeps every existing slot
    // -----------------------------------------------------------------------
    function test_StorageLayoutIsUpgradeSafe() public {
        vm.deal(USER, 10);
        vm.prank(USER);
        lockToken.approve(address(v1), 1);
        vm.prank(USER);
        v1.depositTokens{value: 1}(bytes32("layout"), depositRoute, 1);

        vm.deal(USER, 10);
        vm.prank(USER);
        lockToken.approve(address(v2), 1);
        vm.prank(USER);
        v2.depositTokens{value: 1}(bytes32("layout"), depositRoute, 1);

        bytes32 slot52_v1 = vm.load(address(v1), bytes32(uint256(52)));
        bytes32 slot52_v2 = vm.load(address(v2), bytes32(uint256(52)));
        require(slot52_v1 == slot52_v2, "slot 52 moved");
        require(uint256(slot52_v1) == 1, "slot 52 is not gasAccumulated");

        bytes32 slot53_v1 = vm.load(address(v1), bytes32(uint256(53)));
        bytes32 slot53_v2 = vm.load(address(v2), bytes32(uint256(53)));
        require(slot53_v1 == slot53_v2, "slot 53 moved");
        require(
            uint256(slot53_v1) == uint256(uint160(address(registry))),
            "slot 53 is not registry"
        );
    }
}
