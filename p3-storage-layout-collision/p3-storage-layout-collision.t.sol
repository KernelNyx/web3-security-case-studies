// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/*
 *  UUPS STORAGE-LAYOUT DIVERGENCE  --  SELF-CONTAINED REPRODUCTION
 *  ==============================================================
 *  No forks, no RPC, no external dependencies beyond forge-std.
 *
 *  Two implementations of the same logical contract are modelled,
 *  each with the storage layout its compiler actually emitted:
 *
 *    BridgeNamespaced : AccessControl is ERC-7201 namespaced
 *                       -> consumes ZERO linear slots   (OZ 5.x model)
 *    BridgeLinear     : AccessControl is linear
 *                       -> consumes _roles(1) + __gap(49) = 50 slots  (OZ 4.9 model)
 *
 *  Inheritance order is identical in both: the access-control base sits
 *  BEFORE the reentrancy guard and before every bridge state variable,
 *  so a change in what access-control consumes displaces everything after it.
 *
 *  Consequence: BridgeNamespaced stores _status at slot 201, BridgeLinear
 *  stores _roles at slot 201. Every subsequent variable is 50 slots apart.
 */

interface IStorageLayout {
    function STORAGE_LAYOUT_ID() external pure returns (bytes32);
}

/// @dev Minimal EIP-1967 UUPS proxy. Implementation slot is written by the
///      implementation itself (via delegatecall), exactly like OZ UUPS.
contract UUPSProxy {
    // EIP-1967: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
    // 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

    constructor(address impl) {
        assembly {
            sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, impl)
        }
    }

    receive() external payable {}

    fallback() external payable {
        assembly {
            let impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function implementation() external view returns (address impl) {
        assembly {
            impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
        }
    }
}

// ---------------------------------------------------------------------------
// BUILD B  --  namespaced AccessControl (OpenZeppelin 5.x model)
// ---------------------------------------------------------------------------
contract BridgeNamespaced {
    bytes32 public constant MULTISIG_ROLE  = keccak256("MULTISIG_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // ERC-7201: keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.AccessControl")) - 1)) & ~0xff
    bytes32 private constant AC_NS_SLOT =
        0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    // ---- storage: mirrors the compiler-emitted namespaced layout ----
    uint8 private _initialized;                          // slot 0
    bool  private _initializing;                         // slot 0

    uint256[50] private __gapContext;                    // slots   1.. 50
    uint256[50] private __gapERC165;                     // slots  51..100
    uint256[50] private __gapERC1967;                    // slots 101..150
    uint256[50] private __gapUUPS;                       // slots 151..200

    // AccessControl is namespaced => consumes ZERO linear slots here

    uint256 private _status;                             // slot  201  (guard)
    uint256[49] private __gapGuard;                      // slots 202..250

    uint256 public gasAccumulated;                       // slot  251
    address public Mapper;                               // slot  252
    mapping(bytes32 => bool) public usedHashes;          // slot  253
    uint256[50] private __gapSelf;                       // slots 254..303

    error AlreadyInitialized();

    // ---- namespaced role access ----
    function _roleSlot(bytes32 role, address account) private pure returns (bytes32) {
        bytes32 inner = keccak256(abi.encode(role, AC_NS_SLOT));
        return keccak256(abi.encode(account, inner));
    }

    function _grantRole(bytes32 role, address account) internal {
        bytes32 s = _roleSlot(role, account);
        assembly {
            sstore(s, 1)
        }
    }

    function hasRole(bytes32 role, address account) public view returns (bool ok) {
        bytes32 s = _roleSlot(role, account);
        assembly {
            ok := sload(s)
        }
    }

    // ---- lifecycle ----
    function initialize(
        address multisig,
        address emergency,
        address mapper_,
        uint256 seedGas
    ) external {
        if (_initialized != 0) revert AlreadyInitialized();
        _initialized = 1;
        _status = 1; // NOT_ENTERED
        gasAccumulated = seedGas;
        Mapper = mapper_;
        _grantRole(MULTISIG_ROLE, multisig);
        _grantRole(EMERGENCY_ROLE, emergency);
    }

    function upgradeTo(address newImpl) external virtual {
        require(hasRole(MULTISIG_ROLE, msg.sender), "missing MULTISIG_ROLE");
        assembly {
            sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, newImpl)
        }
    }

    // ---- bridge surface ----
    function bridgeTokens(uint256 amount) external payable {
        require(Mapper != address(0), "Mapper unset");
        require(amount > 0, "zero amount");
        gasAccumulated += msg.value;
    }

    function withdrawGasAccumulated() external {
        require(hasRole(EMERGENCY_ROLE, msg.sender), "missing EMERGENCY_ROLE");
        uint256 amount = gasAccumulated;
        gasAccumulated = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function status() external view returns (uint256) {
        return _status;
    }

    function STORAGE_LAYOUT_ID() public pure virtual returns (bytes32) {
        return keccak256("LAYOUT_NAMESPACED_AC");
    }
}

// ---------------------------------------------------------------------------
// BUILD A  --  linear AccessControl (OpenZeppelin 4.9 model)
// ---------------------------------------------------------------------------
contract BridgeLinear {
    bytes32 public constant MULTISIG_ROLE  = keccak256("MULTISIG_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    // ---- storage: mirrors the compiler-emitted linear layout ----
    uint8 private _initialized;                          // slot 0
    bool  private _initializing;                         // slot 0

    uint256[50] private __gapContext;                    // slots   1.. 50
    uint256[50] private __gapERC165;                     // slots  51..100
    uint256[50] private __gapERC1967;                    // slots 101..150
    uint256[50] private __gapUUPS;                       // slots 151..200

    mapping(bytes32 => RoleData) private _roles;         // slot  201  <-- LINEAR
    uint256[49] private __gapAccessControl;              // slots 202..250

    uint256 private _status;                             // slot  251
    uint256[49] private __gapGuard;                      // slots 252..300

    uint256 public gasAccumulated;                       // slot  301
    address public Mapper;                               // slot  302
    mapping(bytes32 => bool) public usedHashes;          // slot  303
    uint256[50] private __gapSelf;                       // slots 304..353

    error AlreadyInitialized();

    function _grantRole(bytes32 role, address account) internal {
        _roles[role].members[account] = true;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members[account];
    }

    function initialize(
        address multisig,
        address emergency,
        address mapper_,
        uint256 seedGas
    ) external {
        if (_initialized != 0) revert AlreadyInitialized();
        _initialized = 1;
        _status = 1;
        gasAccumulated = seedGas;
        Mapper = mapper_;
        _grantRole(MULTISIG_ROLE, multisig);
        _grantRole(EMERGENCY_ROLE, emergency);
    }

    function upgradeTo(address newImpl) external virtual {
        require(hasRole(MULTISIG_ROLE, msg.sender), "missing MULTISIG_ROLE");
        assembly {
            sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, newImpl)
        }
    }

    function bridgeTokens(uint256 amount) external payable {
        require(Mapper != address(0), "Mapper unset");
        require(amount > 0, "zero amount");
        gasAccumulated += msg.value;
    }

    function withdrawGasAccumulated() external {
        require(hasRole(EMERGENCY_ROLE, msg.sender), "missing EMERGENCY_ROLE");
        uint256 amount = gasAccumulated;
        gasAccumulated = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function status() external view returns (uint256) {
        return _status;
    }

    function STORAGE_LAYOUT_ID() public pure virtual returns (bytes32) {
        return keccak256("LAYOUT_LINEAR_AC");
    }
}

// ---------------------------------------------------------------------------
// FIX  --  identical layout to BridgeNamespaced, plus a layout guard
// ---------------------------------------------------------------------------
contract BridgeNamespacedGuarded is BridgeNamespaced {
    function upgradeTo(address newImpl) external override {
        require(hasRole(MULTISIG_ROLE, msg.sender), "missing MULTISIG_ROLE");
        require(
            IStorageLayout(newImpl).STORAGE_LAYOUT_ID() == STORAGE_LAYOUT_ID(),
            "incompatible storage layout"
        );
        assembly {
            sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, newImpl)
        }
    }
}

// ---------------------------------------------------------------------------
// TESTS
// ---------------------------------------------------------------------------
contract BridgeLayoutPoC is Test {
    uint256 private constant SEED_GAS    = 1 ether;
    uint256 private constant PROXY_FUNDS = 100 ether;

    BridgeNamespaced nsImpl;
    BridgeLinear     linImpl;
    UUPSProxy        proxy;

    address multisig;
    address emergency;
    address mapperAddr;

    function setUp() public {
        multisig   = makeAddr("multisig");
        emergency  = makeAddr("emergency");
        mapperAddr = makeAddr("mapper");

        nsImpl  = new BridgeNamespaced();
        linImpl = new BridgeLinear();
        proxy   = new UUPSProxy(address(nsImpl));
    }

    // -----------------------------------------------------------------
    // 1. The vulnerability
    // -----------------------------------------------------------------
    function test_ExploitReproduces() public {
        BridgeNamespaced live = BridgeNamespaced(address(proxy));
        live.initialize(multisig, emergency, mapperAddr, SEED_GAS);

        // ---- healthy before the upgrade ----
        assertTrue(live.hasRole(live.MULTISIG_ROLE(), multisig), "pre: role held");
        assertEq(live.Mapper(), mapperAddr, "pre: Mapper set");
        assertEq(live.gasAccumulated(), SEED_GAS, "pre: accounting intact");
        assertEq(live.status(), 1, "pre: guard initialised");

        // raw proof that slot 201 is the guard (not a roles mapping)
        assertEq(
            uint256(vm.load(address(proxy), bytes32(uint256(201)))),
            1,
            "slot 201 == _status under the namespaced layout"
        );

        vm.deal(address(proxy), PROXY_FUNDS);

        // ================================================================
        // A routine-looking, privileged implementation upgrade.
        // Nothing about this call is abusive: the caller holds the role,
        // the new code compiles, the ABI is identical.
        // ================================================================
        vm.prank(multisig);
        live.upgradeTo(address(linImpl));
        // ================================================================

        BridgeLinear broken = BridgeLinear(address(proxy));

        // 1. role registry orphaned
        assertFalse(
            broken.hasRole(broken.MULTISIG_ROLE(), multisig),
            "roles orphaned: hasRole(MULTISIG_ROLE) == false"
        );

        // 2. Mapper pointer lost -> every mapInfo() call would revert
        assertEq(broken.Mapper(), address(0), "Mapper resolves to address(0)");

        // 3. accounting lost
        assertEq(broken.gasAccumulated(), 0, "gasAccumulated reads zero");

        // 4. reentrancy guard poisoned with the stale gasAccumulated value
        assertEq(
            broken.status(),
            SEED_GAS,
            "guard reads slot 251, which held gasAccumulated"
        );

        // 5. the bridge is unusable
        vm.expectRevert(bytes("Mapper unset"));
        broken.bridgeTokens{value: 0}(1);

        // 6. and it can never be upgraded again: _authorizeUpgrade is role-gated
        vm.prank(multisig);
        vm.expectRevert(bytes("missing MULTISIG_ROLE"));
        broken.upgradeTo(address(nsImpl));

        // 7. funds remain locked in the proxy
        assertEq(address(proxy).balance, PROXY_FUNDS, "funds stranded");
    }

    // -----------------------------------------------------------------
    // 2. The remediation
    // -----------------------------------------------------------------
    function test_FixPreventsExploit() public {
        BridgeNamespaced live = BridgeNamespaced(address(proxy));
        live.initialize(multisig, emergency, mapperAddr, SEED_GAS);

        // Step 1: ship the guard via a layout-COMPATIBLE upgrade.
        // Same storage model, so every slot keeps its meaning.
        BridgeNamespacedGuarded guarded = new BridgeNamespacedGuarded();
        vm.prank(multisig);
        live.upgradeTo(address(guarded));

        BridgeNamespacedGuarded g = BridgeNamespacedGuarded(address(proxy));

        assertTrue(g.hasRole(g.MULTISIG_ROLE(), multisig), "fix: roles preserved");
        assertEq(g.Mapper(), mapperAddr, "fix: Mapper preserved");
        assertEq(g.gasAccumulated(), SEED_GAS, "fix: accounting preserved");
        assertEq(g.status(), 1, "fix: guard intact");

        // Step 2: the dangerous cross-layout upgrade is now rejected
        // up front, instead of silently bricking the proxy.
        vm.prank(multisig);
        vm.expectRevert(bytes("incompatible storage layout"));
        g.upgradeTo(address(linImpl));

        // Step 3: absolutely nothing changed.
        assertTrue(g.hasRole(g.MULTISIG_ROLE(), multisig), "post: still healthy");
        assertEq(g.Mapper(), mapperAddr, "post: still healthy");
        assertEq(g.gasAccumulated(), SEED_GAS, "post: still healthy");
        assertEq(g.status(), 1, "post: still healthy");

        // Step 4: the bridge is fully operable.
        vm.deal(multisig, 1 ether);
        vm.prank(multisig);
        g.bridgeTokens{value: 0.5 ether}(1);
        assertEq(g.gasAccumulated(), SEED_GAS + 0.5 ether, "post: bridge operable");
    }
}
