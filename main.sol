// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
  LamaXII — "bloom-lama terminal / hedge console"
  ERC20-only custody hedge markets with signed settlement.
  Self-contained (no imports), constructor-injected authorities, mainnet-safe patterns.
*/

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IERC20Metadata is IERC20 {
    function decimals() external view returns (uint8);
}

abstract contract LMX_Reentrancy {
    error LMX_Reentered();
    uint256 private _g;
    modifier nonReentrant() {
        if (_g == 2) revert LMX_Reentered();
        _g = 2;
        _;
        _g = 1;
    }
    constructor() { _g = 1; }
}

abstract contract LMX_Pause {
    error LMX_Paused();
    error LMX_NotGuardian();
    event LMX_PauseFlip(bool paused, address indexed by);
    bool public lmxPaused;
    address public immutable LMX_GUARDIAN;
    modifier whenLive() { if (lmxPaused) revert LMX_Paused(); _; }
    constructor(address guardian_) { LMX_GUARDIAN = guardian_; }
    function lmxSetPaused(bool v) external {
        if (msg.sender != LMX_GUARDIAN) revert LMX_NotGuardian();
        lmxPaused = v;
        emit LMX_PauseFlip(v, msg.sender);
    }
}

abstract contract LMX_Own2Step {
    error LMX_NotOwner();
    error LMX_NoPendingOwner();
    error LMX_BadOwner();
    event LMX_OwnerProposed(address indexed currentOwner, address indexed pendingOwner);
    event LMX_OwnerAccepted(address indexed previousOwner, address indexed newOwner);
    address public owner;
    address public pendingOwner;
    modifier onlyOwner() { if (msg.sender != owner) revert LMX_NotOwner(); _; }
    constructor(address owner_) { if (owner_ == address(0)) revert LMX_BadOwner(); owner = owner_; }
    function proposeOwner(address nextOwner) external onlyOwner {
        if (nextOwner == address(0)) revert LMX_BadOwner();
        pendingOwner = nextOwner;
        emit LMX_OwnerProposed(owner, nextOwner);
    }
    function acceptOwner() external {
        address p = pendingOwner;
        if (p == address(0)) revert LMX_NoPendingOwner();
        if (msg.sender != p) revert LMX_NotOwner();
        address prev = owner;
        owner = p;
        pendingOwner = address(0);
        emit LMX_OwnerAccepted(prev, p);
    }
}

library LMX_ECDSA {
    error LMX_BadSig();
    error LMX_BadSigS();
    error LMX_BadSigV();
    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert LMX_BadSig();
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := mload(add(sig, 0x20)) s := mload(add(sig, 0x40)) v := byte(0, mload(add(sig, 0x60))) }
        return recover(digest, v, r, s);
    }
    function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) revert LMX_BadSigS();
        if (v != 27 && v != 28) revert LMX_BadSigV();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert LMX_BadSig();
        return signer;
    }
}

library LMX_SafeERC20 {
    error LMX_ERC20CallFailed();
    error LMX_ERC20BadReturn();
    function safeTransfer(IERC20 t, address to, uint256 a) internal { _call(t, abi.encodeWithSelector(IERC20.transfer.selector, to, a)); }
    function safeTransferFrom(IERC20 t, address f, address to, uint256 a) internal { _call(t, abi.encodeWithSelector(IERC20.transferFrom.selector, f, to, a)); }
    function _call(IERC20 t, bytes memory data) private {
        (bool ok, bytes memory ret) = address(t).call(data);
        if (!ok) revert LMX_ERC20CallFailed();
        if (ret.length == 0) return;
        if (ret.length != 32) revert LMX_ERC20BadReturn();
        if (!abi.decode(ret, (bool))) revert LMX_ERC20BadReturn();
    }
}

library LMX_Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; }
    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) { return a >= b ? a - b : b - a; }
    function mulDivDown(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) { unchecked { z = (x * y) / d; } }
    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) { unchecked { z = (x * y + d - 1) / d; } }
}

library LMX_Bitmap {
    function get(uint256 w, uint256 bit) internal pure returns (bool) { return (w & (1 << bit)) != 0; }
    function set(uint256 w, uint256 bit) internal pure returns (uint256) { return w | (1 << bit); }
}

abstract contract LMX_EIP712Domain {
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 internal immutable _DT;
    bytes32 internal immutable _NH;
    bytes32 internal immutable _VH;
    constructor(string memory n, string memory v) {
        _DT = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        _NH = keccak256(bytes(n));
        _VH = keccak256(bytes(v));
        DOMAIN_SEPARATOR = keccak256(abi.encode(_DT, _NH, _VH, block.chainid, address(this)));
    }
    function _hashTyped(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }
}

contract LamaXII is LMX_Reentrancy, LMX_Own2Step, LMX_Pause, LMX_EIP712Domain {
    using LMX_SafeERC20 for IERC20;
    using LMX_Math for uint256;
    using LMX_Bitmap for uint256;

    // Workspace-unique anchors (not authority, not sinks)
    address public constant LMX_ANCHOR_A = 0xb590323b1403C9b6AfeB812235bf58e2f35c18cd;
    address public constant LMX_ANCHOR_B = 0x28B39F8e19aa8F355eC2B3544A14aB7D41d7bea4;
    address public constant LMX_ANCHOR_C = 0xE3C19A25ECacafcc2cFE6B8aE17b540266956E8a;
    address public constant LMX_ANCHOR_D = 0x3c2fA47D0cD3A574BbE8F861827C2e4f01C141Bc;
    address public constant LMX_ANCHOR_E = 0x553eB3157A1d8749E64405cf3FA72D70e3c7d5B7;
    address public constant LMX_ANCHOR_F = 0x8f59883C39e6cf6a9F0273425e787404481c0159;
    address public constant LMX_ANCHOR_G = 0x44bb44dB634DEE4F3E447bb515648B915848F390;
    address public constant LMX_ANCHOR_H = 0x53eD32E9b3B93eb79a73Aa3676d9107De2Cbf5BA;
    address public constant LMX_ANCHOR_I = 0xE9208943966A6Fe3cB463765663233A52c989c07;
    bytes32 internal constant _LMX_SEED_A = hex"d563c42d912d99d2771dd780edd8fbb31643c357c02cb34c266a985cdd3ae9e6";
    bytes32 internal constant _LMX_SEED_B = hex"b9fa684b1795f27baff376edbf2b9f56e60c14c666f8c8218539dedbf104a564";
    bytes32 internal constant _LMX_SEED_C = hex"ad32753fc1639d4cd3c8e857567c6db7cfd1dfd9aa34cbbfdb561b5b2eec2bd4";
    bytes32 internal constant _LMX_SEED_D = hex"1c7bf71eba67c4291b0ac1be7611ac47391e0da71376fa01df694072b5dd125f";
    bytes32 internal constant _LMX_SEED_E = hex"d4e81be342b7a0c8ee0287189674e1c19c3c4d769fd13774bc8a168de27a0f7b";
    bytes32 internal constant _LMX_SEED_F = hex"7387f84147ec19d75ed0a71da5ff3565a90d4aebb264283eb5f71f2c728dadbc";

    error LMXx_BadCfg();
    error LMXx_BadAsset();
    error LMXx_BadMarket();
    error LMXx_BadBucket();
    error LMXx_Late();
    error LMXx_TooEarly();
    error LMXx_Amount0();
    error LMXx_Overflow();
    error LMXx_Unauth();
    error LMXx_Settled();
    error LMXx_Cancelled();
    error LMXx_NotSettled();
    error LMXx_ClaimNone();
    error LMXx_PriceInvalid();
    error LMXx_FeeTooHigh();
    error LMXx_RescueDenied();
    error LMXx_OracleUnconfigured();
    error LMXx_BadNonce();
    error LMXx_BadWindow();
    error LMXx_BadSymbol();

    event LMX_TerminalBoot(bytes32 indexed bootId, address indexed owner, address indexed guardian, address asset);
    event LMX_RoleShift(address indexed by, address indexed oracle, address indexed feeVault);
