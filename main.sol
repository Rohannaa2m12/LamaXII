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

