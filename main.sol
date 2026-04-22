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
