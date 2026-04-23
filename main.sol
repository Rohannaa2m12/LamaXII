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
    event LMX_FeeCurve(uint16 makerBps, uint16 takerBps, uint16 claimBps, uint32 feeFloor);
    event LMX_MarketListed(uint256 indexed marketId, bytes32 indexed symbol, uint40 openAt, uint40 lockAt, uint40 closeAt);
    event LMX_BetSlip(uint256 indexed marketId, address indexed user, uint8 indexed bucket, uint128 stake, uint128 fee);
    event LMX_MarketCancelled(uint256 indexed marketId, bytes32 reasonHash);
    event LMX_MarketSettled(uint256 indexed marketId, uint64 indexed priceE8, uint8 indexed winnerBucket, uint128 totalPool, uint128 winningPool);
    event LMX_Claimed(uint256 indexed marketId, address indexed user, uint128 payout, uint128 stakeBack, uint8 bucket);
    event LMX_ProtocolSweep(address indexed to, uint256 amount);
    event LMX_MarketSwept(uint256 indexed marketId, uint256 amount, address indexed to);

    uint256 public constant LMX_BUCKETS = 3;
    uint8 internal constant _B_UP = 0;
    uint8 internal constant _B_DOWN = 1;
    uint8 internal constant _B_FLAT = 2;
    uint256 internal constant _FLAG_SETTLED = 0;
    uint256 internal constant _FLAG_CANCELLED = 1;
    uint256 internal constant _FLAG_SWEPT = 2;

    bytes32 public constant LMX_BOOT_SALT = keccak256("LamaXII.bootsalt.violet-hedge");
    bytes32 public constant LMX_MARKET_TYPEHASH = keccak256(
        "MarketSettle(uint256 marketId,bytes32 symbol,uint64 priceE8,uint40 lockAt,uint40 closeAt,uint256 oracleNonce,bytes32 meta)"
    );
    bytes32 public constant LMX_ORACLE_ROTATE_TYPEHASH =
        keccak256("OracleRotate(address oracle,uint256 effectiveAt,uint256 nonce,bytes32 memo)");

    IERC20 public immutable COLLATERAL;
    uint8 public immutable COLLATERAL_DECIMALS;

    address public oracleSigner;
    address public feeVault;
    uint16 public makerFeeBps;
    uint16 public takerFeeBps;
    uint16 public claimFeeBps;
    uint32 public feeFloor;

    uint32 public immutable LMX_MIN_OPEN;
    uint32 public immutable LMX_MIN_LOCK_GAP;
    uint32 public immutable LMX_MIN_CLOSE_GAP;
    uint32 public immutable LMX_MAX_HORIZON;
    uint128 public immutable LMX_MIN_STAKE;
    uint128 public immutable LMX_MAX_STAKE;

    event LMX_OracleScheduled(address indexed nextOracle, uint40 indexed executeAfter, bytes32 memo);
    event LMX_OracleActivated(address indexed oracle, address indexed by);

    address public scheduledOracle;
    uint40 public scheduledOracleAt;
    bytes32 public scheduledOracleMemo;

    struct MarketFrame {
        bytes32 symbol;
        uint40 openAt;
        uint40 lockAt;
        uint40 closeAt;
        uint64 strikeE8;
        uint32 flatBandE8;
        uint32 maxBets;
        uint32 feeHint;
    }
    struct MarketPools {
        uint128 poolUp;
        uint128 poolDown;
        uint128 poolFlat;
        uint128 poolTotal;
        uint128 feeTotal;
    }
    struct MarketSettle {
        uint64 priceE8;
        uint8 winnerBucket;
        uint40 settledAt;
        uint40 oracleLockAt;
        uint40 oracleCloseAt;
        bytes32 meta;
    }
    struct Ticket {
        uint128 stake;
        uint8 bucket;
        bool claimed;
    }

    uint256 public marketCount;
    mapping(uint256 => MarketFrame) public markets;
    mapping(uint256 => MarketPools) public pools;
    mapping(uint256 => MarketSettle) public settles;
    mapping(uint256 => uint256) public marketFlags;
    mapping(uint256 => mapping(address => Ticket)) public tickets;
    mapping(uint256 => uint32) public participantCount;
    mapping(uint256 => mapping(address => uint128)) public stakeByUser;
    uint256 public oracleNonce;
    mapping(bytes32 => bool) public usedOracleDigests;

    constructor(
        address owner_,
        address guardian_,
        address collateral_,
        address oracleSigner_,
        address feeVault_,
        uint16 makerFeeBps_,
        uint16 takerFeeBps_,
        uint16 claimFeeBps_,
        uint32 feeFloor_,
        uint32 minOpen_,
        uint32 minLockGap_,
        uint32 minCloseGap_,
        uint32 maxHorizon_,
        uint128 minStake_,
        uint128 maxStake_
    ) LMX_Own2Step(owner_) LMX_Pause(guardian_) LMX_EIP712Domain("LamaXII", "12") {
        if (collateral_ == address(0)) revert LMXx_BadAsset();
        if (oracleSigner_ == address(0) || feeVault_ == address(0)) revert LMXx_BadCfg();
        if (makerFeeBps_ > 950 || takerFeeBps_ > 950 || claimFeeBps_ > 950) revert LMXx_FeeTooHigh();
        if (minStake_ == 0 || maxStake_ == 0 || minStake_ > maxStake_) revert LMXx_BadCfg();
        if (minOpen_ < 7 || minLockGap_ < 31 || minCloseGap_ < 31 || maxHorizon_ < 180) revert LMXx_BadCfg();

        COLLATERAL = IERC20(collateral_);
        uint8 dec = 18;
        (bool ok, bytes memory data) = collateral_.staticcall(abi.encodeWithSelector(IERC20Metadata.decimals.selector));
        if (ok && data.length >= 32) dec = uint8(uint256(bytes32(data)));
        COLLATERAL_DECIMALS = dec;

        oracleSigner = oracleSigner_;
        feeVault = feeVault_;
        makerFeeBps = makerFeeBps_;
        takerFeeBps = takerFeeBps_;
        claimFeeBps = claimFeeBps_;
        feeFloor = feeFloor_;

        LMX_MIN_OPEN = minOpen_;
        LMX_MIN_LOCK_GAP = minLockGap_;
        LMX_MIN_CLOSE_GAP = minCloseGap_;
        LMX_MAX_HORIZON = maxHorizon_;
        LMX_MIN_STAKE = minStake_;
        LMX_MAX_STAKE = maxStake_;

        bytes32 bootId = keccak256(
            abi.encodePacked(
                LMX_BOOT_SALT,
                address(this),
                block.chainid,
                owner_,
                guardian_,
                collateral_,
                oracleSigner_,
                feeVault_,
                block.timestamp,
                block.prevrandao
            )
        );
        emit LMX_TerminalBoot(bootId, owner_, guardian_, collateral_);
        emit LMX_RoleShift(msg.sender, oracleSigner_, feeVault_);
        emit LMX_FeeCurve(makerFeeBps_, takerFeeBps_, claimFeeBps_, feeFloor_);
    }

    receive() external payable { revert LMXx_BadCfg(); }
    fallback() external payable { revert LMXx_BadCfg(); }

    function isSettled(uint256 marketId) public view returns (bool) { return marketFlags[marketId].get(_FLAG_SETTLED); }
    function isCancelled(uint256 marketId) public view returns (bool) { return marketFlags[marketId].get(_FLAG_CANCELLED); }
    function isSwept(uint256 marketId) public view returns (bool) { return marketFlags[marketId].get(_FLAG_SWEPT); }

    function quoteFee(uint256 stake, bool isTaker) public view returns (uint256 fee) {
        uint256 bps = isTaker ? takerFeeBps : makerFeeBps;
        fee = LMX_Math.mulDivUp(stake, bps, 10_000);
        if (fee < feeFloor) fee = feeFloor;
        if (fee > stake) fee = stake;
    }

    function previewBucket(uint64 strikeE8, uint32 flatBandE8, uint64 finalPriceE8) public pure returns (uint8) {
        uint256 delta = LMX_Math.absDiff(uint256(finalPriceE8), uint256(strikeE8));
        if (delta <= uint256(flatBandE8)) return _B_FLAT;
        return finalPriceE8 > strikeE8 ? _B_UP : _B_DOWN;
    }

    function poolOf(uint256 marketId, uint8 bucket) public view returns (uint128) {
        MarketPools memory ps = pools[marketId];
        if (bucket == _B_UP) return ps.poolUp;
        if (bucket == _B_DOWN) return ps.poolDown;
        if (bucket == _B_FLAT) return ps.poolFlat;
        revert LMXx_BadBucket();
    }

    function setRoles(address oracleSigner_, address feeVault_) external onlyOwner {
        if (oracleSigner_ == address(0) || feeVault_ == address(0)) revert LMXx_BadCfg();
        oracleSigner = oracleSigner_;
        feeVault = feeVault_;
        emit LMX_RoleShift(msg.sender, oracleSigner_, feeVault_);
    }

    function setFees(uint16 makerFeeBps_, uint16 takerFeeBps_, uint16 claimFeeBps_, uint32 feeFloor_) external onlyOwner {
        if (makerFeeBps_ > 950 || takerFeeBps_ > 950 || claimFeeBps_ > 950) revert LMXx_FeeTooHigh();
        makerFeeBps = makerFeeBps_;
        takerFeeBps = takerFeeBps_;
        claimFeeBps = claimFeeBps_;
        feeFloor = feeFloor_;
        emit LMX_FeeCurve(makerFeeBps_, takerFeeBps_, claimFeeBps_, feeFloor_);
    }

    function listMarket(
        bytes32 symbol,
        uint40 openAt,
        uint40 lockAt,
        uint40 closeAt,
        uint64 strikeE8,
        uint32 flatBandE8,
        uint32 maxBets,
        uint32 feeHint
    ) external onlyOwner whenLive returns (uint256 marketId) {
        if (symbol == bytes32(0)) revert LMXx_BadSymbol();
        uint256 nowT = block.timestamp;
        if (openAt < nowT + LMX_MIN_OPEN) revert LMXx_BadWindow();
        if (lockAt < openAt + LMX_MIN_LOCK_GAP) revert LMXx_BadWindow();
        if (closeAt < lockAt + LMX_MIN_CLOSE_GAP) revert LMXx_BadWindow();
        if (closeAt > nowT + LMX_MAX_HORIZON) revert LMXx_BadWindow();
        if (strikeE8 == 0) revert LMXx_BadCfg();
        if (flatBandE8 == 0 || flatBandE8 > 5_000_000_000) revert LMXx_BadCfg();
        marketId = ++marketCount;
        markets[marketId] = MarketFrame(symbol, openAt, lockAt, closeAt, strikeE8, flatBandE8, maxBets, feeHint);
        emit LMX_MarketListed(marketId, symbol, openAt, lockAt, closeAt);
    }

    function listMarketBatch(MarketFrame[] calldata frames) external onlyOwner whenLive returns (uint256 firstId, uint256 lastId) {
        uint256 n = frames.length;
        if (n == 0) revert LMXx_BadCfg();
        firstId = marketCount + 1;
        for (uint256 i = 0; i < n; i++) {
            MarketFrame calldata f = frames[i];
            _listOne(f.symbol, f.openAt, f.lockAt, f.closeAt, f.strikeE8, f.flatBandE8, f.maxBets, f.feeHint);
        }
        lastId = marketCount;
    }

    function _listOne(
        bytes32 symbol,
        uint40 openAt,
        uint40 lockAt,
        uint40 closeAt,
        uint64 strikeE8,
        uint32 flatBandE8,
        uint32 maxBets,
        uint32 feeHint
    ) internal {
        if (symbol == bytes32(0)) revert LMXx_BadSymbol();
        uint256 nowT = block.timestamp;
        if (openAt < nowT + LMX_MIN_OPEN) revert LMXx_BadWindow();
        if (lockAt < openAt + LMX_MIN_LOCK_GAP) revert LMXx_BadWindow();
        if (closeAt < lockAt + LMX_MIN_CLOSE_GAP) revert LMXx_BadWindow();
        if (closeAt > nowT + LMX_MAX_HORIZON) revert LMXx_BadWindow();
        if (strikeE8 == 0) revert LMXx_BadCfg();
        if (flatBandE8 == 0 || flatBandE8 > 5_000_000_000) revert LMXx_BadCfg();
        uint256 marketId = ++marketCount;
        markets[marketId] = MarketFrame(symbol, openAt, lockAt, closeAt, strikeE8, flatBandE8, maxBets, feeHint);
        emit LMX_MarketListed(marketId, symbol, openAt, lockAt, closeAt);
    }

    function tweakMarket(
        uint256 marketId,
        uint64 newStrikeE8,
        uint32 newFlatBandE8,
        uint32 newMaxBets,
        uint32 newFeeHint
    ) external onlyOwner whenLive {
        MarketFrame storage m = markets[marketId];
        if (m.openAt == 0) revert LMXx_BadMarket();
        if (isCancelled(marketId) || isSettled(marketId)) revert LMXx_BadCfg();
        if (block.timestamp >= m.openAt) revert LMXx_Late();
        if (newStrikeE8 == 0) revert LMXx_BadCfg();
        if (newFlatBandE8 == 0 || newFlatBandE8 > 5_000_000_000) revert LMXx_BadCfg();
        m.strikeE8 = newStrikeE8;
        m.flatBandE8 = newFlatBandE8;
        m.maxBets = newMaxBets;
        m.feeHint = newFeeHint;
    }

    function previewPayout(uint256 marketId, address user) external view returns (uint256 gross, uint256 fee, uint256 net, bool winner) {
        Ticket memory tk = tickets[marketId][user];
        if (tk.stake == 0 || tk.claimed) return (0, 0, 0, false);
        if (isCancelled(marketId)) return (tk.stake, 0, tk.stake, true);
        if (!isSettled(marketId)) return (0, 0, 0, false);
        MarketSettle memory st = settles[marketId];
        if (tk.bucket != st.winnerBucket) return (0, 0, 0, false);
        uint128 winPool = poolOf(marketId, st.winnerBucket);
        if (winPool == 0) return (0, 0, 0, false);
        MarketPools memory ps = pools[marketId];
        gross = LMX_Math.mulDivDown(uint256(ps.poolTotal), uint256(tk.stake), uint256(winPool));
        fee = LMX_Math.mulDivUp(gross, claimFeeBps, 10_000);
        net = gross - fee;
        winner = true;
    }

    function symbolKey(string calldata s) external pure returns (bytes32) {
        return keccak256(bytes(s));
    }

    function cancelMarketBatch(uint256[] calldata ids, bytes32 reasonHash) external onlyOwner whenLive {
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 marketId = ids[i];
            if (markets[marketId].openAt == 0) revert LMXx_BadMarket();
            if (isSettled(marketId)) revert LMXx_Settled();
            if (isCancelled(marketId)) continue;
            marketFlags[marketId] = marketFlags[marketId].set(_FLAG_CANCELLED);
            emit LMX_MarketCancelled(marketId, reasonHash);
        }
    }

    function marketRange(uint256 startId, uint256 endId)
        external
        view
        returns (MarketFrame[] memory frames, MarketPools[] memory ps, MarketSettle[] memory st, uint256[] memory flags)
    {
        if (startId == 0 || endId < startId) revert LMXx_BadCfg();
        uint256 last = LMX_Math.min(endId, marketCount);
        uint256 n = last - startId + 1;
        frames = new MarketFrame[](n);
        ps = new MarketPools[](n);
        st = new MarketSettle[](n);
        flags = new uint256[](n);
        uint256 k = 0;
        for (uint256 id = startId; id <= last; id++) {
            frames[k] = markets[id];
            ps[k] = pools[id];
            st[k] = settles[id];
            flags[k] = marketFlags[id];
            unchecked { k++; }
        }
    }

    function marketPhases(uint256[] calldata ids) external view returns (uint8[] memory phases) {
        phases = new uint8[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 marketId = ids[i];
            MarketFrame memory m = markets[marketId];
            if (m.openAt == 0) { phases[i] = 255; continue; }
            uint256 t = block.timestamp;
            if (isCancelled(marketId)) phases[i] = 90;
            else if (isSettled(marketId)) phases[i] = 80;
            else if (t < m.openAt) phases[i] = 0;
            else if (t < m.lockAt) phases[i] = 1;
            else if (t < m.closeAt) phases[i] = 2;
            else phases[i] = 3;
        }
    }

    function userTicket(uint256 marketId, address user) external view returns (uint128 stake, uint8 bucket, bool claimed, uint128 rawStake) {
        Ticket memory tk = tickets[marketId][user];
        stake = tk.stake;
        bucket = tk.bucket;
        claimed = tk.claimed;
        rawStake = stakeByUser[marketId][user];
    }

    function userTickets(uint256[] calldata marketIds, address user)
        external
        view
        returns (uint128[] memory stake, uint8[] memory bucket, bool[] memory claimed)
    {
        stake = new uint128[](marketIds.length);
        bucket = new uint8[](marketIds.length);
        claimed = new bool[](marketIds.length);
        for (uint256 i = 0; i < marketIds.length; i++) {
            Ticket memory tk = tickets[marketIds[i]][user];
            stake[i] = tk.stake;
            bucket[i] = tk.bucket;
            claimed[i] = tk.claimed;
        }
    }

    function quoteFees(uint256[] calldata stakes, bool isTaker) external view returns (uint256[] memory fees) {
        fees = new uint256[](stakes.length);
        for (uint256 i = 0; i < stakes.length; i++) {
            fees[i] = quoteFee(stakes[i], isTaker);
        }
    }

    function previewBucketForMarket(uint256 marketId, uint64 finalPriceE8) external view returns (uint8 bucket) {
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) revert LMXx_BadMarket();
        bucket = previewBucket(m.strikeE8, m.flatBandE8, finalPriceE8);
    }

    function previewBucketsForMarket(uint256 marketId, uint64[] calldata pricesE8) external view returns (uint8[] memory buckets) {
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) revert LMXx_BadMarket();
        buckets = new uint8[](pricesE8.length);
        for (uint256 i = 0; i < pricesE8.length; i++) {
            buckets[i] = previewBucket(m.strikeE8, m.flatBandE8, pricesE8[i]);
        }
    }

    function protocolBalance() external view returns (uint256 bal, uint256 listedMarkets, uint256 nowTs) {
        bal = COLLATERAL.balanceOf(address(this));
        listedMarkets = marketCount;
        nowTs = block.timestamp;
    }

    function marketTimers(uint256 marketId) external view returns (uint256 nowTs, uint256 openAt, uint256 lockAt, uint256 closeAt, int256 toOpen, int256 toLock, int256 toClose) {
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) revert LMXx_BadMarket();
        nowTs = block.timestamp;
        openAt = m.openAt;
        lockAt = m.lockAt;
        closeAt = m.closeAt;
        toOpen = int256(openAt) - int256(nowTs);
        toLock = int256(lockAt) - int256(nowTs);
        toClose = int256(closeAt) - int256(nowTs);
    }

    function isBettingOpen(uint256 marketId) external view returns (bool) {
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) return false;
        if (isCancelled(marketId) || isSettled(marketId)) return false;
        uint256 t = block.timestamp;
        return t >= m.openAt && t < m.lockAt;
    }

    function isClosable(uint256 marketId) external view returns (bool) {
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) return false;
        if (isCancelled(marketId) || isSettled(marketId)) return false;
        return block.timestamp >= m.closeAt;
    }

    function terminalVersion() external pure returns (bytes32 build) {
        build = keccak256("LamaXII.terminal.build.12");
    }

    function bucketLabel(uint8 bucket) external pure returns (bytes32) {
        if (bucket == _B_UP) return keccak256("LMX.BUCKET.UP");
        if (bucket == _B_DOWN) return keccak256("LMX.BUCKET.DOWN");
        if (bucket == _B_FLAT) return keccak256("LMX.BUCKET.FLAT");
        return bytes32(0);
    }

    function placeBet(uint256 marketId, uint8 bucket, uint128 stake, bool isTaker) external nonReentrant whenLive {
        if (stake == 0) revert LMXx_Amount0();
        if (stake < LMX_MIN_STAKE || stake > LMX_MAX_STAKE) revert LMXx_BadCfg();
        if (bucket >= LMX_BUCKETS) revert LMXx_BadBucket();
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) revert LMXx_BadMarket();
        if (isCancelled(marketId)) revert LMXx_Cancelled();
        if (isSettled(marketId)) revert LMXx_Settled();
        uint256 t = block.timestamp;
        if (t < m.openAt) revert LMXx_TooEarly();
        if (t >= m.lockAt) revert LMXx_Late();
        Ticket storage tk = tickets[marketId][msg.sender];
        if (tk.stake != 0) revert LMXx_BadCfg();

        uint256 fee = quoteFee(stake, isTaker);
        uint256 net = stake - fee;
        if (net == 0) revert LMXx_BadCfg();
        COLLATERAL.safeTransferFrom(msg.sender, address(this), stake);

        MarketPools storage ps = pools[marketId];
        ps.poolTotal = uint128(uint256(ps.poolTotal) + net);
        ps.feeTotal = uint128(uint256(ps.feeTotal) + fee);
        if (bucket == _B_UP) ps.poolUp = uint128(uint256(ps.poolUp) + net);
        else if (bucket == _B_DOWN) ps.poolDown = uint128(uint256(ps.poolDown) + net);
        else ps.poolFlat = uint128(uint256(ps.poolFlat) + net);

        if (stakeByUser[marketId][msg.sender] == 0) participantCount[marketId] = participantCount[marketId] + 1;
        stakeByUser[marketId][msg.sender] = stake;

        tk.stake = uint128(net);
        tk.bucket = bucket;
        tk.claimed = false;
        emit LMX_BetSlip(marketId, msg.sender, bucket, uint128(net), uint128(fee));
    }

    function cancelMarket(uint256 marketId, bytes32 reasonHash) external onlyOwner whenLive {
        if (markets[marketId].openAt == 0) revert LMXx_BadMarket();
        if (isSettled(marketId)) revert LMXx_Settled();
        if (isCancelled(marketId)) revert LMXx_Cancelled();
        marketFlags[marketId] = marketFlags[marketId].set(_FLAG_CANCELLED);
        emit LMX_MarketCancelled(marketId, reasonHash);
    }

    function settleMarket(uint256 marketId, uint64 priceE8, uint256 oracleNonce_, bytes32 meta, bytes calldata sig)
        external
        nonReentrant
        whenLive
    {
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) revert LMXx_BadMarket();
        if (isCancelled(marketId)) revert LMXx_Cancelled();
        if (isSettled(marketId)) revert LMXx_Settled();
        if (priceE8 == 0) revert LMXx_PriceInvalid();
        if (block.timestamp < m.closeAt) revert LMXx_TooEarly();
        if (oracleSigner == address(0)) revert LMXx_OracleUnconfigured();
        if (oracleNonce_ <= oracleNonce) revert LMXx_BadNonce();

        bytes32 structHash = keccak256(abi.encode(LMX_MARKET_TYPEHASH, marketId, m.symbol, priceE8, m.lockAt, m.closeAt, oracleNonce_, meta));
        bytes32 digest = _hashTyped(structHash);
        if (usedOracleDigests[digest]) revert LMXx_BadNonce();
        usedOracleDigests[digest] = true;
        address signer = LMX_ECDSA.recover(digest, sig);
        if (signer != oracleSigner) revert LMXx_Unauth();
        oracleNonce = oracleNonce_;

        uint8 win = previewBucket(m.strikeE8, m.flatBandE8, priceE8);
        MarketPools memory ps = pools[marketId];
        uint128 winPool = poolOf(marketId, win);

        marketFlags[marketId] = marketFlags[marketId].set(_FLAG_SETTLED);
        settles[marketId] = MarketSettle(priceE8, win, uint40(block.timestamp), m.lockAt, m.closeAt, meta);
        emit LMX_MarketSettled(marketId, priceE8, win, ps.poolTotal, winPool);
    }

    function claim(uint256 marketId) external nonReentrant {
        Ticket storage tk = tickets[marketId][msg.sender];
        if (tk.claimed) revert LMXx_ClaimNone();
        if (tk.stake == 0) revert LMXx_ClaimNone();

        if (isCancelled(marketId)) {
            tk.claimed = true;
            uint128 back = tk.stake;
            if (back != 0) COLLATERAL.safeTransfer(msg.sender, back);
            emit LMX_Claimed(marketId, msg.sender, back, back, tk.bucket);
            return;
        }

        if (!isSettled(marketId)) revert LMXx_NotSettled();
        MarketSettle memory st = settles[marketId];
        MarketPools memory ps = pools[marketId];
        uint8 b = tk.bucket;
        uint128 userStake = tk.stake;
        uint128 winPool = poolOf(marketId, st.winnerBucket);
        tk.claimed = true;

        if (b != st.winnerBucket || winPool == 0) {
            emit LMX_Claimed(marketId, msg.sender, 0, 0, b);
            return;
        }

        uint256 gross = LMX_Math.mulDivDown(uint256(ps.poolTotal), uint256(userStake), uint256(winPool));
        if (gross > type(uint128).max) revert LMXx_Overflow();
        uint256 fee = LMX_Math.mulDivUp(gross, claimFeeBps, 10_000);
        uint256 net = gross - fee;
        if (net > type(uint128).max) revert LMXx_Overflow();
        pools[marketId].feeTotal = uint128(uint256(pools[marketId].feeTotal) + fee);
        if (net != 0) COLLATERAL.safeTransfer(msg.sender, net);
        emit LMX_Claimed(marketId, msg.sender, uint128(net), 0, b);
    }

    function sweepFees(uint256 amount) external nonReentrant {
        address vault = feeVault;
        if (vault == address(0)) revert LMXx_BadCfg();
        if (msg.sender != vault && msg.sender != owner) revert LMXx_Unauth();
        uint256 bal = COLLATERAL.balanceOf(address(this));
        uint256 x = LMX_Math.min(amount, bal);
        if (x == 0) return;
        COLLATERAL.safeTransfer(vault, x);
        emit LMX_ProtocolSweep(vault, x);
    }

    function sweepMarketRemainder(uint256 marketId, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert LMXx_BadCfg();
        if (!isSettled(marketId) && !isCancelled(marketId)) revert LMXx_TooEarly();
        if (isSwept(marketId)) revert LMXx_BadCfg();
        MarketFrame memory m = markets[marketId];
        if (block.timestamp < uint256(m.closeAt) + 9 days) revert LMXx_TooEarly();
        marketFlags[marketId] = marketFlags[marketId].set(_FLAG_SWEPT);
        uint256 bal = COLLATERAL.balanceOf(address(this));
        uint256 x = LMX_Math.min(amount, bal);
        if (x == 0) return;
        COLLATERAL.safeTransfer(to, x);
        emit LMX_MarketSwept(marketId, x, to);
    }

    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (token == address(COLLATERAL)) revert LMXx_RescueDenied();
        if (to == address(0)) revert LMXx_BadCfg();
        IERC20(token).transfer(to, amount);
    }

    function marketPhase(uint256 marketId) external view returns (uint8 phase) {
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) return 255;
        uint256 t = block.timestamp;
        if (isCancelled(marketId)) return 90;
        if (isSettled(marketId)) return 80;
        if (t < m.openAt) return 0;
        if (t < m.lockAt) return 1;
        if (t < m.closeAt) return 2;
        return 3;
    }

    function marketDigest(uint256 marketId) external view returns (bytes32 d) {
        MarketFrame memory m = markets[marketId];
        if (m.openAt == 0) revert LMXx_BadMarket();
        MarketPools memory ps = pools[marketId];
        d = keccak256(
            abi.encode(
                marketId,
                m.symbol,
                m.openAt,
                m.lockAt,
                m.closeAt,
                m.strikeE8,
                m.flatBandE8,
                ps.poolUp,
                ps.poolDown,
                ps.poolFlat,
                ps.poolTotal,
                ps.feeTotal,
                marketFlags[marketId]
            )
        );
    }

    function batchClaim(uint256[] calldata marketIds) external nonReentrant {
        for (uint256 i = 0; i < marketIds.length; i++) {
            _claimOne(marketIds[i], msg.sender);
        }
    }

    function _claimOne(uint256 marketId, address user) internal {
        Ticket storage tk = tickets[marketId][user];
        if (tk.claimed || tk.stake == 0) return;
        if (isCancelled(marketId)) {
            tk.claimed = true;
            uint128 back = tk.stake;
            if (back != 0) COLLATERAL.safeTransfer(user, back);
            emit LMX_Claimed(marketId, user, back, back, tk.bucket);
            return;
        }
        if (!isSettled(marketId)) return;
        MarketSettle memory st = settles[marketId];
        MarketPools memory ps = pools[marketId];
        uint8 b = tk.bucket;
        uint128 userStake = tk.stake;
        uint128 winPool = poolOf(marketId, st.winnerBucket);
        tk.claimed = true;
        if (b != st.winnerBucket || winPool == 0) {
            emit LMX_Claimed(marketId, user, 0, 0, b);
            return;
        }
        uint256 gross = LMX_Math.mulDivDown(uint256(ps.poolTotal), uint256(userStake), uint256(winPool));
        if (gross > type(uint128).max) revert LMXx_Overflow();
        uint256 fee = LMX_Math.mulDivUp(gross, claimFeeBps, 10_000);
        uint256 net = gross - fee;
        if (net > type(uint128).max) revert LMXx_Overflow();
        pools[marketId].feeTotal = uint128(uint256(pools[marketId].feeTotal) + fee);
        if (net != 0) COLLATERAL.safeTransfer(user, net);
        emit LMX_Claimed(marketId, user, uint128(net), 0, b);
    }

    function rotateOracleBySig(
        address nextOracle,
        uint256 effectiveAt,
        uint256 nonce,
        bytes32 memo,
        bytes calldata sig
    ) external nonReentrant {
        if (nextOracle == address(0)) revert LMXx_BadCfg();
        bytes32 structHash = keccak256(abi.encode(LMX_ORACLE_ROTATE_TYPEHASH, nextOracle, effectiveAt, nonce, memo));
        bytes32 digest = _hashTyped(structHash);
        if (usedOracleDigests[digest]) revert LMXx_BadNonce();
        usedOracleDigests[digest] = true;
        address signer = LMX_ECDSA.recover(digest, sig);
        if (signer != owner) revert LMXx_Unauth();

        if (effectiveAt > block.timestamp) {
            scheduledOracle = nextOracle;
            scheduledOracleAt = uint40(effectiveAt);
            scheduledOracleMemo = memo;
            emit LMX_OracleScheduled(nextOracle, uint40(effectiveAt), memo);
            return;
        }
        oracleSigner = nextOracle;
        emit LMX_OracleActivated(nextOracle, msg.sender);
        emit LMX_RoleShift(msg.sender, oracleSigner, feeVault);
    }

    function executeScheduledOracle() external nonReentrant {
        uint40 at = scheduledOracleAt;
        address next = scheduledOracle;
        if (at == 0 || next == address(0)) revert LMXx_BadCfg();
        if (block.timestamp < at) revert LMXx_TooEarly();
        scheduledOracleAt = 0;
        scheduledOracle = address(0);
        scheduledOracleMemo = bytes32(0);
        oracleSigner = next;
        emit LMX_OracleActivated(next, msg.sender);
        emit LMX_RoleShift(msg.sender, oracleSigner, feeVault);
    }

    function terminalFingerprint() external view returns (bytes32 fp) {
        fp = keccak256(
            abi.encodePacked(
                "LMX.fp",
                address(this),
                block.chainid,
                owner,
                LMX_GUARDIAN,
                address(COLLATERAL),
                oracleSigner,
                feeVault,
                makerFeeBps,
                takerFeeBps,
                claimFeeBps
            )
        );
    }

    function marketSnapshot(uint256 marketId)
        external
        view
        returns (MarketFrame memory m, MarketPools memory ps, MarketSettle memory st, uint256 flags, uint32 participants, uint8 phase)
    {
        m = markets[marketId];
        if (m.openAt == 0) revert LMXx_BadMarket();
        ps = pools[marketId];
        st = settles[marketId];
        flags = marketFlags[marketId];
        participants = participantCount[marketId];
        if (isCancelled(marketId)) phase = 90;
        else if (isSettled(marketId)) phase = 80;
        else {
            uint256 t = block.timestamp;
            if (t < m.openAt) phase = 0;
            else if (t < m.lockAt) phase = 1;
            else if (t < m.closeAt) phase = 2;
            else phase = 3;
        }
    }

    function marketSnapshots(uint256[] calldata ids)
        external
        view
        returns (MarketFrame[] memory ms, MarketPools[] memory ps, MarketSettle[] memory st, uint256[] memory flags, uint32[] memory participants, uint8[] memory phase)
    {
        uint256 n = ids.length;
        ms = new MarketFrame[](n);
        ps = new MarketPools[](n);
