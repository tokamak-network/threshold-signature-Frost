// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./IZecFrost.sol";


/// @title AppManager
/// @notice Keeps a registry of apps and their owners along with Schnorr signing public keys.
///         Computes and stores the signer address derived from the public key as keccak256(pkx || pky)[12:] (last 20 bytes).
/// @dev Each (appid) is owned by a single EOA; only that owner can update or remove the entry.
contract AppManager {
    // ---------- Types ----------
    struct AppInfo {
        address appOwner;     // who may update/remove this app entry
        uint256 pkx;          // signer public key X (secp256k1)
        uint256 pky;          // signer public key Y (secp256k1)
        address signerAddr;   // keccak256(pkx||pky) last 20 bytes
        bool exists;          // sentinel to check presence
    }

    // ---------- Storage ----------
    mapping(uint256 => AppInfo) private apps;
    IZecFrost public zecFrost;        // on-chain verifier contract
    address public owner;             // contract admin for zecFrost updates

    // ---------- Events ----------
    event AppAdded(uint256 indexed appid, address indexed owner, uint256 pkx, uint256 pky, address signerAddr);
    event AppUpdated(uint256 indexed appid, uint256 pkx, uint256 pky, address signerAddr);
    event AppRemoved(uint256 indexed appid);
    event ZecFrostSet(address indexed oldAddr, address indexed newAddr);

    // ---------- Errors ----------
    error AppAlreadyExists(uint256 appid);
    error AppNotFound(uint256 appid);
    error NotAppOwner(uint256 appid, address caller);
    error ZeroAddress();

    // ---------- Modifiers ----------
    modifier onlyAdmin() {
        require(msg.sender == owner, "AppManager: not admin");
        _;
    }

    modifier onlyAppOwner(uint256 appid) {
        AppInfo memory info = apps[appid];
        if (!info.exists) revert AppNotFound(appid);
        if (info.appOwner != msg.sender) revert NotAppOwner(appid, msg.sender);
        _;
    }

    // ---------- Constructor ----------
    /// @param zecFrost_ Address of deployed ZecFrost verifier (can be updated later by admin).
    constructor(address zecFrost_) {
        owner = msg.sender;
        _setZecFrost(zecFrost_);
    }

    // ---------- Admin ----------
    function setZecFrost(address zecFrost_) external onlyAdmin {
        _setZecFrost(zecFrost_);
    }

    function _setZecFrost(address zecFrost_) internal {
        if (zecFrost_ == address(0)) revert ZeroAddress();
        emit ZecFrostSet(address(zecFrost), zecFrost_);
        zecFrost = IZecFrost(zecFrost_);
    }

    // ---------- App CRUD ----------
    /// @notice Register a new app. The caller becomes the app owner.
    /// @dev Fails if the appid already exists.
    function addApp(uint256 appid, uint256 pkx, uint256 pky) external {
        if (apps[appid].exists) revert AppAlreadyExists(appid);
        address signerAddr = _deriveAddressFromPubkey(pkx, pky);
        apps[appid] = AppInfo({
            appOwner: msg.sender,
            pkx: pkx,
            pky: pky,
            signerAddr: signerAddr,
            exists: true
        });
        emit AppAdded(appid, msg.sender, pkx, pky, signerAddr);
    }

    /// @notice Update the public key (and derived signer address) for an existing app.
    /// @dev Only the app owner can call this.
    function updateApp(uint256 appid, uint256 pkx, uint256 pky) external onlyAppOwner(appid) {
        address signerAddr = _deriveAddressFromPubkey(pkx, pky);
        AppInfo storage info = apps[appid];
        info.pkx = pkx;
        info.pky = pky;
        info.signerAddr = signerAddr;
        emit AppUpdated(appid, pkx, pky, signerAddr);
    }

    /// @notice Remove an existing app entry.
    /// @dev Only the app owner can call this.
    function removeApp(uint256 appid) external onlyAppOwner(appid) {
        delete apps[appid];
        emit AppRemoved(appid);
    }

    // ---------- Read ----------
    function getApp(uint256 appid) external view returns (
        address appOwner,
        uint256 pkx,
        uint256 pky,
        address signerAddr,
        bool exists
    ) {
        AppInfo memory info = apps[appid];
        return (info.appOwner, info.pkx, info.pky, info.signerAddr, info.exists);
    }

    /// @notice Verify a Schnorr signature for a registered app by delegating to ZecFrost and comparing addresses.
    /// @param message The 32-byte message digest (already hashed as needed by caller).
    /// @param appid The application id whose public key should be used.
    /// @param rx X coordinate of R.
    /// @param ry Y coordinate of R.
    /// @param z Schnorr scalar component.
    /// @return ok True if recovered address equals the signer address stored for the app.
    function verify(
        bytes32 message,
        uint256 appid,
        uint256 rx,
        uint256 ry,
        uint256 z
    ) external view returns (bool ok) {
        AppInfo memory info = apps[appid];
        if (!info.exists) revert AppNotFound(appid);

        address recovered = zecFrost.verify(
            message,
            info.pkx,
            info.pky,
            rx,
            ry,
            z
        );
        return (recovered == info.signerAddr);
    }

    // ---------- Utils ----------
    /// @dev Derive an Ethereum-style address from the uncompressed public key (x||y).
    ///      Equivalent to address(uint160(uint256(keccak256(abi.encodePacked(pkx, pky))))).
    function _deriveAddressFromPubkey(uint256 pkx, uint256 pky) internal pure returns (address) {
        bytes32 h = keccak256(abi.encodePacked(pkx, pky));
        return address(uint160(uint256(h)));
    }
}
