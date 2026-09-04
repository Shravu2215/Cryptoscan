// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CryptoAnchor
 * @notice Anchors cryptographic scan commitments (Merkle root, orgId, scannerVersion,
 * timestamp, and submitter) on-chain for tamper-evident verification.
 *
 * Implements write-once immutable historical records: once anchored, a scanId
 * cannot be overwritten or updated.
 *
 * Enforces role-based write access: only the contract owner or explicitly
 * authorized writers may submit anchors. Read operations are public.
 */
contract CryptoAnchor {
    struct AnchorRecord {
        bytes32 merkleRoot;     // SHA-256 Merkle root of canonical CBOM components
        address anchoredBy;    // Wallet address that submitted the anchor
        uint256 timestamp;     // Block timestamp at anchor submission time
        string orgId;          // Organization or tenant identifier
        string scannerVersion; // Version string of scanner engine (e.g. "1.0.0")
        bool exists;           // True once anchored (immutable flag)
    }

    /// @notice Contract deployer and administrator
    address public owner;

    /// @notice Mapping of accounts authorized to submit scan anchors
    mapping(address => bool) public authorizedWriters;

    /// @notice Mapping from scanId (bytes32 keccak256 of UUID) to its AnchorRecord
    mapping(bytes32 => AnchorRecord) private anchors;

    /// @notice Emitted when a scan is anchored on-chain
    event ScanAnchored(
        bytes32 indexed scanId,
        bytes32 merkleRoot,
        address indexed anchoredBy,
        uint256 timestamp,
        string orgId,
        string scannerVersion
    );

    /// @notice Emitted when a writer is authorized
    event WriterAuthorized(address indexed writer);

    /// @notice Emitted when a writer is revoked
    event WriterRevoked(address indexed writer);

    /// @notice Emitted when contract ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "CryptoAnchor: caller is not the owner");
        _;
    }

    modifier onlyAuthorized() {
        require(msg.sender == owner || authorizedWriters[msg.sender], "CryptoAnchor: unauthorized writer");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedWriters[msg.sender] = true;
        emit WriterAuthorized(msg.sender);
    }

    /**
     * @notice Grants or revokes anchor submission permissions for an account.
     * @param writer Address to authorize or revoke.
     * @param authorized True to authorize, false to revoke.
     */
    function setAuthorizedWriter(address writer, bool authorized) external onlyOwner {
        require(writer != address(0), "CryptoAnchor: invalid writer address");
        authorizedWriters[writer] = authorized;
        if (authorized) {
            emit WriterAuthorized(writer);
        } else {
            emit WriterRevoked(writer);
        }
    }

    /**
     * @notice Transfers ownership of the contract to a new account.
     * @param newOwner Address of the new owner.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "CryptoAnchor: new owner cannot be zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        authorizedWriters[newOwner] = true;
    }

    /**
     * @notice Anchors a scan's Merkle root with organization ID and scanner version.
     * @param scanId Unique 32-byte identifier for the scan (e.g. keccak256 of UUID).
     * @param merkleRoot 32-byte cryptographic Merkle root of the CBOM components.
     * @param orgId Identifier for the organization or tenant.
     * @param scannerVersion Version of the scanner used for this scan.
     */
    function anchorScan(
        bytes32 scanId,
        bytes32 merkleRoot,
        string memory orgId,
        string memory scannerVersion
    ) public onlyAuthorized {
        require(!anchors[scanId].exists, "CryptoAnchor: scanId already anchored");
        require(merkleRoot != bytes32(0), "CryptoAnchor: empty merkleRoot");

        anchors[scanId] = AnchorRecord({
            merkleRoot: merkleRoot,
            anchoredBy: msg.sender,
            timestamp: block.timestamp,
            orgId: orgId,
            scannerVersion: scannerVersion,
            exists: true
        });

        emit ScanAnchored(
            scanId,
            merkleRoot,
            msg.sender,
            block.timestamp,
            orgId,
            scannerVersion
        );
    }

    /**
     * @notice Overload for backward compatibility with 2-parameter callers.
     */
    function anchorScan(bytes32 scanId, bytes32 merkleRoot) external onlyAuthorized {
        anchorScan(scanId, merkleRoot, "default-org", "1.0.0");
    }

    /**
     * @notice Retrieves the anchored record for a given scanId.
     * @param scanId 32-byte scan identifier.
     */
    function getAnchor(bytes32 scanId)
        external
        view
        returns (
            bytes32 merkleRoot,
            address anchoredBy,
            uint256 timestamp,
            string memory orgId,
            string memory scannerVersion,
            bool exists
        )
    {
        AnchorRecord storage rec = anchors[scanId];
        return (
            rec.merkleRoot,
            rec.anchoredBy,
            rec.timestamp,
            rec.orgId,
            rec.scannerVersion,
            rec.exists
        );
    }

    /**
     * @notice Returns true if the scan has already been anchored.
     * @param scanId 32-byte scan identifier.
     */
    function isAnchored(bytes32 scanId) external view returns (bool) {
        return anchors[scanId].exists;
    }
}
