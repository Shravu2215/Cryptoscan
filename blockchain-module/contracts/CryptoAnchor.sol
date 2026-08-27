// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * CryptoAnchor
 *
 * Anchors the SHA-256 hash of a scan's (findings + CBOM) content on-chain,
 * so any later "verify" call can prove the report wasn't tampered with
 * after the fact — the on-chain hash is the source of truth.
 *
 * Mirrors the Anchor table in backend-core/prisma/schema.prisma:
 *   scanId, contentHash, txHash (implicit — the tx that calls this),
 *   signature is done off-chain by the submitting wallet (msg.sender IS
 *   the signature — no separate signature field needed on-chain).
 */
contract CryptoAnchor {
    struct AnchorRecord {
        bytes32 contentHash;   // sha256 of the off-chain content (findings+cbom)
        address anchoredBy;    // wallet that submitted the anchor (acts as signer)
        uint256 timestamp;     // block timestamp at anchor time
        bool exists;
    }

    // scanId (as bytes32, e.g. keccak256 of the UUID string) => record
    mapping(bytes32 => AnchorRecord) private anchors;

    event ScanAnchored(
        bytes32 indexed scanId,
        bytes32 contentHash,
        address indexed anchoredBy,
        uint256 timestamp
    );

    /**
     * Anchor a scan's content hash. Reverts if this scanId was already
     * anchored — an anchor is a one-time, immutable commitment, not an
     * update. If a scan is re-run, generate a new scanId.
     */
    function anchorScan(bytes32 scanId, bytes32 contentHash) external {
        require(!anchors[scanId].exists, 'CryptoAnchor: scanId already anchored');
        require(contentHash != bytes32(0), 'CryptoAnchor: empty contentHash');

        anchors[scanId] = AnchorRecord({
            contentHash: contentHash,
            anchoredBy: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        emit ScanAnchored(scanId, contentHash, msg.sender, block.timestamp);
    }

    /**
     * Read back the anchored record for verification. The verify service
     * calls this, recomputes the off-chain hash, and compares.
     */
    function getAnchor(bytes32 scanId)
        external
        view
        returns (bytes32 contentHash, address anchoredBy, uint256 timestamp, bool exists)
    {
        AnchorRecord memory rec = anchors[scanId];
        return (rec.contentHash, rec.anchoredBy, rec.timestamp, rec.exists);
    }

    function isAnchored(bytes32 scanId) external view returns (bool) {
        return anchors[scanId].exists;
    }
}
