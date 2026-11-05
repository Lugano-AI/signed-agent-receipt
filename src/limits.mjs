// These limits are part of the SAR-RI v0.2 profile, not host recommendations.
export const LIMITS = Object.freeze({
  maxInputBytes: 256 * 1024,
  maxDepth: 32,
  maxNodes: 1024,
  maxObjectMembers: 32,
  maxArrayItems: 64,
  maxStringCodeUnits: 8192,
  maxIdLength: 64,
  maxInventoryItems: 16,
  maxTrustEntries: 16,
  maxTreeSize: 2_147_483_647,
  maxProofItems: 31,
  minSpkiBytes: 32,
  maxSpkiBytes: 1024,
  signatureBytes: 64,
  digestBytes: 32,
});
