#!/usr/bin/env node
// Independent RFC 9162-style binary Merkle-tree oracle used by this audit.
// It intentionally imports no receipt-v0.2 code.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export const sha256 = (...chunks) => {
  const hash = createHash("sha256");
  for (const chunk of chunks) hash.update(chunk);
  return hash.digest();
};

const LEAF_PREFIX = Buffer.from([0]);
const NODE_PREFIX = Buffer.from([1]);

export const leafHash = (entry) => sha256(LEAF_PREFIX, Buffer.from(entry));
export const nodeHash = (left, right) => sha256(NODE_PREFIX, left, right);

export function largestPowerOfTwoBelow(n) {
  if (!Number.isSafeInteger(n) || n < 2) throw new Error("tree size must be an integer >= 2");
  let result = 1;
  while (result * 2 < n) result *= 2;
  return result;
}

// MTH(D_n), recursively defined in RFC 9162 section 2.1.1.  `entries` are
// raw leaf inputs; leafHash adds the 0x00 prefix exactly once.
export function merkleTreeHash(entries) {
  if (!Array.isArray(entries)) throw new TypeError("entries must be an array");
  if (entries.length === 0) return sha256();
  if (entries.length === 1) return leafHash(entries[0]);
  const split = largestPowerOfTwoBelow(entries.length);
  return nodeHash(
    merkleTreeHash(entries.slice(0, split)),
    merkleTreeHash(entries.slice(split)),
  );
}

// PATH(m, D_n), recursively defined in RFC 9162 section 2.1.3.1.  The path
// is bottom-up, and contains the shortest sequence of sibling node hashes.
export function auditPath(entries, index) {
  if (!Array.isArray(entries) || !Number.isSafeInteger(index) || index < 0 || index >= entries.length) {
    throw new RangeError("index is outside the supplied entries");
  }
  if (entries.length === 1) return [];
  const split = largestPowerOfTwoBelow(entries.length);
  if (index < split) {
    return [...auditPath(entries.slice(0, split), index), merkleTreeHash(entries.slice(split))];
  }
  return [...auditPath(entries.slice(split), index - split), merkleTreeHash(entries.slice(0, split))];
}

// Independently expressed form of RFC 9162 section 2.1.3.2.  It rejects a
// short or surplus path rather than returning a merely partial root.
export function rootFromInclusionPath(leaf, leafIndex, treeSize, path) {
  if (!Buffer.isBuffer(leaf) || leaf.length !== 32) throw new TypeError("leaf hash must be 32 bytes");
  if (!Number.isSafeInteger(treeSize) || treeSize < 1 || !Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
    throw new RangeError("invalid leaf index or tree size");
  }
  if (!Array.isArray(path) || !path.every((node) => Buffer.isBuffer(node) && node.length === 32)) {
    throw new TypeError("path must contain only 32-byte node hashes");
  }

  let fn = leafIndex;
  let sn = treeSize - 1;
  let root = Buffer.from(leaf);
  for (const sibling of path) {
    if (sn === 0) throw new Error("surplus inclusion-path node");
    if (fn % 2 === 1 || fn === sn) {
      root = nodeHash(sibling, root);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      root = nodeHash(root, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error("short inclusion path");
  return root;
}

export function runOracleSelfTest(maxSize = 64) {
  const tested = [];
  for (let size = 1; size <= maxSize; size += 1) {
    const entries = Array.from({ length: size }, (_, index) => Buffer.from(`independent-vector/${size}/${index}`, "utf8"));
    const expected = merkleTreeHash(entries);
    for (let index = 0; index < size; index += 1) {
      const path = auditPath(entries, index);
      assert.deepEqual(rootFromInclusionPath(leafHash(entries[index]), index, size, path), expected);
      tested.push({ size, index, path_length: path.length });
    }
  }
  return tested;
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  const vectors = runOracleSelfTest();
  console.log(JSON.stringify({ oracle: "independent-rfc9162-style", valid_vectors: vectors.length, max_tree_size: 64 }, null, 2));
}
