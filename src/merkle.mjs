import { createHash } from "node:crypto";
import { fail } from "./errors.mjs";
import { LIMITS } from "./limits.mjs";

const LEAF_PREFIX = Buffer.from([0]);
const NODE_PREFIX = Buffer.from([1]);

function sha256(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function assertHash(value, code = "invalid-merkle-hash") {
  if (!Buffer.isBuffer(value) || value.length !== LIMITS.digestBytes) fail(code);
}

function assertTreeInputs(leafIndex, treeSize) {
  if (!Number.isSafeInteger(treeSize) || treeSize < 1 || treeSize > LIMITS.maxTreeSize) fail("invalid-tree-size");
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) fail("leaf-index-out-of-range");
}

/** SAR tree leaf: RFC-style leaf prefix over the canonical signed statement. */
export function leafHash(statementBytes) {
  if (!Buffer.isBuffer(statementBytes)) fail("invalid-statement-bytes");
  return sha256(LEAF_PREFIX, statementBytes);
}

/** SAR tree interior-node recurrence: SHA-256(0x01 || left || right). */
export function nodeHash(left, right) {
  assertHash(left);
  assertHash(right);
  return sha256(NODE_PREFIX, left, right);
}

function largestPowerOfTwoLessThan(value) {
  let result = 1;
  while (result * 2 < value) result *= 2;
  return result;
}

/** Number of nodes in the unique recursive RFC-style audit path. */
export function auditPathLength(leafIndex, treeSize) {
  assertTreeInputs(leafIndex, treeSize);
  let index = leafIndex;
  let size = treeSize;
  let count = 0;
  while (size > 1) {
    const split = largestPowerOfTwoLessThan(size);
    if (index < split) {
      size = split;
    } else {
      index -= split;
      size -= split;
    }
    count += 1;
  }
  return count;
}

/**
 * RFC 9162's iterative inclusion verification recurrence. The profile uses
 * this tree hash/audit-path mechanics but does not claim RFC protocol conformance.
 */
export function inclusionRoot(leaf, leafIndex, treeSize, path) {
  assertHash(leaf, "invalid-leaf-hash");
  assertTreeInputs(leafIndex, treeSize);
  if (!Array.isArray(path)) fail("invalid-inclusion-path");
  const expectedLength = auditPathLength(leafIndex, treeSize);
  if (path.length < expectedLength) fail("inclusion-proof-too-short");
  if (path.length > expectedLength) fail("inclusion-proof-too-long");
  for (const entry of path) assertHash(entry, "invalid-inclusion-path");

  let fn = leafIndex;
  let sn = treeSize - 1;
  let root = Buffer.from(leaf);
  for (const sibling of path) {
    if (sn === 0) fail("inclusion-proof-too-long");
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
  if (sn !== 0) fail("inclusion-proof-too-short");
  return root;
}
