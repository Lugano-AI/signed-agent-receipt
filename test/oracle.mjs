// Independent recursive test oracle. This file intentionally does not import
// src/merkle.mjs or fixture construction helpers.
import { createHash } from "node:crypto";

function hash(...parts) {
  const state = createHash("sha256");
  for (const part of parts) state.update(part);
  return state.digest();
}

export function oracleLeaf(bytes) {
  return hash(Buffer.from([0]), bytes);
}

export function oracleNode(left, right) {
  return hash(Buffer.from([1]), left, right);
}

export function oracleSplit(size) {
  let split = 1;
  while (split * 2 < size) split *= 2;
  return split;
}

export function oracleTreeHash(leaves) {
  if (leaves.length === 0) throw new Error("oracle requires nonempty tree");
  if (leaves.length === 1) return leaves[0];
  const split = oracleSplit(leaves.length);
  return oracleNode(oracleTreeHash(leaves.slice(0, split)), oracleTreeHash(leaves.slice(split)));
}

export function oracleAuditPath(leaves, index) {
  if (leaves.length === 1) return [];
  const split = oracleSplit(leaves.length);
  if (index < split) {
    return [...oracleAuditPath(leaves.slice(0, split), index), oracleTreeHash(leaves.slice(split))];
  }
  return [...oracleAuditPath(leaves.slice(split), index - split), oracleTreeHash(leaves.slice(0, split))];
}

function buildFromPath(leaf, index, size, path, offset) {
  if (size === 1) return { root: leaf, offset };
  const split = oracleSplit(size);
  if (index < split) {
    const left = buildFromPath(leaf, index, split, path, offset);
    if (left.offset >= path.length) throw new Error("oracle short path");
    return { root: oracleNode(left.root, path[left.offset]), offset: left.offset + 1 };
  }
  const right = buildFromPath(leaf, index - split, size - split, path, offset);
  if (right.offset >= path.length) throw new Error("oracle short path");
  return { root: oracleNode(path[right.offset], right.root), offset: right.offset + 1 };
}

export function oracleRootFromPath(leaf, index, size, path) {
  const outcome = buildFromPath(leaf, index, size, path, 0);
  if (outcome.offset !== path.length) throw new Error("oracle long path");
  return outcome.root;
}
