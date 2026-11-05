import { createHash } from "node:crypto";
import { auditPathLength, inclusionRoot, leafHash } from "../src/merkle.mjs";
import { assert, expectCode } from "./assertions.mjs";
import { oracleAuditPath, oracleLeaf, oracleRootFromPath, oracleTreeHash } from "./oracle.mjs";

function changedHash(value) {
  const copy = Buffer.from(value);
  copy[0] ^= 0x80;
  return copy;
}

export function runMerkleTests() {
  // This covers size 1, every power/uneven size through 64, and every index.
  // All expected roots and paths come from test/oracle.mjs, not verifier code.
  for (let size = 1; size <= 64; size += 1) {
    const inputs = Array.from({ length: size }, (_, index) => Buffer.from(`independent-leaf-${size}-${index}`, "utf8"));
    const leaves = inputs.map(oracleLeaf);
    const expectedRoot = oracleTreeHash(leaves);
    for (let index = 0; index < size; index += 1) {
      const path = oracleAuditPath(leaves, index);
      assert.equal(auditPathLength(index, size), path.length, `path length ${size}/${index}`);
      const root = inclusionRoot(leafHash(inputs[index]), index, size, path);
      assert.deepEqual(root, expectedRoot, `root ${size}/${index}`);
      assert.deepEqual(oracleRootFromPath(leaves[index], index, size, path), expectedRoot);

      if (path.length > 0) {
        expectCode(() => inclusionRoot(leafHash(inputs[index]), index, size, path.slice(1)), "inclusion-proof-too-short");
      }
      expectCode(() => inclusionRoot(leafHash(inputs[index]), index, size, [...path, Buffer.alloc(32)]), "inclusion-proof-too-long");
      if (path.length > 0) {
        assert.notDeepEqual(inclusionRoot(leafHash(inputs[index]), index, size, [changedHash(path[0]), ...path.slice(1)]), expectedRoot);
      }
      if (path.length > 1) {
        assert.notDeepEqual(inclusionRoot(leafHash(inputs[index]), index, size, [...path].reverse()), expectedRoot);
      }
    }
  }

  const single = leafHash(Buffer.from("size-one", "utf8"));
  assert.deepEqual(inclusionRoot(single, 0, 1, []), single);
  expectCode(() => inclusionRoot(single, 0, 1, [Buffer.alloc(32)]), "inclusion-proof-too-long");
  expectCode(() => inclusionRoot(single, 1, 1, []), "leaf-index-out-of-range");
  expectCode(() => inclusionRoot(single, 0, 2, [Buffer.alloc(31)]), "invalid-inclusion-path");

  // Lock the SHA-256 construction itself to an independent direct hash.
  const sample = Buffer.from("leaf-domain-check", "ascii");
  assert.deepEqual(leafHash(sample), createHash("sha256").update(Buffer.from([0])).update(sample).digest());
}
