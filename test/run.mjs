#!/usr/bin/env node
import { runCliTests } from "./cli.test.mjs";
import { runCryptoAndByteTests } from "./crypto-and-bytes.test.mjs";
import { runMerkleTests } from "./merkle.test.mjs";
import { runStrictJsonTests } from "./strict-json.test.mjs";
import { runVerifierTests } from "./verifier.test.mjs";

const suites = [
  ["strict JSON and canonical bytes", runStrictJsonTests],
  ["crypto and fixed byte vectors", runCryptoAndByteTests],
  ["independent Merkle oracle", runMerkleTests],
  ["profile verifier", runVerifierTests],
  ["CLI and independent fixture generator", runCliTests],
];

let failures = 0;
for (const [name, suite] of suites) {
  try {
    suite();
    process.stdout.write(`PASS ${name}\n`);
  } catch (error) {
    failures += 1;
    // Test failures are local developer output, not the verifier's untrusted
    // input surface. Keep enough stack context to fix a regression.
    process.stderr.write(`FAIL ${name}: ${error?.stack ?? error}\n`);
  }
}
if (failures === 0) process.stdout.write("ALL SAR-RI v0.2 TESTS PASSED\n");
process.exitCode = failures === 0 ? 0 : 1;
