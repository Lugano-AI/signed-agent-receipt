import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkArtifacts, renderReport, RESULT } from "../src/verify.mjs";
import { validateIssuerTrust, validateReceipt } from "../src/profile.mjs";
import {
  ISSUER_PRIVATE_PEM,
  ISSUER_PUBLIC_PEM,
  LOG_PRIVATE_PEM,
  LOG_PUBLIC_PEM,
} from "../fixtures/test-keys.mjs";
import { buildFixtureSet } from "../tools/fixture-api.mjs";
import { assert, bytes, checkStatus, clone, expectCode } from "./assertions.mjs";

function fixture(size = 8) {
  return buildFixtureSet({
    size,
    issuerPrivateKey: ISSUER_PRIVATE_PEM,
    issuerPublicKey: ISSUER_PUBLIC_PEM,
    logPrivateKey: LOG_PRIVATE_PEM,
    logPublicKey: LOG_PUBLIC_PEM,
  });
}

function reportFor(set, receipt = set.receipts[0], overrides = {}) {
  return checkArtifacts({
    receiptBytes: bytes(receipt),
    issuerTrustBytes: bytes(set.issuerTrust),
    logTrustBytes: bytes(set.logTrust),
    treeHeadBytes: bytes(set.treeHead),
    ...overrides,
  });
}

function alteredDigest(value) {
  return `sha256:${value.slice("sha256:".length).replace(/^./, (character) => (character === "0" ? "1" : "0"))}`;
}

function longFormOuterSequence(base64url) {
  const der = Buffer.from(base64url, "base64url");
  assert.equal(der[0], 0x30);
  assert.ok(der[1] < 0x80);
  return Buffer.concat([Buffer.from([0x30, 0x81, der[1]]), der.subarray(2)]).toString("base64url");
}

export function runVerifierTests() {
  // Full artifact pipeline across powers and uneven trees, every index.
  for (let size = 1; size <= 64; size += 1) {
    const set = fixture(size);
    for (const receipt of set.receipts) {
      const report = reportFor(set, receipt);
      assert.equal(report.result, RESULT.PASSED, `valid ${size}/${receipt.inclusion.leaf_index}`);
    }
  }

  const set = fixture(8);
  const valid = set.receipts[3];
  const maximumInventory = clone(valid);
  maximumInventory.statement.receipt.inventory.tool_artifacts = Array(16).fill(valid.statement.receipt.inventory.tool_artifacts[0]);
  assert.doesNotThrow(() => validateReceipt(maximumInventory));
  const excessInventory = clone(maximumInventory);
  excessInventory.statement.receipt.inventory.tool_artifacts.push(valid.statement.receipt.inventory.tool_artifacts[0]);
  expectCode(() => validateReceipt(excessInventory), "invalid-receipt-inventory");
  const maximumTrust = clone(set.issuerTrust);
  maximumTrust.issuers = Array.from({ length: 16 }, (_, index) => ({
    ...set.issuerTrust.issuers[0],
    key_id: `issuer-bound-${index}`,
  }));
  assert.doesNotThrow(() => validateIssuerTrust(maximumTrust));
  const excessTrust = clone(maximumTrust);
  excessTrust.issuers.push({ ...maximumTrust.issuers[0], key_id: "issuer-bound-extra" });
  expectCode(() => validateIssuerTrust(excessTrust), "invalid-issuer-trust");
  const success = reportFor(set, valid);
  assert.equal(success.result, RESULT.PASSED);
  const rendered = renderReport(success);
  assert.match(rendered, /RESULT: ARTIFACT CHECKS PASSED/);
  assert.match(rendered, /NOT ESTABLISHED: agent execution/);
  assert.doesNotMatch(rendered, /VERIFIED/);

  const noTrust = checkArtifacts({ receiptBytes: bytes(valid) });
  assert.equal(noTrust.result, RESULT.UNTRUSTED);
  checkStatus(noTrust, "issuer_trust", "UNTRUSTED");
  const noHead = checkArtifacts({ receiptBytes: bytes(valid), issuerTrustBytes: bytes(set.issuerTrust), logTrustBytes: bytes(set.logTrust) });
  assert.equal(noHead.result, RESULT.UNTRUSTED);
  checkStatus(noHead, "tree_head", "UNTRUSTED");

  const tamperedStatement = clone(valid);
  tamperedStatement.statement.receipt.assertions.runtime_artifact = alteredDigest(tamperedStatement.statement.receipt.assertions.runtime_artifact);
  const tamperedStatementReport = reportFor(set, tamperedStatement);
  assert.equal(tamperedStatementReport.result, RESULT.FAILED);
  checkStatus(tamperedStatementReport, "issuer_signature", "FAIL");

  const copiedHeadSignature = clone(valid);
  copiedHeadSignature.signature = set.treeHead.signature;
  const copiedSignatureReport = reportFor(set, copiedHeadSignature);
  assert.equal(copiedSignatureReport.result, RESULT.FAILED);
  checkStatus(copiedSignatureReport, "issuer_signature", "FAIL");

  const corruptedPath = clone(valid);
  corruptedPath.inclusion.path[0] = alteredDigest(corruptedPath.inclusion.path[0]);
  const corruptedPathReport = reportFor(set, corruptedPath);
  assert.equal(corruptedPathReport.result, RESULT.FAILED);
  checkStatus(corruptedPathReport, "merkle_inclusion", "FAIL");
  const shortPath = clone(valid);
  shortPath.inclusion.path.pop();
  const shortPathReport = reportFor(set, shortPath);
  assert.equal(shortPathReport.result, RESULT.FAILED);
  checkStatus(shortPathReport, "receipt_profile", "FAIL");
  const longPath = clone(valid);
  longPath.inclusion.path.push(set.treeHead.head.root);
  const longPathReport = reportFor(set, longPath);
  assert.equal(longPathReport.result, RESULT.FAILED);
  checkStatus(longPathReport, "receipt_profile", "FAIL");
  const reorderedPath = clone(valid);
  reorderedPath.inclusion.path.reverse();
  const reorderedReport = reportFor(set, reorderedPath);
  assert.equal(reorderedReport.result, RESULT.FAILED);
  checkStatus(reorderedReport, "merkle_inclusion", "FAIL");

  const mismatchedIndex = clone(valid);
  mismatchedIndex.inclusion.leaf_index = "4";
  const mismatchedIndexReport = reportFor(set, mismatchedIndex);
  assert.equal(mismatchedIndexReport.result, RESULT.FAILED);
  checkStatus(mismatchedIndexReport, "merkle_inclusion", "FAIL");
  const forgedRootHead = clone(set.treeHead);
  forgedRootHead.head.root = alteredDigest(forgedRootHead.head.root);
  const forgedRootReport = reportFor(set, valid, { treeHeadBytes: bytes(forgedRootHead) });
  assert.equal(forgedRootReport.result, RESULT.FAILED);
  checkStatus(forgedRootReport, "merkle_inclusion", "FAIL");
  const timestampedHead = clone(set.treeHead);
  timestampedHead.head.timestamp = "not-allowed";
  const timestampedHeadReport = reportFor(set, valid, { treeHeadBytes: bytes(timestampedHead) });
  assert.equal(timestampedHeadReport.result, RESULT.FAILED);
  checkStatus(timestampedHeadReport, "tree_head", "FAIL");

  const missingInventory = clone(valid);
  delete missingInventory.statement.receipt.inventory.file_artifacts;
  const missingInventoryReport = reportFor(set, missingInventory);
  assert.equal(missingInventoryReport.result, RESULT.FAILED);
  checkStatus(missingInventoryReport, "receipt_profile", "FAIL");
  const unknownReceiptField = clone(valid);
  unknownReceiptField.extra = "not-allowed";
  const unknownReceiptReport = reportFor(set, unknownReceiptField);
  assert.equal(unknownReceiptReport.result, RESULT.FAILED);
  checkStatus(unknownReceiptReport, "receipt_profile", "FAIL");
  const badAlgorithm = clone(valid);
  badAlgorithm.statement.issuer.algorithm = "ed25519";
  const badAlgorithmReport = reportFor(set, badAlgorithm);
  assert.equal(badAlgorithmReport.result, RESULT.FAILED);
  checkStatus(badAlgorithmReport, "receipt_profile", "FAIL");
  const paddedSignature = clone(valid);
  paddedSignature.signature = `${paddedSignature.signature}=`;
  const paddedSignatureReport = reportFor(set, paddedSignature);
  assert.equal(paddedSignatureReport.result, RESULT.FAILED);
  checkStatus(paddedSignatureReport, "receipt_profile", "FAIL");
  const uppercaseDigest = clone(valid);
  uppercaseDigest.statement.receipt.assertions.policy_artifact = uppercaseDigest.statement.receipt.assertions.policy_artifact.toUpperCase();
  const uppercaseDigestReport = reportFor(set, uppercaseDigest);
  assert.equal(uppercaseDigestReport.result, RESULT.FAILED);
  checkStatus(uppercaseDigestReport, "receipt_profile", "FAIL");

  const rawNestedDuplicate = JSON.stringify(valid).replace(
    `"runtime_artifact":"${valid.statement.receipt.assertions.runtime_artifact}"`,
    `"runtime_artifact":"${valid.statement.receipt.assertions.runtime_artifact}","\\u0072untime_artifact":"${valid.statement.receipt.assertions.runtime_artifact}"`,
  );
  const nestedDuplicateReport = checkArtifacts({
    receiptBytes: Buffer.from(rawNestedDuplicate, "utf8"),
    issuerTrustBytes: bytes(set.issuerTrust),
    logTrustBytes: bytes(set.logTrust),
    treeHeadBytes: bytes(set.treeHead),
  });
  assert.equal(nestedDuplicateReport.result, RESULT.FAILED);
  checkStatus(nestedDuplicateReport, "receipt_profile", "FAIL");
  const duplicateTrust = Buffer.from(`{"profile":"sar-ri-issuer-trust-v0.2","\\u0070rofile":"sar-ri-issuer-trust-v0.2","issuers":[]}`, "utf8");
  const duplicateTrustReport = checkArtifacts({ receiptBytes: bytes(valid), issuerTrustBytes: duplicateTrust, logTrustBytes: bytes(set.logTrust), treeHeadBytes: bytes(set.treeHead) });
  assert.equal(duplicateTrustReport.result, RESULT.FAILED);
  checkStatus(duplicateTrustReport, "issuer_trust", "FAIL");

  const wrongIssuer = generateKeyPairSync("ed25519");
  const substitutedIssuerTrust = clone(set.issuerTrust);
  substitutedIssuerTrust.issuers[0].spki = Buffer.from(wrongIssuer.publicKey.export({ type: "spki", format: "der" })).toString("base64url");
  const substitutedIssuerReport = reportFor(set, valid, { issuerTrustBytes: bytes(substitutedIssuerTrust) });
  assert.equal(substitutedIssuerReport.result, RESULT.FAILED);
  checkStatus(substitutedIssuerReport, "issuer_signature", "FAIL");
  const swappedRolesReport = reportFor(set, valid, { issuerTrustBytes: bytes(set.logTrust), logTrustBytes: bytes(set.issuerTrust) });
  assert.equal(swappedRolesReport.result, RESULT.FAILED);
  checkStatus(swappedRolesReport, "issuer_trust", "FAIL");

  const { publicKey: rsaPublic } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaTrust = clone(set.issuerTrust);
  rsaTrust.issuers[0].spki = Buffer.from(rsaPublic.export({ type: "spki", format: "der" })).toString("base64url");
  const rsaTrustReport = reportFor(set, valid, { issuerTrustBytes: bytes(rsaTrust) });
  assert.equal(rsaTrustReport.result, RESULT.FAILED);
  checkStatus(rsaTrustReport, "issuer_trust", "FAIL");

  const overlapSet = buildFixtureSet({
    size: 3,
    issuerPrivateKey: ISSUER_PRIVATE_PEM,
    issuerPublicKey: ISSUER_PUBLIC_PEM,
    logPrivateKey: ISSUER_PRIVATE_PEM,
    logPublicKey: ISSUER_PUBLIC_PEM,
  });
  const overlapReport = reportFor(overlapSet, overlapSet.receipts[1]);
  assert.equal(overlapReport.result, RESULT.FAILED);
  checkStatus(overlapReport, "issuer_log_key_separation", "FAIL");
  const alternateSpkiTrust = clone(set.logTrust);
  alternateSpkiTrust.logs[0].spki = longFormOuterSequence(alternateSpkiTrust.logs[0].spki);
  const alternateSpkiReport = reportFor(set, valid, { logTrustBytes: bytes(alternateSpkiTrust) });
  assert.equal(alternateSpkiReport.result, RESULT.FAILED);
  checkStatus(alternateSpkiReport, "log_trust", "FAIL");

  const fixtureDirectory = fileURLToPath(new URL("../fixtures/valid/size-17/", import.meta.url));
  const fileBytes = (name) => readFileSync(join(fixtureDirectory, name));
  for (let index = 0; index < 17; index += 1) {
    const report = checkArtifacts({
      receiptBytes: fileBytes(`receipt-${index}.json`),
      issuerTrustBytes: fileBytes("issuer-trust.json"),
      logTrustBytes: fileBytes("log-trust.json"),
      treeHeadBytes: fileBytes("tree-head.json"),
    });
    assert.equal(report.result, RESULT.PASSED, `checked-in fixture ${index}`);
  }
}
