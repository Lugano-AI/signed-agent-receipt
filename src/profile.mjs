import { canonicalBytes } from "./canonical.mjs";
import { decodeDigest, decodeSignature, assertId, parseDecimal, parseEd25519Spki } from "./encoding.mjs";
import { fail } from "./errors.mjs";
import { LIMITS } from "./limits.mjs";
import { auditPathLength } from "./merkle.mjs";

export const PROFILES = Object.freeze({
  statement: "sar-ri-statement-v0.2",
  treeHead: "sar-ri-tree-head-v0.2",
  issuerTrust: "sar-ri-issuer-trust-v0.2",
  logTrust: "sar-ri-log-trust-v0.2",
});

export const ALGORITHM = "Ed25519";
export const ISSUER_SIGNATURE_PREFIX = Buffer.from("SAR-RI-v0.2\0issuer-signature\0", "ascii");
export const TREE_HEAD_SIGNATURE_PREFIX = Buffer.from("SAR-RI-v0.2\0tree-head-signature\0", "ascii");

export const REQUIRED_SCOPE = Object.freeze({
  evidence: "artifact-digest-only",
  attestation: "not-implemented",
  observation: "not-implemented",
  retention: "not-measured",
  time: "not-authenticated",
  history: "not-checked",
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertRecord(value, code) {
  if (!isRecord(value)) fail(code);
  return value;
}

function assertExactKeys(value, expected, code) {
  assertRecord(value, code);
  const actual = Object.keys(value);
  if (actual.length !== expected.length) fail(code);
  const allowed = new Set(expected);
  for (const key of actual) {
    if (!allowed.has(key)) fail(code);
  }
}

function assertExactString(value, expected, code) {
  if (value !== expected) fail(code);
}

function assertDigest(value, code) {
  try {
    return decodeDigest(value);
  } catch {
    fail(code);
  }
}

function assertDigestArray(value, code, maximum = LIMITS.maxInventoryItems) {
  if (!Array.isArray(value) || value.length > maximum) fail(code);
  return value.map((entry) => assertDigest(entry, code));
}

function assertAlgorithm(value, code) {
  assertExactString(value, ALGORITHM, code);
}

function assertScope(value) {
  const keys = Object.keys(REQUIRED_SCOPE);
  assertExactKeys(value, keys, "invalid-statement-scope");
  for (const key of keys) assertExactString(value[key], REQUIRED_SCOPE[key], "invalid-statement-scope");
}

function assertIssuer(value) {
  assertExactKeys(value, ["algorithm", "key_id"], "invalid-statement-issuer");
  assertAlgorithm(value.algorithm, "invalid-statement-issuer");
  try {
    assertId(value.key_id);
  } catch {
    fail("invalid-statement-issuer");
  }
}

function assertReceiptBody(value) {
  assertExactKeys(value, ["receipt_id", "log_id", "assertions", "inventory", "scope"], "invalid-receipt-body");
  try {
    assertId(value.receipt_id);
    assertId(value.log_id);
  } catch {
    fail("invalid-receipt-body");
  }

  assertExactKeys(value.assertions, ["runtime_artifact", "policy_artifact"], "invalid-receipt-assertions");
  assertDigest(value.assertions.runtime_artifact, "invalid-receipt-assertions");
  assertDigest(value.assertions.policy_artifact, "invalid-receipt-assertions");

  assertExactKeys(
    value.inventory,
    ["tool_artifacts", "egress_artifacts", "file_artifacts", "payment_artifacts"],
    "invalid-receipt-inventory",
  );
  assertDigestArray(value.inventory.tool_artifacts, "invalid-receipt-inventory");
  assertDigestArray(value.inventory.egress_artifacts, "invalid-receipt-inventory");
  assertDigestArray(value.inventory.file_artifacts, "invalid-receipt-inventory");
  assertDigestArray(value.inventory.payment_artifacts, "invalid-receipt-inventory");
  assertScope(value.scope);
}

export function statementBytes(statement) {
  return canonicalBytes(statement);
}

export function issuerSignaturePreimage(statement) {
  return Buffer.concat([ISSUER_SIGNATURE_PREFIX, statementBytes(statement)]);
}

export function treeHeadSignaturePreimage(head) {
  return Buffer.concat([TREE_HEAD_SIGNATURE_PREFIX, canonicalBytes(head)]);
}

export function validateReceipt(value) {
  assertExactKeys(value, ["statement", "signature", "inclusion"], "invalid-receipt-envelope");
  const statement = assertRecord(value.statement, "invalid-statement");
  assertExactKeys(statement, ["profile", "issuer", "receipt"], "invalid-statement");
  assertExactString(statement.profile, PROFILES.statement, "unsupported-statement-profile");
  assertIssuer(statement.issuer);
  assertReceiptBody(statement.receipt);

  let signature;
  try {
    signature = decodeSignature(value.signature);
  } catch {
    fail("invalid-receipt-signature");
  }

  const inclusion = assertRecord(value.inclusion, "invalid-inclusion");
  assertExactKeys(inclusion, ["tree_size", "leaf_index", "path"], "invalid-inclusion");
  let treeSize;
  let leafIndex;
  try {
    treeSize = parseDecimal(inclusion.tree_size, { allowZero: false, code: "invalid-tree-size" });
    leafIndex = parseDecimal(inclusion.leaf_index, { allowZero: true, code: "invalid-leaf-index" });
  } catch (error) {
    if (error?.code === "invalid-leaf-index") fail("invalid-leaf-index");
    fail("invalid-tree-size");
  }
  if (leafIndex >= treeSize) fail("leaf-index-out-of-range");
  const path = assertDigestArray(inclusion.path, "invalid-inclusion-path", LIMITS.maxProofItems);
  const expectedPathLength = auditPathLength(leafIndex, treeSize);
  if (path.length < expectedPathLength) fail("inclusion-proof-too-short");
  if (path.length > expectedPathLength) fail("inclusion-proof-too-long");

  return Object.freeze({
    value,
    statement,
    statementBytes: statementBytes(statement),
    signature,
    treeSize,
    leafIndex,
    path,
  });
}

export function validateTreeHead(value) {
  assertExactKeys(value, ["head", "signature"], "invalid-tree-head-envelope");
  const head = assertRecord(value.head, "invalid-tree-head");
  assertExactKeys(head, ["profile", "log_id", "algorithm", "tree_size", "root"], "invalid-tree-head");
  assertExactString(head.profile, PROFILES.treeHead, "unsupported-tree-head-profile");
  try {
    assertId(head.log_id);
  } catch {
    fail("invalid-tree-head");
  }
  assertAlgorithm(head.algorithm, "invalid-tree-head");
  let treeSize;
  try {
    treeSize = parseDecimal(head.tree_size, { allowZero: false, code: "invalid-tree-head-size" });
  } catch {
    fail("invalid-tree-head-size");
  }
  const root = assertDigest(head.root, "invalid-tree-head-root");
  let signature;
  try {
    signature = decodeSignature(value.signature);
  } catch {
    fail("invalid-tree-head-signature");
  }
  return Object.freeze({ value, head, treeSize, root, signature });
}

function validateTrustEntries(value, kind) {
  const isIssuer = kind === "issuer";
  const profile = isIssuer ? PROFILES.issuerTrust : PROFILES.logTrust;
  const collectionName = isIssuer ? "issuers" : "logs";
  const identity = isIssuer ? "key_id" : "log_id";
  const envelopeCode = isIssuer ? "invalid-issuer-trust" : "invalid-log-trust";
  assertExactKeys(value, ["profile", collectionName], envelopeCode);
  assertExactString(value.profile, profile, isIssuer ? "unsupported-issuer-trust-profile" : "unsupported-log-trust-profile");
  const records = value[collectionName];
  if (!Array.isArray(records) || records.length > LIMITS.maxTrustEntries) fail(envelopeCode);
  const seen = new Set();
  const byId = new Map();
  for (const record of records) {
    assertExactKeys(record, [identity, "algorithm", "spki"], envelopeCode);
    try {
      assertId(record[identity]);
    } catch {
      fail(envelopeCode);
    }
    if (seen.has(record[identity])) fail(isIssuer ? "duplicate-issuer-trust-id" : "duplicate-log-trust-id");
    seen.add(record[identity]);
    assertAlgorithm(record.algorithm, envelopeCode);
    let key;
    try {
      key = parseEd25519Spki(record.spki);
    } catch (error) {
      fail(["wrong-public-key-type", "noncanonical-ed25519-spki"].includes(error?.code) ? error.code : envelopeCode);
    }
    // Compare exported canonical DER in the verifier, rather than the textual
    // trust spelling, when enforcing issuer/log key-role separation.
    const publicKeyDer = Buffer.from(key.export({ type: "spki", format: "der" }));
    byId.set(record[identity], Object.freeze({ ...record, publicKey: key, publicKeyDer }));
  }
  return Object.freeze({ value, byId });
}

export function validateIssuerTrust(value) {
  return validateTrustEntries(value, "issuer");
}

export function validateLogTrust(value) {
  return validateTrustEntries(value, "log");
}
