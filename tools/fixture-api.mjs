// Public test-fixture API. It uses a separate recursive tree constructor from
// src/merkle.mjs so a verifier regression cannot make its own fixtures pass.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  ALGORITHM,
  PROFILES,
  REQUIRED_SCOPE,
  issuerSignaturePreimage,
  statementBytes,
  treeHeadSignaturePreimage,
} from "../src/profile.mjs";
import { encodeDigest } from "../src/encoding.mjs";

function sha256(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function externalLeafHash(statementBytes) {
  return sha256(Buffer.from([0]), statementBytes);
}

function externalNodeHash(left, right) {
  return sha256(Buffer.from([1]), left, right);
}

function splitPoint(length) {
  let split = 1;
  while (split * 2 < length) split *= 2;
  return split;
}

function externalTreeHash(leaves) {
  if (leaves.length === 0) throw new Error("fixture tree needs at least one leaf");
  if (leaves.length === 1) return leaves[0];
  const split = splitPoint(leaves.length);
  return externalNodeHash(externalTreeHash(leaves.slice(0, split)), externalTreeHash(leaves.slice(split)));
}

function externalAuditPath(leaves, index) {
  if (leaves.length === 1) return [];
  const split = splitPoint(leaves.length);
  if (index < split) {
    return [...externalAuditPath(leaves.slice(0, split), index), externalTreeHash(leaves.slice(split))];
  }
  return [...externalAuditPath(leaves.slice(split), index - split), externalTreeHash(leaves.slice(0, split))];
}

function artifactDigest(label) {
  return encodeDigest(sha256(Buffer.from(label, "utf8")));
}

function assertionScope() {
  return { ...REQUIRED_SCOPE };
}

export function createFixtureStatement({ receiptId, logId, ordinal }) {
  return {
    profile: PROFILES.statement,
    issuer: { algorithm: ALGORITHM, key_id: "fixture-issuer-v02" },
    receipt: {
      receipt_id: receiptId,
      log_id: logId,
      assertions: {
        runtime_artifact: artifactDigest(`runtime:${ordinal}`),
        policy_artifact: artifactDigest(`policy:${ordinal}`),
      },
      inventory: {
        tool_artifacts: [artifactDigest(`tool:${ordinal}`)],
        egress_artifacts: ordinal % 2 === 0 ? [artifactDigest(`egress:${ordinal}`)] : [],
        file_artifacts: ordinal % 3 === 0 ? [artifactDigest(`file:${ordinal}`)] : [],
        payment_artifacts: ordinal % 5 === 0 ? [artifactDigest(`payment:${ordinal}`)] : [],
      },
      scope: assertionScope(),
    },
  };
}

function coercePrivateKey(input) {
  const key = input?.type === "private" ? input : createPrivateKey(input);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("fixture private key must be Ed25519");
  return key;
}

function coercePublicKey(input) {
  const key = input?.type === "public" ? input : createPublicKey(input);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("fixture public key must be Ed25519");
  return key;
}

function spkiBase64url(key) {
  return Buffer.from(key.export({ type: "spki", format: "der" })).toString("base64url");
}

function assertPair(privateKey, publicKey) {
  const challenge = Buffer.from("SAR-RI fixture key-pair check", "ascii");
  if (!verify(null, challenge, publicKey, sign(null, challenge, privateKey))) throw new Error("fixture key pair mismatch");
}

/**
 * Build a valid, externally inspectable set of receipts for every leaf of one
 * bounded tree. Callers may pass independently generated Ed25519 test keys.
 */
export function buildFixtureSet({
  size,
  issuerPrivateKey,
  issuerPublicKey,
  logPrivateKey,
  logPublicKey,
  issuerKeyId = "fixture-issuer-v02",
  logId = "fixture-log-v02",
}) {
  if (!Number.isSafeInteger(size) || size < 1 || size > 64) throw new Error("fixture size must be 1 through 64");
  const issuerPrivate = coercePrivateKey(issuerPrivateKey);
  const issuerPublic = coercePublicKey(issuerPublicKey);
  const logPrivate = coercePrivateKey(logPrivateKey);
  const logPublic = coercePublicKey(logPublicKey);
  assertPair(issuerPrivate, issuerPublic);
  assertPair(logPrivate, logPublic);

  const statements = Array.from({ length: size }, (_, ordinal) => createFixtureStatement({
    receiptId: `fixture-${size}-${ordinal}`,
    logId,
    ordinal,
  }));
  // The supplied IDs are deliberately validated by the consumer profile too;
  // replacing fixture IDs should not create a special trust path.
  for (const statement of statements) statement.issuer.key_id = issuerKeyId;
  const canonicalStatementBytes = statements.map(statementBytes);
  const leaves = canonicalStatementBytes.map(externalLeafHash);
  const root = externalTreeHash(leaves);

  const head = {
    profile: PROFILES.treeHead,
    log_id: logId,
    algorithm: ALGORITHM,
    tree_size: String(size),
    root: encodeDigest(root),
  };
  const treeHead = {
    head,
    signature: sign(null, treeHeadSignaturePreimage(head), logPrivate).toString("base64url"),
  };
  const receipts = statements.map((statement, index) => ({
    statement,
    signature: sign(null, issuerSignaturePreimage(statement), issuerPrivate).toString("base64url"),
    inclusion: {
      tree_size: String(size),
      leaf_index: String(index),
      path: externalAuditPath(leaves, index).map(encodeDigest),
    },
  }));
  const issuerTrust = {
    profile: PROFILES.issuerTrust,
    issuers: [{ key_id: issuerKeyId, algorithm: ALGORITHM, spki: spkiBase64url(issuerPublic) }],
  };
  const logTrust = {
    profile: PROFILES.logTrust,
    logs: [{ log_id: logId, algorithm: ALGORITHM, spki: spkiBase64url(logPublic) }],
  };
  return Object.freeze({ receipts, treeHead, issuerTrust, logTrust, root: encodeDigest(root) });
}

/** Write a new fixture directory. It refuses an existing output path. */
export function writeFixtureSet(outputDirectory, fixtureSet) {
  mkdirSync(outputDirectory, { recursive: false });
  const writeJson = (name, value) => writeFileSync(join(outputDirectory, name), `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
  writeJson("issuer-trust.json", fixtureSet.issuerTrust);
  writeJson("log-trust.json", fixtureSet.logTrust);
  writeJson("tree-head.json", fixtureSet.treeHead);
  fixtureSet.receipts.forEach((receipt, index) => writeJson(`receipt-${index}.json`, receipt));
  writeJson("manifest.json", {
    profile: "sar-ri-fixture-set-v0.2",
    tree_size: String(fixtureSet.receipts.length),
    root: fixtureSet.root,
    receipt_files: fixtureSet.receipts.map((_, index) => `receipt-${index}.json`),
  });
}

export const fixtureTreeOracle = Object.freeze({ externalLeafHash, externalNodeHash, externalTreeHash, externalAuditPath });
