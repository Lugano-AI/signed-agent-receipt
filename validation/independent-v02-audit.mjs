#!/usr/bin/env node
// Independent hostile-input audit for Signed Agent Receipt v0.2.
//
// This script deliberately does not import v0.2's canonicalizer, Merkle
// implementation, fixture builder, or test keys to construct its positive
// vectors.  It uses Node's built-in crypto and this audit's separate RFC-style
// tree oracle, then exercises the shipped verifier and CLI as subjects.
import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const AUDIT_DIR = dirname(SCRIPT_PATH);

function parseAuditArguments(argv) {
  let target = resolve(AUDIT_DIR, ".."); // default after copying into <v0.2>/validation/
  let output = join(AUDIT_DIR, "independent-v02-audit-results.json");
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if ((flag !== "--target" && flag !== "--output") || typeof value !== "string" || value.startsWith("--")) {
      throw new Error("usage: node independent-v02-audit.mjs [--target RECEIPT_V02_DIR] [--output RESULT.json]");
    }
    if (flag === "--target") target = resolve(value);
    else output = resolve(value);
    index += 1;
  }
  return { target, output };
}

const AUDIT_OPTIONS = parseAuditArguments(process.argv.slice(2));
const V02_DIR = AUDIT_OPTIONS.target;
const RESULT_PATH = AUDIT_OPTIONS.output;
const CLI = join(V02_DIR, "cli/check.mjs");
const FIXTURE_TOOL = join(V02_DIR, "tools/make-fixtures.mjs");
const TEST_RUNNER = join(V02_DIR, "test/run.mjs");
const canonicalModule = await import(pathToFileURL(join(V02_DIR, "src/canonical.mjs")).href);
const merkleModule = await import(pathToFileURL(join(V02_DIR, "src/merkle.mjs")).href);
const strictJsonModule = await import(pathToFileURL(join(V02_DIR, "src/strict-json.mjs")).href);
const verifyModule = await import(pathToFileURL(join(V02_DIR, "src/verify.mjs")).href);
const oracleModule = await import(new URL("./independent-rfc9162-oracle.mjs", import.meta.url));
const { canonical: subjectCanonical } = canonicalModule;
const { auditPathLength } = merkleModule;
const { parseStrictJson } = strictJsonModule;
const { checkArtifacts } = verifyModule;
const { auditPath, leafHash, merkleTreeHash, rootFromInclusionPath } = oracleModule;

const PASSED = "ARTIFACT CHECKS PASSED";
const FAILED = "ARTIFACT CHECKS FAILED";
const UNTRUSTED = "ARTIFACT CHECKS UNTRUSTED";
const ISSUER_PREFIX = Buffer.from("SAR-RI-v0.2\0issuer-signature\0", "ascii");
const HEAD_PREFIX = Buffer.from("SAR-RI-v0.2\0tree-head-signature\0", "ascii");
const SCOPE = Object.freeze({
  evidence: "artifact-digest-only",
  attestation: "not-implemented",
  observation: "not-implemented",
  retention: "not-measured",
  time: "not-authenticated",
  history: "not-checked",
});

const cases = [];
const failures = [];
let temporaryDirectory = null;

function sha256(...chunks) {
  const hash = createHash("sha256");
  for (const chunk of chunks) hash.update(chunk);
  return hash.digest();
}

function digest(label) {
  return `sha256:${sha256(Buffer.from(label, "utf8")).toString("hex")}`;
}

function compareUtf16(left, right) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

// The audit's independent, deliberately narrow canonical serializer.  Positive
// vectors use only the profile's admitted JSON value types.
function independentCanonical(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(independentCanonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort(compareUtf16).map((key) => `${JSON.stringify(key)}:${independentCanonical(value[key])}`).join(",")}}`;
  }
  throw new TypeError("audit canonicalizer received an unsupported value");
}

function independentCanonicalBytes(value) {
  return Buffer.from(independentCanonical(value), "utf8");
}

function issuerPreimage(statement) {
  return Buffer.concat([ISSUER_PREFIX, independentCanonicalBytes(statement)]);
}

function headPreimage(head) {
  return Buffer.concat([HEAD_PREFIX, independentCanonicalBytes(head)]);
}

function spkiBase64url(publicKey) {
  return Buffer.from(publicKey.export({ type: "spki", format: "der" })).toString("base64url");
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function makeStatement(size, ordinal, issuerKeyId, logId) {
  return {
    profile: "sar-ri-statement-v0.2",
    issuer: { algorithm: "Ed25519", key_id: issuerKeyId },
    receipt: {
      receipt_id: `receipt-${size}-${ordinal}`,
      log_id: logId,
      assertions: {
        runtime_artifact: digest(`runtime/${size}/${ordinal}`),
        policy_artifact: digest(`policy/${size}/${ordinal}`),
      },
      inventory: {
        tool_artifacts: [digest(`tool/${size}/${ordinal}`)],
        egress_artifacts: ordinal % 2 === 0 ? [digest(`egress/${size}/${ordinal}`)] : [],
        file_artifacts: ordinal % 3 === 0 ? [digest(`file/${size}/${ordinal}`)] : [],
        payment_artifacts: ordinal % 5 === 0 ? [digest(`payment/${size}/${ordinal}`)] : [],
      },
      scope: { ...SCOPE },
    },
  };
}

function signIssuer(statement, issuerPrivateKey) {
  return sign(null, issuerPreimage(statement), issuerPrivateKey).toString("base64url");
}

function signHead(head, logPrivateKey) {
  return sign(null, headPreimage(head), logPrivateKey).toString("base64url");
}

function buildIndependentFixtureSet(size, { issuer = generateKeyPairSync("ed25519"), log = generateKeyPairSync("ed25519"), issuerKeyId = "issuer-a", logId = "log-a" } = {}) {
  assert(Number.isSafeInteger(size) && size >= 1 && size <= 64, "audit fixture size must be 1..64");
  const statements = Array.from({ length: size }, (_, ordinal) => makeStatement(size, ordinal, issuerKeyId, logId));
  const statementBytes = statements.map(independentCanonicalBytes);
  const rootBytes = merkleTreeHash(statementBytes);
  const head = {
    profile: "sar-ri-tree-head-v0.2",
    log_id: logId,
    algorithm: "Ed25519",
    tree_size: String(size),
    root: `sha256:${rootBytes.toString("hex")}`,
  };
  const treeHead = { head, signature: signHead(head, log.privateKey) };
  const receipts = statements.map((statement, index) => ({
    statement,
    signature: signIssuer(statement, issuer.privateKey),
    inclusion: {
      tree_size: String(size),
      leaf_index: String(index),
      path: auditPath(statementBytes, index).map((node) => `sha256:${node.toString("hex")}`),
    },
  }));
  const issuerTrust = {
    profile: "sar-ri-issuer-trust-v0.2",
    issuers: [{ key_id: issuerKeyId, algorithm: "Ed25519", spki: spkiBase64url(issuer.publicKey) }],
  };
  const logTrust = {
    profile: "sar-ri-log-trust-v0.2",
    logs: [{ log_id: logId, algorithm: "Ed25519", spki: spkiBase64url(log.publicKey) }],
  };
  return { issuer, log, statements, statementBytes, rootBytes, receipts, treeHead, issuerTrust, logTrust };
}

function directReport(set, receipt = set.receipts[0], overrides = {}) {
  return checkArtifacts({
    receiptBytes: overrides.receiptBytes ?? jsonBytes(receipt),
    issuerTrustBytes: Object.hasOwn(overrides, "issuerTrustBytes") ? overrides.issuerTrustBytes : jsonBytes(overrides.issuerTrust ?? set.issuerTrust),
    logTrustBytes: Object.hasOwn(overrides, "logTrustBytes") ? overrides.logTrustBytes : jsonBytes(overrides.logTrust ?? set.logTrust),
    treeHeadBytes: Object.hasOwn(overrides, "treeHeadBytes") ? overrides.treeHeadBytes : jsonBytes(overrides.treeHead ?? set.treeHead),
  });
}

function checkStatus(report, name, status) {
  const entry = report.checks.find((candidate) => candidate.name === name);
  assert(entry, `missing ${name} check`);
  assert.equal(entry.status, status, `${name} should be ${status}; got ${entry.status} (${entry.detail})`);
}

function assertResult(report, expectedResult, expectedExit) {
  assert.equal(report.result, expectedResult);
  assert.equal(report.exitCode, expectedExit);
}

function safeError(error) {
  return error instanceof Error ? error.message : String(error);
}

function runCase(name, work) {
  try {
    const detail = work();
    cases.push({ name, status: "PASS", ...(detail && typeof detail === "object" ? detail : {}) });
  } catch (error) {
    const detail = safeError(error);
    cases.push({ name, status: "FAIL", detail });
    failures.push({ name, detail });
  }
}

function expectSarError(bytes, expectedCode) {
  let caught = null;
  try {
    parseStrictJson(bytes);
  } catch (error) {
    caught = error;
  }
  assert(caught, `expected ${expectedCode}, but input parsed`);
  assert.equal(caught.code, expectedCode);
}

function flipBase64url(value) {
  const last = value.at(-1);
  return `${value.slice(0, -1)}${last === "A" ? "B" : "A"}`;
}

function flipDigest(value) {
  const last = value.at(-1);
  return `${value.slice(0, -1)}${last === "0" ? "1" : "0"}`;
}

function independentPathLength(index, size) {
  if (index < 0 || index >= size || size < 1) throw new RangeError("bad independent path dimensions");
  let count = 0;
  let localIndex = index;
  let localSize = size;
  while (localSize > 1) {
    let split = 1;
    while (split * 2 < localSize) split *= 2;
    if (localIndex < split) localSize = split;
    else {
      localIndex -= split;
      localSize -= split;
    }
    count += 1;
  }
  return count;
}

function fileManifest(directory, exclusions = []) {
  const excluded = new Set(exclusions.map((path) => resolve(path)));
  const entries = [];
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absolute = join(current, entry.name);
      if (excluded.has(resolve(absolute))) continue;
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile()) {
        entries.push({
          file: relative(directory, absolute),
          sha256: sha256(readFileSync(absolute)).toString("hex"),
          bytes: readFileSync(absolute).length,
        });
      }
    }
  };
  walk(directory);
  return entries.sort((left, right) => left.file.localeCompare(right.file));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function cli(args, options = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: V02_DIR,
    encoding: "utf8",
    timeout: options.timeout ?? 5000,
  });
  return {
    exit: result.status,
    signal: result.signal,
    error: result.error ? `${result.error.name}:${result.error.message}` : null,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function assertSafeCli(result, expectedExit) {
  assert.equal(result.error, null, `CLI process error: ${result.error}`);
  assert.equal(result.signal, null, `CLI signal: ${result.signal}`);
  assert.equal(result.exit, expectedExit, `CLI exit ${result.exit}; stdout=${result.stdout}; stderr=${result.stderr}`);
  const transcript = `${result.stdout}\n${result.stderr}`;
  assert(!/Error:|\n\s*at\s|independent-run-/u.test(transcript), `unsafe CLI detail leaked: ${transcript}`);
}

function longFormOuterSpki(publicKey) {
  const canonical = Buffer.from(publicKey.export({ type: "spki", format: "der" }));
  assert.equal(canonical[0], 0x30);
  assert(canonical[1] < 0x80, "fixture expects short-form outer DER length");
  return Buffer.concat([Buffer.from([0x30, 0x81, canonical[1]]), canonical.subarray(2)]);
}

function publicKeyPem(key) {
  return key.export({ type: "spki", format: "pem" });
}

function privateKeyPem(key) {
  return key.export({ type: "pkcs8", format: "pem" });
}

function runFixtureTool(args) {
  const result = spawnSync(process.execPath, [FIXTURE_TOOL, ...args], { cwd: V02_DIR, encoding: "utf8", timeout: 5000 });
  return { exit: result.status, signal: result.signal, error: result.error ? `${result.error.name}:${result.error.message}` : null, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function verifyGeneratedFixtureDirectory(directory) {
  const manifest = JSON.parse(readFileSync(join(directory, "manifest.json"), "utf8"));
  const treeHead = JSON.parse(readFileSync(join(directory, "tree-head.json"), "utf8"));
  const root = Buffer.from(treeHead.head.root.slice("sha256:".length), "hex");
  const files = manifest.receipt_files;
  const statementBytes = files.map((file) => independentCanonicalBytes(JSON.parse(readFileSync(join(directory, file), "utf8")).statement));
  const expectedRoot = merkleTreeHash(statementBytes);
  assert.deepEqual(root, expectedRoot, "fixture generator head root differs from independent tree root");
  for (let index = 0; index < files.length; index += 1) {
    const receipt = JSON.parse(readFileSync(join(directory, files[index]), "utf8"));
    const path = receipt.inclusion.path.map((encoded) => Buffer.from(encoded.slice("sha256:".length), "hex"));
    const reconstructed = rootFromInclusionPath(leafHash(statementBytes[index]), index, files.length, path);
    assert.deepEqual(reconstructed, expectedRoot, `fixture generator path ${index} does not reach independent root`);
  }
  return { tree_size: files.length, root: treeHead.head.root };
}

function run() {
  // When this script is copied into <v0.2>/validation/, its default result
  // lives below the target.  Exclude only that known generated report; all
  // profile inputs, including the copied audit scripts, remain frozen.
  const beforeManifest = fileManifest(V02_DIR, [RESULT_PATH]);
  // Keep hostile fixtures outside the target tree.  When this harness is
  // copied into <v0.2>/validation/, a target-local temp directory would make
  // its own before/after freeze manifest report a false mutation.
  temporaryDirectory = mkdtempSync(join(tmpdir(), "sar-ri-independent-run-"));

  runCase("node-ed25519-rfc8032-vector-1", () => {
    const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
    const publicBytes = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
    const expectedSignature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    const privateDer = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
    const publicDer = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicBytes]);
    const signature = sign(null, Buffer.alloc(0), { key: privateDer, format: "der", type: "pkcs8" });
    assert.equal(signature.toString("hex"), expectedSignature);
    assert(verify(null, Buffer.alloc(0), { key: publicDer, format: "der", type: "spki" }, signature));
    return { vector: "RFC 8032 section 7.1 test vector 1" };
  });

  runCase("unicode-sort-and-independent-canonical-bytes", () => {
    const input = {
      "\u20ac": "Euro Sign",
      "\r": "Carriage Return",
      "\ufb33": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "\ud83d\ude00": "Emoji: Grinning Face",
      "\u0080": "Control",
      "\u00f6": "Latin Small Letter O With Diaeresis",
    };
    const expectedOrder = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\ud83d\ude00", "\ufb33"];
    assert.deepEqual(Object.keys(input).sort(compareUtf16), expectedOrder);
    assert.equal(subjectCanonical(input), independentCanonical(input));
    return { expected_utf16_order: expectedOrder };
  });

  runCase("strict-parser-hostile-raw-inputs", () => {
    const failuresByCode = [
      [Buffer.from('{"a":"one","\\u0061":"two"}', "utf8"), "duplicate-json-key"],
      [Buffer.from('{"outer":{"b":"one","\\u0062":"two"}}', "utf8"), "duplicate-json-key"],
      [Buffer.from([0x7b, 0xff, 0x7d]), "invalid-utf8"],
      [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("{}")]), "json-bom-not-allowed"],
      [Buffer.from('{"x":"\\ud800"}', "utf8"), "lone-surrogate"],
      [Buffer.from('{"x":"\\udc00"}', "utf8"), "lone-surrogate"],
      [Buffer.from('{"n":1}', "utf8"), "json-number-not-allowed"],
      [Buffer.from('{"n":1.00000000000000001}', "utf8"), "json-number-not-allowed"],
      [Buffer.from('{"n":1e-1000}', "utf8"), "json-number-not-allowed"],
      [Buffer.from('{"n":-0}', "utf8"), "json-number-not-allowed"],
      [Buffer.from('{"n":9007199254740993}', "utf8"), "json-number-not-allowed"],
      [Buffer.from('{"n":1e+30}', "utf8"), "json-number-not-allowed"],
      [Buffer.from('{"x":"\u0000"}', "utf8"), "unescaped-json-control"],
      [Buffer.from("{}{}", "utf8"), "trailing-json-data"],
      [Buffer.from(`${"[".repeat(33)}null${"]".repeat(33)}`, "utf8"), "json-depth-limit"],
      [Buffer.alloc(256 * 1024 + 1, 0x20), "json-input-byte-limit"],
      [Buffer.from(`[${Array.from({ length: 65 }, () => "null").join(",")}]`, "utf8"), "json-array-item-limit"],
      [Buffer.from(`{"x":"${"a".repeat(8193)}"}`, "utf8"), "json-string-limit"],
    ];
    for (const [bytes, code] of failuresByCode) expectSarError(bytes, code);
    const prototypeProbe = parseStrictJson(Buffer.from('{"__proto__":"literal","constructor":"literal"}', "utf8"));
    assert.equal(Object.getPrototypeOf(prototypeProbe), null);
    assert.equal(prototypeProbe.__proto__, "literal");
    assert.equal({}.polluted, undefined);
    return { rejected_cases: failuresByCode.length, decoded_duplicate_keys: true, prototype_pollution: "not observed" };
  });

  runCase("independent-path-length-boundaries", () => {
    let checked = 0;
    for (let size = 1; size <= 128; size += 1) {
      for (let index = 0; index < size; index += 1) {
        assert.equal(auditPathLength(index, size), independentPathLength(index, size));
        checked += 1;
      }
    }
    const max = 2_147_483_647;
    for (const index of [0, 1, 2, 3, max - 4, max - 3, max - 2, max - 1]) {
      assert.equal(auditPathLength(index, max), independentPathLength(index, max));
      assert(auditPathLength(index, max) <= 31);
      checked += 1;
    }
    return { dimensions_checked: checked, maximum_tree_size: max };
  });

  runCase("valid-direct-matrix-every-index-sizes-1-through-64", () => {
    const issuer = generateKeyPairSync("ed25519");
    const log = generateKeyPairSync("ed25519");
    let vectors = 0;
    for (let size = 1; size <= 64; size += 1) {
      const set = buildIndependentFixtureSet(size, { issuer, log });
      for (let index = 0; index < size; index += 1) {
        const path = set.receipts[index].inclusion.path.map((entry) => Buffer.from(entry.slice("sha256:".length), "hex"));
        assert.deepEqual(rootFromInclusionPath(leafHash(set.statementBytes[index]), index, size, path), set.rootBytes);
        const report = directReport(set, set.receipts[index]);
        assertResult(report, PASSED, 0);
        checkStatus(report, "issuer_signature", "PASS");
        checkStatus(report, "tree_head_signature", "PASS");
        checkStatus(report, "merkle_inclusion", "PASS");
        vectors += 1;
      }
    }
    return { valid_vectors: vectors, sizes: "1..64", independent_tree_oracle: true };
  });

  runCase("canonical-whitespace-and-member-order-are-signed-by-canonical-form", () => {
    const set = buildIndependentFixtureSet(7);
    const receipt = clone(set.receipts[3]);
    const reorderedStatement = {
      receipt: receipt.statement.receipt,
      issuer: receipt.statement.issuer,
      profile: receipt.statement.profile,
    };
    const raw = Buffer.from(` { \n  "inclusion" : ${JSON.stringify(receipt.inclusion)}, \n "signature" : ${JSON.stringify(receipt.signature)}, \n "statement" : ${JSON.stringify(reorderedStatement)} \n } \n`, "utf8");
    const report = directReport(set, receipt, { receiptBytes: raw });
    assertResult(report, PASSED, 0);
    return { reordered_and_whitespace_variant: "accepted with original valid signature" };
  });

  runCase("hostile-proof-and-cryptographic-mutations", () => {
    const set = buildIndependentFixtureSet(17);
    // Index 11 of a 17-leaf tree has a five-node, uneven-tree path, so path
    // reordering is a real mutation rather than a one-element no-op.
    const index = 11;
    const base = set.receipts[index];
    const mutations = [];
    const assertFailed = (name, receipt = base, overrides = {}) => {
      const report = directReport(set, receipt, overrides);
      assertResult(report, FAILED, 1);
      mutations.push(name);
    };

    const badIssuerSignature = clone(base);
    badIssuerSignature.signature = flipBase64url(badIssuerSignature.signature);
    assertFailed("issuer-signature-bit-flip", badIssuerSignature);

    const badHeadSignature = clone(set.treeHead);
    badHeadSignature.signature = flipBase64url(badHeadSignature.signature);
    assertFailed("tree-head-signature-bit-flip", base, { treeHead: badHeadSignature });

    const badPathHash = clone(base);
    badPathHash.inclusion.path[0] = flipDigest(badPathHash.inclusion.path[0]);
    assertFailed("proof-sibling-bit-flip", badPathHash);

    const reorderedPath = clone(base);
    reorderedPath.inclusion.path.reverse();
    assertFailed("proof-reordered", reorderedPath);

    const shortPath = clone(base);
    shortPath.inclusion.path.pop();
    assertFailed("proof-short-before-tree-head", shortPath, { issuerTrustBytes: null, logTrustBytes: null, treeHeadBytes: null });

    const longPath = clone(base);
    longPath.inclusion.path.push(longPath.inclusion.path[0]);
    assertFailed("proof-long-before-tree-head", longPath, { issuerTrustBytes: null, logTrustBytes: null, treeHeadBytes: null });

    const wrongIndex = clone(base);
    wrongIndex.inclusion.leaf_index = "0";
    assertFailed("proof-wrong-index", wrongIndex);

    const wrongTreeSize = clone(base);
    wrongTreeSize.inclusion.tree_size = "16";
    assertFailed("proof-wrong-tree-size", wrongTreeSize);

    const badRootHead = clone(set.treeHead);
    badRootHead.head.root = flipDigest(badRootHead.head.root);
    badRootHead.signature = signHead(badRootHead.head, set.log.privateKey);
    assertFailed("signed-head-wrong-root", base, { treeHead: badRootHead });

    const differentLogHead = clone(set.treeHead);
    differentLogHead.head.log_id = "other-log";
    differentLogHead.signature = signHead(differentLogHead.head, set.log.privateKey);
    const differentLogTrust = clone(set.logTrust);
    differentLogTrust.logs.push({ log_id: "other-log", algorithm: "Ed25519", spki: spkiBase64url(set.log.publicKey) });
    const logMismatch = directReport(set, base, { treeHead: differentLogHead, logTrust: differentLogTrust });
    assertResult(logMismatch, FAILED, 1);
    checkStatus(logMismatch, "log_binding", "FAIL");
    mutations.push("signed-head-log-id-mismatch");

    const differentSizeHead = clone(set.treeHead);
    differentSizeHead.head.tree_size = "16";
    differentSizeHead.signature = signHead(differentSizeHead.head, set.log.privateKey);
    const sizeMismatch = directReport(set, base, { treeHead: differentSizeHead });
    assertResult(sizeMismatch, FAILED, 1);
    checkStatus(sizeMismatch, "tree_size_binding", "FAIL");
    mutations.push("signed-head-tree-size-mismatch");

    const issuerDomainConfusion = clone(base);
    issuerDomainConfusion.signature = sign(null, headPreimage(set.treeHead.head), set.issuer.privateKey).toString("base64url");
    assertFailed("issuer-signature-head-domain", issuerDomainConfusion);

    const headDomainConfusion = clone(set.treeHead);
    headDomainConfusion.signature = sign(null, issuerPreimage(base.statement), set.log.privateKey).toString("base64url");
    assertFailed("tree-head-signature-issuer-domain", base, { treeHead: headDomainConfusion });

    const upperDigest = clone(base);
    upperDigest.statement.receipt.assertions.runtime_artifact = upperDigest.statement.receipt.assertions.runtime_artifact.toUpperCase();
    assertFailed("noncanonical-digest-case", upperDigest);

    const paddedSignature = clone(base);
    paddedSignature.signature += "=";
    assertFailed("padded-signature", paddedSignature);

    const injectedTrust = clone(base);
    injectedTrust.statement.issuer.spki = spkiBase64url(set.issuer.publicKey);
    assertFailed("receipt-embedded-trust", injectedTrust);

    const wrongIssuerAlgorithm = clone(base);
    wrongIssuerAlgorithm.statement.issuer.algorithm = "Ed448";
    assertFailed("issuer-algorithm-confusion", wrongIssuerAlgorithm);

    return { rejected_mutations: mutations.length, mutations };
  });

  runCase("trust-substitution-key-type-and-role-separation", () => {
    const set = buildIndependentFixtureSet(9);
    const unrelatedIssuer = generateKeyPairSync("ed25519");
    const wrongIssuerTrust = clone(set.issuerTrust);
    wrongIssuerTrust.issuers[0].spki = spkiBase64url(unrelatedIssuer.publicKey);
    assertResult(directReport(set, set.receipts[4], { issuerTrust: wrongIssuerTrust }), FAILED, 1);

    const swappedIssuerTrust = clone(set.issuerTrust);
    const swappedLogTrust = clone(set.logTrust);
    swappedIssuerTrust.issuers[0].spki = spkiBase64url(set.log.publicKey);
    swappedLogTrust.logs[0].spki = spkiBase64url(set.issuer.publicKey);
    assertResult(directReport(set, set.receipts[4], { issuerTrust: swappedIssuerTrust, logTrust: swappedLogTrust }), FAILED, 1);

    const missingSelector = clone(set.receipts[4]);
    missingSelector.statement.issuer.key_id = "unknown-issuer";
    const missingReport = directReport(set, missingSelector);
    assertResult(missingReport, FAILED, 1);
    checkStatus(missingReport, "issuer_signature", "FAIL");

    const badAlgorithmTrust = clone(set.issuerTrust);
    badAlgorithmTrust.issuers[0].algorithm = "ed25519";
    assertResult(directReport(set, set.receipts[4], { issuerTrust: badAlgorithmTrust }), FAILED, 1);

    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaTrust = clone(set.issuerTrust);
    rsaTrust.issuers[0].spki = spkiBase64url(rsa.publicKey);
    assertResult(directReport(set, set.receipts[4], { issuerTrust: rsaTrust }), FAILED, 1);

    const same = generateKeyPairSync("ed25519");
    const sameKeySet = buildIndependentFixtureSet(3, { issuer: same, log: same });
    const sameKeyReport = directReport(sameKeySet, sameKeySet.receipts[1]);
    assertResult(sameKeyReport, FAILED, 1);
    checkStatus(sameKeyReport, "issuer_log_key_separation", "FAIL");

    const alternateSameKeySet = buildIndependentFixtureSet(3, { issuer: same, log: same });
    alternateSameKeySet.logTrust.logs[0].spki = longFormOuterSpki(same.publicKey).toString("base64url");
    const alternateReport = directReport(alternateSameKeySet, alternateSameKeySet.receipts[1]);
    assertResult(alternateReport, FAILED, 1);
    const secureFailure = alternateReport.checks.find((entry) =>
      (entry.name === "issuer_log_key_separation" || entry.name === "log_trust") && entry.status === "FAIL");
    assert(secureFailure, "same public key under alternate ASN.1 encoding reached a pass path");

    return { trust_substitution: "rejected", same_key_standard: "rejected", same_key_alternate_spki: secureFailure.name };
  });

  runCase("strict-receipt-schema-and-untrusted-boundary", () => {
    const set = buildIndependentFixtureSet(5);
    const unknownEnvelope = clone(set.receipts[0]);
    unknownEnvelope.extension = "no";
    assertResult(directReport(set, unknownEnvelope), FAILED, 1);

    const missingScope = clone(set.receipts[0]);
    delete missingScope.statement.receipt.scope;
    assertResult(directReport(set, missingScope), FAILED, 1);

    const nestedDuplicateRaw = Buffer.from('{"statement":{},"\\u0073tatement":{},"signature":"x","inclusion":{}}', "utf8");
    assertResult(directReport(set, set.receipts[0], { receiptBytes: nestedDuplicateRaw, issuerTrustBytes: null, logTrustBytes: null, treeHeadBytes: null }), FAILED, 1);

    const withoutExternalInputs = directReport(set, set.receipts[0], { issuerTrustBytes: null, logTrustBytes: null, treeHeadBytes: null });
    assertResult(withoutExternalInputs, UNTRUSTED, 3);
    checkStatus(withoutExternalInputs, "issuer_trust", "UNTRUSTED");
    return { unknown_fields: "rejected", external_trust_absent: "untrusted-not-passed" };
  });

  runCase("fixture-tool-and-cli-real-artifact-path", () => {
    const keys = { issuer: generateKeyPairSync("ed25519"), log: generateKeyPairSync("ed25519") };
    const paths = {
      issuerPrivate: join(temporaryDirectory, "issuer-private.pem"),
      issuerPublic: join(temporaryDirectory, "issuer-public.pem"),
      logPrivate: join(temporaryDirectory, "log-private.pem"),
      logPublic: join(temporaryDirectory, "log-public.pem"),
      generated: join(temporaryDirectory, "generated-fixtures"),
    };
    writeFileSync(paths.issuerPrivate, privateKeyPem(keys.issuer.privateKey));
    writeFileSync(paths.issuerPublic, publicKeyPem(keys.issuer.publicKey));
    writeFileSync(paths.logPrivate, privateKeyPem(keys.log.privateKey));
    writeFileSync(paths.logPublic, publicKeyPem(keys.log.publicKey));
    const args = [
      "--out", paths.generated,
      "--size", "17",
      "--issuer-private-key", paths.issuerPrivate,
      "--issuer-public-key", paths.issuerPublic,
      "--log-private-key", paths.logPrivate,
      "--log-public-key", paths.logPublic,
    ];
    const generated = runFixtureTool(args);
    assert.equal(generated.error, null);
    assert.equal(generated.signal, null);
    assert.equal(generated.exit, 0, generated.stderr);
    const fixtureEvidence = verifyGeneratedFixtureDirectory(paths.generated);
    const receiptFiles = JSON.parse(readFileSync(join(paths.generated, "manifest.json"), "utf8")).receipt_files;
    for (const receiptFile of receiptFiles) {
      const result = cli([
        "--receipt", join(paths.generated, receiptFile),
        "--issuer-trust", join(paths.generated, "issuer-trust.json"),
        "--log-trust", join(paths.generated, "log-trust.json"),
        "--tree-head", join(paths.generated, "tree-head.json"),
      ]);
      assertSafeCli(result, 0);
      assert(result.stdout.includes(PASSED));
      assert(result.stdout.includes("NOT ESTABLISHED:"));
      assert(!result.stdout.includes("VERIFIED"));
    }
    const noOverwrite = runFixtureTool(args);
    assert.equal(noOverwrite.exit, 1);
    return { generated_tree_size: fixtureEvidence.tree_size, generated_root: fixtureEvidence.root, cli_receipts_checked: receiptFiles.length, overwrite: "refused" };
  });

  runCase("cli-errors-bounds-and-nonregular-input", () => {
    const set = buildIndependentFixtureSet(3);
    const files = {
      receipt: join(temporaryDirectory, "cli-receipt.json"),
      issuer: join(temporaryDirectory, "cli-issuer.json"),
      log: join(temporaryDirectory, "cli-log.json"),
      head: join(temporaryDirectory, "cli-head.json"),
      malformed: join(temporaryDirectory, "cli-malformed.json"),
      tooLarge: join(temporaryDirectory, "cli-too-large.json"),
      fifo: join(temporaryDirectory, "cli-input.fifo"),
    };
    writeJson(files.receipt, set.receipts[2]);
    writeJson(files.issuer, set.issuerTrust);
    writeJson(files.log, set.logTrust);
    writeJson(files.head, set.treeHead);
    writeFileSync(files.malformed, Buffer.from('{"n":1}', "utf8"));
    writeFileSync(files.tooLarge, Buffer.alloc(256 * 1024 + 1, 0x20));

    const valid = cli(["--receipt", files.receipt, "--issuer-trust", files.issuer, "--log-trust", files.log, "--tree-head", files.head]);
    assertSafeCli(valid, 0);
    const untrusted = cli(["--receipt", files.receipt]);
    assertSafeCli(untrusted, 3);
    const missingReceipt = cli([]);
    assertSafeCli(missingReceipt, 2);
    const repeated = cli(["--receipt", files.receipt, "--receipt", files.receipt]);
    assertSafeCli(repeated, 2);
    const unknown = cli(["--sth", files.head, "--receipt", files.receipt]);
    assertSafeCli(unknown, 2);
    const unavailable = cli(["--receipt", join(temporaryDirectory, "does-not-exist.json")]);
    assertSafeCli(unavailable, 1);
    const malformed = cli(["--receipt", files.malformed]);
    assertSafeCli(malformed, 1);
    const oversized = cli(["--receipt", files.tooLarge]);
    assertSafeCli(oversized, 1);
    assert(oversized.stdout.includes("input-file-too-large"));

    const fifoCreate = spawnSync("mkfifo", [files.fifo], { encoding: "utf8", timeout: 2000 });
    assert.equal(fifoCreate.status, 0, fifoCreate.stderr);
    const fifo = cli(["--receipt", files.fifo], { timeout: 1500 });
    assertSafeCli(fifo, 1);
    assert(fifo.stdout.includes("input-file-not-regular"));
    return { valid: 0, untrusted: 3, usage_errors: 2, malformed_or_file_errors: 1, fifo: "nonblocking rejection" };
  });

  runCase("shipped-test-suite-and-syntax", () => {
    const runner = spawnSync(process.execPath, [TEST_RUNNER], { cwd: V02_DIR, encoding: "utf8", timeout: 30000 });
    assert.equal(runner.error, undefined);
    assert.equal(runner.signal, null, runner.stderr);
    assert.equal(runner.status, 0, `${runner.stdout}\n${runner.stderr}`);
    const mjsFiles = fileManifest(V02_DIR).filter((entry) => entry.file.endsWith(".mjs"));
    for (const entry of mjsFiles) {
      const syntax = spawnSync(process.execPath, ["--check", join(V02_DIR, entry.file)], { encoding: "utf8", timeout: 5000 });
      assert.equal(syntax.status, 0, `${entry.file}: ${syntax.stderr}`);
    }
    return { shipped_test_runner: "passed", syntax_checked_modules: mjsFiles.length };
  });

  const afterManifest = fileManifest(V02_DIR, [RESULT_PATH]);
  try {
    assert.deepEqual(afterManifest, beforeManifest, "v0.2 artifact changed during independent audit execution");
  } catch (error) {
    failures.push({ name: "artifact-freeze-during-audit", detail: safeError(error) });
    cases.push({ name: "artifact-freeze-during-audit", status: "FAIL", detail: safeError(error) });
  }

  return { beforeManifest, afterManifest };
}

let manifests = { beforeManifest: [], afterManifest: [] };
try {
  manifests = run();
} catch (error) {
  failures.push({ name: "audit-harness", detail: safeError(error) });
  cases.push({ name: "audit-harness", status: "FAIL", detail: safeError(error) });
}

if (temporaryDirectory) {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}

const result = {
  audit: "independent-sar-v0.2-hostile-input-audit",
  date: "2026-11-02",
  node: process.version,
  status: failures.length === 0 ? "PASS" : "FAIL",
  limitations: [
    "This is a bounded local code-and-fixture audit, not an independent human audit or production certification.",
    "It does not observe an agent/runtime, validate hardware attestation, measure zero retention/deletion, verify a public log, prove append-only history, authenticate time, or verify a deployed service.",
    "The input-path check verifies bounded local reads and FIFO rejection; it does not turn a mutable pathname into an authenticated immutable artifact source.",
  ],
  v02_manifest_before: manifests.beforeManifest,
  v02_manifest_after: manifests.afterManifest,
  cases,
  failures,
};
writeJson(RESULT_PATH, result);
console.log(JSON.stringify({ status: result.status, passed: cases.filter((entry) => entry.status === "PASS").length, failed: failures.length, results: relative(process.cwd(), RESULT_PATH) }, null, 2));
process.exitCode = failures.length === 0 ? 0 : 1;
