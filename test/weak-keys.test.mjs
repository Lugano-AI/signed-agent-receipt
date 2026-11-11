import { checkArtifacts, RESULT } from "../src/verify.mjs";
import { parseEd25519Spki } from "../src/encoding.mjs";
import { validateIssuerTrust } from "../src/profile.mjs";
import {
  ISSUER_PRIVATE_PEM,
  ISSUER_PUBLIC_PEM,
  LOG_PRIVATE_PEM,
  LOG_PUBLIC_PEM,
} from "../fixtures/test-keys.mjs";
import { buildFixtureSet } from "../tools/fixture-api.mjs";
import { assert, bytes, clone, expectCode } from "./assertions.mjs";

// Small-order and non-canonical Ed25519 trust keys. Under the identity key,
// R = identity and S = 0 verify for every message in Node's Ed25519, so a
// checker that trusted such a key would pass a signature nobody made.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const spki = (raw) => Buffer.concat([SPKI_PREFIX, raw]).toString("base64url");
const hex = (value) => Buffer.from(value, "hex");
const withSignBit = (raw) => {
  const copy = Buffer.from(raw);
  copy[31] |= 0x80;
  return copy;
};
const identity = Buffer.alloc(32);
identity[0] = 1;
const identitySignBit = Buffer.from(identity);
identitySignBit[31] |= 0x80;
const forgedSignature = Buffer.concat([identity, Buffer.alloc(32)]).toString("base64url");

const WEAK = [
  ["identity", identity],
  ["identity with the sign bit set", identitySignBit],
  ["y = 0, order 4", Buffer.alloc(32)],
  ["order 8, first", hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")],
  ["order 8, second", hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")],
  ["y = p - 1, order 2", hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")],
];
const NONCANONICAL = [
  ["y = p", hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")],
  ["y = p + 1", hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")],
  ["y = 2^255 - 1", hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")],
];

function fixture() {
  return buildFixtureSet({
    size: 1,
    issuerPrivateKey: ISSUER_PRIVATE_PEM,
    issuerPublicKey: ISSUER_PUBLIC_PEM,
    logPrivateKey: LOG_PRIVATE_PEM,
    logPublicKey: LOG_PUBLIC_PEM,
  });
}

export function runWeakKeyTests() {
  // Each weak or non-canonical value is refused with either sign bit.
  for (const [name, raw] of WEAK) {
    for (const value of [raw, withSignBit(raw)]) {
      expectCode(() => parseEd25519Spki(spki(value)), "weak-ed25519-public-key");
    }
    void name;
  }
  for (const [name, raw] of NONCANONICAL) {
    for (const value of [raw, withSignBit(raw)]) {
      expectCode(() => parseEd25519Spki(spki(value)), "noncanonical-ed25519-point");
    }
    void name;
  }

  // A valid key with the sign bit set still parses: RFC 8032 section 7.1, test SHA(abc).
  parseEd25519Spki(spki(hex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")));

  const set = fixture();
  // Control: the genuine fixture keys still parse and the genuine set still passes.
  parseEd25519Spki(set.issuerTrust.issuers[0].spki);
  parseEd25519Spki(set.logTrust.logs[0].spki);
  const control = checkArtifacts({
    receiptBytes: bytes(set.receipts[0]),
    issuerTrustBytes: bytes(set.issuerTrust),
    logTrustBytes: bytes(set.logTrust),
    treeHeadBytes: bytes(set.treeHead),
  });
  assert.equal(control.result, RESULT.PASSED, "genuine fixture set must still pass");

  // A weak issuer key in the trust file must be refused at trust load.
  const weakIssuerTrust = clone(set.issuerTrust);
  weakIssuerTrust.issuers[0].spki = spki(identity);
  expectCode(() => validateIssuerTrust(weakIssuerTrust), "weak-ed25519-public-key");

  // End to end: a weak issuer key and a signature nobody made must not pass.
  const forgedReceipt = clone(set.receipts[0]);
  forgedReceipt.signature = forgedSignature;
  const a = checkArtifacts({
    receiptBytes: bytes(forgedReceipt),
    issuerTrustBytes: bytes(weakIssuerTrust),
    logTrustBytes: bytes(set.logTrust),
    treeHeadBytes: bytes(set.treeHead),
  });
  assert.notEqual(a.result, RESULT.PASSED, "a small-order issuer key must not pass");

  // One weak point written two ways, as issuer and log key, both signatures forged.
  const weakLogTrust = clone(set.logTrust);
  weakLogTrust.logs[0].spki = spki(identitySignBit);
  const forgedHead = clone(set.treeHead);
  forgedHead.signature = forgedSignature;
  const b = checkArtifacts({
    receiptBytes: bytes(forgedReceipt),
    issuerTrustBytes: bytes(weakIssuerTrust),
    logTrustBytes: bytes(weakLogTrust),
    treeHeadBytes: bytes(forgedHead),
  });
  assert.notEqual(b.result, RESULT.PASSED, "two encodings of one weak point must not pass");
}
