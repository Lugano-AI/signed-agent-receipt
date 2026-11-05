import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { canonicalBytes } from "../src/canonical.mjs";
import { leafHash } from "../src/merkle.mjs";
import {
  ISSUER_SIGNATURE_PREFIX,
  TREE_HEAD_SIGNATURE_PREFIX,
  issuerSignaturePreimage,
  statementBytes,
  treeHeadSignaturePreimage,
} from "../src/profile.mjs";
import { assert } from "./assertions.mjs";

const RFC8032_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_SIGNATURE = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
  + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

export function runCryptoAndByteTests() {
  // RFC 8032 §7.1 test vector 1: empty-message Ed25519, independent of SAR.
  const privateDer = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(RFC8032_SEED, "hex")]);
  const publicDer = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(RFC8032_PUBLIC, "hex")]);
  const privateKey = createPrivateKey({ key: privateDer, format: "der", type: "pkcs8" });
  const publicKey = createPublicKey({ key: publicDer, format: "der", type: "spki" });
  const signature = sign(null, Buffer.alloc(0), privateKey);
  assert.equal(signature.toString("hex"), RFC8032_SIGNATURE);
  assert.equal(verify(null, Buffer.alloc(0), publicKey, signature), true);

  assert.equal(ISSUER_SIGNATURE_PREFIX.toString("hex"), "5341522d52492d76302e32006973737565722d7369676e617475726500");
  assert.equal(TREE_HEAD_SIGNATURE_PREFIX.toString("hex"), "5341522d52492d76302e3200747265652d686561642d7369676e617475726500");

  const statement = {
    receipt: { z: "last", a: "first" },
    issuer: { key_id: "fixture-issuer-v02", algorithm: "Ed25519" },
    profile: "sar-ri-statement-v0.2",
  };
  const exactStatement = Buffer.from('{"issuer":{"algorithm":"Ed25519","key_id":"fixture-issuer-v02"},"profile":"sar-ri-statement-v0.2","receipt":{"a":"first","z":"last"}}', "utf8");
  assert.deepEqual(statementBytes(statement), exactStatement);
  assert.deepEqual(canonicalBytes(statement), exactStatement);
  assert.deepEqual(issuerSignaturePreimage(statement), Buffer.concat([ISSUER_SIGNATURE_PREFIX, exactStatement]));
  assert.equal(leafHash(exactStatement).toString("hex"), "9393c93c3fe6af84ed5c4db42f762d1828fb5422d550320872017489346c4da2");

  const head = {
    tree_size: "1",
    root: "sha256:9393c93c3fe6af84ed5c4db42f762d1828fb5422d550320872017489346c4da2",
    algorithm: "Ed25519",
    profile: "sar-ri-tree-head-v0.2",
    log_id: "fixture-log-v02",
  };
  const exactHead = Buffer.from('{"algorithm":"Ed25519","log_id":"fixture-log-v02","profile":"sar-ri-tree-head-v0.2","root":"sha256:9393c93c3fe6af84ed5c4db42f762d1828fb5422d550320872017489346c4da2","tree_size":"1"}', "utf8");
  assert.deepEqual(treeHeadSignaturePreimage(head), Buffer.concat([TREE_HEAD_SIGNATURE_PREFIX, exactHead]));
}
