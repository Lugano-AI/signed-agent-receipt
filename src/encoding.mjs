import { createPublicKey } from "node:crypto";
import { fail } from "./errors.mjs";
import { LIMITS } from "./limits.mjs";

export const ID_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
export const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const B64U_PATTERN = /^[A-Za-z0-9_-]+$/;

export function assertId(value) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) fail("invalid-id");
  return value;
}

export function decodeDigest(value) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) fail("invalid-sha256-digest");
  return Buffer.from(value.slice("sha256:".length), "hex");
}

export function encodeDigest(value) {
  const bytes = Buffer.from(value);
  if (bytes.length !== LIMITS.digestBytes) fail("invalid-sha256-digest-bytes");
  return `sha256:${bytes.toString("hex")}`;
}

/** Decode only the unique unpadded base64url spelling for these bytes. */
export function decodeCanonicalBase64Url(value, { min = 1, max = LIMITS.maxInputBytes, code = "invalid-base64url" } = {}) {
  if (typeof value !== "string" || value.length === 0 || !B64U_PATTERN.test(value) || value.length % 4 === 1) {
    fail(code);
  }
  let decoded;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    fail(code);
  }
  if (decoded.length < min || decoded.length > max || decoded.toString("base64url") !== value) fail(code);
  return decoded;
}

export function decodeSignature(value) {
  return decodeCanonicalBase64Url(value, {
    min: LIMITS.signatureBytes,
    max: LIMITS.signatureBytes,
    code: "invalid-ed25519-signature",
  });
}

export function parseEd25519Spki(value) {
  const der = decodeCanonicalBase64Url(value, {
    min: LIMITS.minSpkiBytes,
    max: LIMITS.maxSpkiBytes,
    code: "invalid-ed25519-spki",
  });
  let key;
  try {
    key = createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    fail("invalid-ed25519-spki");
  }
  if (key.asymmetricKeyType !== "ed25519") fail("wrong-public-key-type");
  // Node accepts some BER-style length encodings. The profile accepts only the
  // canonical DER spelling, so parse then demand byte-for-byte re-export.
  const canonicalDer = Buffer.from(key.export({ type: "spki", format: "der" }));
  if (!der.equals(canonicalDer)) fail("noncanonical-ed25519-spki");
  assertStrongEd25519Point(canonicalDer.subarray(canonicalDer.length - 32));
  return key;
}

// RFC 8032 doesn't require verifiers to reject small-order public keys, and
// Node's Ed25519 verify accepts them. Under such a key anyone can make a
// signature that verifies, for example R = the identity and S = 0. So a trust
// key must be a canonical point encoding (y < p, RFC 8032 section 5.1.3) and
// must not be one of the points of order 1, 2, 4 or 8. This is the list
// libsodium checks, compared with the sign bit cleared. With both rules, two
// accepted encodings are equal exactly when they name the same point.
const ED25519_P = (1n << 255n) - 19n;
const SMALL_ORDER_Y = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((hex) => Buffer.from(hex, "hex"));

function assertStrongEd25519Point(raw) {
  if (raw.length !== 32) fail("invalid-ed25519-spki");
  const y = Buffer.from(raw);
  y[31] &= 0x7f;
  let value = 0n;
  for (let i = 31; i >= 0; i -= 1) value = (value << 8n) | BigInt(y[i]);
  if (value >= ED25519_P) fail("noncanonical-ed25519-point");
  if (SMALL_ORDER_Y.some((bad) => bad.equals(y))) fail("weak-ed25519-public-key");
}

export function parseDecimal(value, { allowZero = false, max = LIMITS.maxTreeSize, code = "invalid-decimal" } = {}) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) fail(code);
  if (!allowZero && value === "0") fail(code);
  // Number conversion is safe only after lexical admission and the explicit
  // profile ceiling. BigInt avoids a silent pre-check rounding error.
  const exact = BigInt(value);
  if (exact > BigInt(max)) fail(code);
  return Number(exact);
}
