# Signed Agent Receipt Reference Profile v0.2

**Status:** bounded offline reference profile, 2026-11-02  
**Identifier family:** `sar-ri-*`  
**Normative language:** the terms **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are to be interpreted as described by RFC 2119 / RFC 8174.

This is a strict, offline format for checking a signed structured statement and its membership in a separately signed Merkle-tree head against caller-supplied trust inputs. It is intentionally named **Signed Agent Receipt**, not “attested.” It does not verify a hardware or runtime attestation chain, observe an agent or an event, measure retention or deletion, authenticate time, establish a public append-only log, or report a research result.

All conformance fixtures shipped with this reference material are deterministic synthetic test data. They are not records of customer tasks, real agent runs, payments, logs, runtimes, hardware, or storage systems.

## 1. What an artifact-check pass establishes

Given a valid receipt, issuer-trust file, log-trust file, and signed tree-head file, a pass establishes only all of the following:

1. A public key selected from the caller's issuer trust file verified an Ed25519 signature over the exact canonical `statement` bytes defined here.
2. A public key selected from the caller's log trust file verified an Ed25519 signature over the exact canonical `head` bytes defined here.
3. The statement's leaf computes to the signed head's root under this profile's bounded Merkle inclusion algorithm.
4. The signed statement has the required fixed schema and limitation markers.

It does **not** establish that an issuer is honest, that any artifact digest corresponds to a real artifact, that an inventory is complete, that an agent executed, that an action was observed, that a runtime had a particular measurement, that data was retained or deleted, that a key was hardware protected, that a clock is correct, that the receipt is fresh or unique, or that a log is public or append-only.

The checker therefore uses `ARTIFACT CHECKS PASSED`, never `VERIFIED`, as its positive result. A relying party, not a receipt, chooses its trust anchors and the decision it is willing to make from this limited result.

## 2. Roles and external trust

* **Issuer:** controls an Ed25519 private key and signs a `statement`.
* **Log signer:** controls a distinct Ed25519 private key and signs a profile-specific Merkle tree head.
* **Relying party:** obtains, pins, rotates, and revokes trusted issuer and log keys outside this format; it invokes the checker with those trust files.

The receipt never supplies a usable public key. Its `issuer.key_id` and `receipt.log_id` are opaque selectors only. A matching identifier inside a receipt does not authenticate a key, a person, a runtime, or a log. The trust files themselves are caller-controlled snapshots; their distribution, key rotation, revocation, and compromise handling are outside v0.2. For a passing receipt, the selected issuer and selected log SPKIs MUST be different public keys; an equal key in both roles fails with `issuer_log_key_separation`.

## 3. Restricted canonical JSON profile

The profile canonicalizes parsed values; the original whitespace and member order of a received JSON file are not signed. Before canonicalization, every input JSON document MUST satisfy all of these rules:

* It is valid UTF-8 JSON with no byte-order mark.
* Duplicate object member names are rejected **after JSON escape decoding**. For example, `"a"` and `"\\u0061"` are duplicates.
* Every string is a sequence of Unicode scalar values. A lone UTF-16 surrogate, including one introduced through a `\\uXXXX` escape, is rejected.
* JSON number tokens are prohibited everywhere. Integer values use the canonical decimal-string form in Section 4 instead. `"1"` is a string; `1`, `1.0`, `1e0`, and `-0` are invalid input.
* Arrays retain their supplied order. Objects are recursively sorted by unsigned UTF-16 code units of their decoded member names, independent of locale.
* Canonical output uses no insignificant whitespace, RFC 8785-compatible JSON string escaping, and UTF-8 encoding.

This is a deliberately restricted, JCS-compatible subset of RFC 8785; it is **not** a claim of complete RFC 8785 conformance. Rejecting numbers avoids silently rounding an application value during ECMAScript number serialization. The profile's test suite must include RFC 8785 Unicode ordering material and negative number/lone-surrogate cases, but a passing suite does not certify arbitrary JSON canonicalizers.

`restrictedCanonical(value)` denotes the resulting JSON text and `UTF8(x)` denotes its UTF-8 byte sequence.

### 3.1 Common lexical forms

| Name | Required form |
|---|---|
| `ID` | ASCII matching `[a-z][a-z0-9._-]{0,63}` |
| `DIGEST` | `sha256:` followed by exactly 64 lowercase hexadecimal characters |
| `DECIMAL` | `0` or `[1-9][0-9]*`; no sign, whitespace, leading zero, decimal point, or exponent |
| `B64URL` | Unpadded RFC 4648 base64url. The encoded text MUST be canonical: decode then re-encode without padding and compare byte-for-byte. |

`tree_size` MUST be a `DECIMAL` in `1..2147483647`; `leaf_index` MUST be a `DECIMAL` in `0..tree_size-1`. `receipt_id`, `key_id`, and `log_id` are IDs. IDs are opaque and may be replayed or linkable; no freshness, uniqueness, time, or privacy property follows from their syntax.

## 4. Receipt schema

A receipt is a JSON object with exactly these three members and no extensions:

```text
Receipt = {
  statement: Statement,
  signature: B64URL(64 decoded bytes),
  inclusion: Inclusion
}
```

`Statement` has exactly `profile`, `issuer`, and `receipt`:

```text
Statement = {
  profile: "sar-ri-statement-v0.2",
  issuer: { algorithm: "Ed25519", key_id: ID },
  receipt: {
    receipt_id: ID,
    log_id: ID,
    assertions: {
      runtime_artifact: DIGEST,
      policy_artifact: DIGEST
    },
    inventory: {
      tool_artifacts: [DIGEST, ...],
      egress_artifacts: [DIGEST, ...],
      file_artifacts: [DIGEST, ...],
      payment_artifacts: [DIGEST, ...]
    },
    scope: {
      evidence: "artifact-digest-only",
      attestation: "not-implemented",
      observation: "not-implemented",
      retention: "not-measured",
      time: "not-authenticated",
      history: "not-checked"
    }
  }
}

Inclusion = {
  tree_size: DECIMAL,
  leaf_index: DECIMAL,
  path: [DIGEST, ...]  // zero or more digests
}
```

Every listed member is REQUIRED. Every inventory array is REQUIRED, may be empty, and contains at most 16 entries. Array order is signed but has no event-order meaning in this profile. The profile has no optional fields, no extension map, no vendor field, and no algorithm agility.

The two `assertions` and four `inventory` arrays contain issuer-supplied SHA-256 artifact digests only. Their names do not make them an observation log, establish the contents or provenance of an artifact, identify a collection boundary, or prove an exhaustive account of a run. The fixed `scope` object is signed precisely to keep those unimplemented properties visible rather than implied by a pass.

## 5. Issuer signature

The issuer signs these exact bytes:

```text
statementBytes = UTF8(restrictedCanonical(statement))
issuerPrefix   = ASCII("SAR-RI-v0.2") || 0x00 || ASCII("issuer-signature") || 0x00
issuerPreimage = issuerPrefix || statementBytes
signature = Ed25519.Sign(issuerPrivateKey, issuerPreimage)
```

The exact `issuerPrefix` octets are `5341522d52492d76302e32006973737565722d7369676e617475726500`. `0x00` above is one zero byte, not printable text. The profile uses pure Ed25519 only; Ed25519ctx, Ed25519ph, Ed448, a prehashed message, and a substituted algorithm fail. The trust-selected issuer SPKI MUST parse as an Ed25519 public key and `signature` MUST decode to exactly 64 bytes.

The domain label, the `statement.profile` value, the key ID, and every statement field are therefore bound by the issuer signature. Neither `inclusion` nor a JSON serialization of the outer receipt is part of this signature; membership is separately bound to the same `statementBytes` in Section 7.

## 6. Profile-specific signed tree head

The receipt has no self-supplied root. It must be paired with a separate head file:

```text
TreeHead = {
  head: {
    profile: "sar-ri-tree-head-v0.2",
    log_id: ID,
    algorithm: "Ed25519",
    tree_size: DECIMAL,
    root: DIGEST
  },
  signature: B64URL(64 decoded bytes)
}
```

The log signer signs these exact bytes:

```text
headBytes = UTF8(restrictedCanonical(head))
headPrefix   = ASCII("SAR-RI-v0.2") || 0x00 || ASCII("tree-head-signature") || 0x00
headPreimage = headPrefix || headBytes
headSignature = Ed25519.Sign(logPrivateKey, headPreimage)
```

The exact `headPrefix` octets are `5341522d52492d76302e3200747265652d686561642d7369676e617475726500`. `statement.receipt.log_id`, `inclusion.tree_size`, and the signed `head.log_id` / `head.tree_size` MUST agree. `head.root` is the only accepted root for the inclusion calculation.

This is a **profile-specific signed Merkle tree head/root snapshot**. It is not an RFC 9162 `SignedTreeHead` wire object, not a Certificate Transparency implementation, and not evidence of a public transparency service. It deliberately contains no timestamp. One valid head gives no trusted event time, publication evidence, consistency proof, split-view detection, monitor observation, or append-only-history result.

## 7. Merkle membership

The binary hash-tree recurrence and recursive audit-path shape follow RFC 9162 Sections 2.1.1 and 2.1.3 (which obsoletes RFC 6962). This narrow reuse does not claim RFC 9162 protocol conformance.

Let `H` be SHA-256 and let `d[i]` be the raw leaf input bytes. For the receipt being checked:

```text
d[leaf_index] = statementBytes
leafHash        = H(0x00 || statementBytes)
nodeHash(L, R)  = H(0x01 || L || R)
```

For a list of `n > 1` leaves, choose `k` as the largest power of two strictly less than `n`. Its Merkle tree hash is:

```text
MTH(D[n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
```

The audit path is bottom-up in the recursive order defined by RFC 9162. The checker MUST derive the required path length from `tree_size` and `leaf_index`, require it exactly, consume every sibling exactly once, and compare the computed root with the decoded `head.root`. A size-one tree requires `path: []`; an empty path fails whenever the required length is nonzero. A shortened, extended, malformed, or mismatched path fails. Because this profile permits only a nonempty tree and a maximum `tree_size` of `2147483647`, a path has at most 31 digests.

An inclusion pass establishes membership of these `statementBytes` in this one signed root snapshot, under the trusted log key. It does not establish that other leaves exist, that the signer operated a complete log, or that later heads extend this head.

## 8. Trust-file schemas

Issuer and log trust are separate external files. A receipt cannot replace either role.

```text
IssuerTrust = {
  profile: "sar-ri-issuer-trust-v0.2",
  issuers: [{ key_id: ID, algorithm: "Ed25519", spki: B64URL }]
}

LogTrust = {
  profile: "sar-ri-log-trust-v0.2",
  logs: [{ log_id: ID, algorithm: "Ed25519", spki: B64URL }]
}
```

Each object has exactly the members shown. Each array has at most 16 entries and no duplicate decoded IDs. An `spki` decodes to 32 through 1024 bytes, is canonical unpadded base64url, and MUST be canonical DER for an Ed25519 SubjectPublicKeyInfo: parse it as Ed25519, re-export its SPKI DER, and require byte-for-byte equality with the decoded input. After the matching issuer and log trust entries are selected, their canonical public-key material MUST differ. An algorithm string, a key ID, or an SPKI in a receipt never causes trust; only the relying party's matching external trust entry does.

The 32-byte Ed25519 public key in each trust `spki` MUST be a canonical point encoding and MUST NOT be a point of order 1, 2, 4 or 8. Read the 32 bytes as a little-endian integer and clear bit 255 (the sign of x); call the result y. First, if y is not below 2^255 - 19, reject the key with `noncanonical-ed25519-point`. Then, if y is one of the five small-order values, reject it with `weak-ed25519-public-key`, whatever the sign bit. As little-endian hex with bit 255 cleared, the five values are `0000000000000000000000000000000000000000000000000000000000000000` (order 4), `0100000000000000000000000000000000000000000000000000000000000000` (order 1), `ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (order 2), `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05` (order 8) and `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a` (order 8). Under a small-order key, a signature nobody made can verify. These rules make two accepted keys equal exactly when they are the same point. Different key bytes still don't show different key holders.

## 9. Bounds and rejection behavior

The checker MUST fail safely when an input exceeds a bound. These are parser and verifier bounds, not a general denial-of-service guarantee.

| Item | Maximum |
|---|---:|
| Raw JSON bytes, each input file | 256 KiB |
| JSON nesting depth | 32 |
| JSON nodes | 1,024 |
| Members in one object | 32 |
| Items in one raw JSON array | 64 |
| String length | 8,192 UTF-16 code units |
| Inventory entries per array | 16 |
| Trust records per trust file | 16 |
| Tree size | 2,147,483,647 |
| Inclusion siblings | 31 and exactly the required count |
| Decoded SPKI | 32–1,024 bytes |
| Decoded Ed25519 signature | 64 bytes |

Unknown members, missing members, wrong literal values, an unsupported version/profile, a malformed lexical form, an oversized value, or an invalid cryptographic check are failures. Version negotiation and extensions are intentionally absent: a changed shape requires a new profile identifier and a separately reviewed verifier.

## 10. Result states

| State | Meaning |
|---|---|
| `ARTIFACT CHECKS PASSED` (exit 0) | All required inputs are present; strict schema, distinct selected issuer/log keys, trusted issuer signature, trusted tree-head signature, identifier/size binding, and bounded inclusion calculation pass. |
| `ARTIFACT CHECKS FAILED` (exit 1) | Any supplied input is malformed, outside the profile, exceeds a bound, lacks a matching trusted key, has an invalid signature, or fails the inclusion/root check. |
| `ARTIFACT CHECKS UNTRUSTED` (exit 3) | The receipt may be structurally usable, but a required external issuer trust input, log trust input, or signed tree head was not supplied. No authenticity conclusion is made. |
| Usage error (exit 2) | Required command-line arguments are absent or malformed before a verification attempt. |

A pass result MUST print the positive scope and the fixed list of non-established properties from Section 1. A caller must not convert `ARTIFACT CHECKS UNTRUSTED` into a pass by accepting keys, roots, or evidence embedded in a receipt.

## 11. Security, privacy, and operational assumptions

The cryptographic result depends on SHA-256 collision/second-preimage resistance, correct Ed25519 implementation, correct strict parsing/canonicalization, secure private-key custody, and correct out-of-band trust selection. It does not defend against a trusted issuer or log signer making a false statement, compromised keys, inconsistent externally distributed trust files, a malicious collector that omits data, or an independently valid but irrelevant statement.

Receipt IDs, issuer IDs, log IDs, artifact digests, array cardinality, and repeated statements can be correlation material. A predictable artifact can be vulnerable to dictionary matching. Different recipients can combine this metadata with outside data. The profile provides no confidentiality, anonymous credential, selective-disclosure, unlinkability, erasure, or data-minimization guarantee. Do not place personal data, prompts, outputs, paths, credentials, raw hostnames, or real task data in a conformance fixture merely because the file is signed.

## 12. Required test-vector categories

An implementation claiming compatibility with this profile MUST run and disclose the result of at least these deterministic tests:

1. RFC 8032 Section 7.1 Ed25519 test vector 1 (the empty-message vector), independently of this format's fixtures.
2. RFC 8785 Section 3.2.3 Unicode member-order material, including the UTF-16 code-unit ordering rule; a lone-surrogate input must be rejected.
3. Number-token inputs such as `{"n":1}` and `{"n":1e+30}` must be rejected rather than serialized. This is a negative profile test, not an implementation of RFC 8785 number serialization.
4. Fixed synthetic statement and head fixtures that expose the complete ASCII domain labels, canonical byte strings, SHA-256 leaf/root values, and Ed25519 signatures used by this profile.
5. Independent-oracle Merkle cases for size 1, powers of two, and uneven tree sizes; every leaf position; and truncated, extra, reordered, and corrupted paths.
6. Negative strict-input cases: duplicate decoded names, malformed UTF-8, BOM, lone surrogates, noncanonical base64url or SPKI DER, small-order or noncanonical Ed25519 points, wrong algorithm/key type, missing fields, unknown fields, excess nesting/size, and trust-ID substitution.

These vectors prove only the cases tested. They are not a security audit, production readiness determination, vendor attestation validation, or empirical study.

## 13. Migration from AAR v0.1

This profile is intentionally incompatible with the historical **Attested Agent Receipt (AAR) v0.1** draft. It removes the unsupported attestation framing and v0.1's claimed retention/event field semantics, uses strict schema and parser rules, uses explicit signing domain labels, signs a separate externally trusted root snapshot, and adopts a bounded recursive Merkle proof verifier.

There is no automatic conversion. A v0.1 receipt MUST NOT be relabeled, reserialized, or treated as a v0.2 receipt. Reissuing content under v0.2 is appropriate only when an issuer deliberately creates a new v0.2 statement and records its actual provenance. Deterministic synthetic data may be reissued solely as a clearly marked conformance fixture, never as evidence that an old or new real run occurred.

## 14. Deliberately missing integrations

The following require separate designs, evidence, and review before any corresponding claim is made:

* hardware or remote-attestation appraisal, endorsements, reference values, and attestation-result handling;
* an instrumented observer, coverage map, event-to-key binding, bypass detection, and collector-failure accounting;
* retention/deletion measurement across local and remote systems;
* authenticated time, challenges/nonces, replay detection, receipt uniqueness, and freshness policy;
* trust distribution, issuer authorization policy, key rotation/revocation, and compromise response;
* public log operation, consistency proofs, gossip, monitors, split-view detection, and append-only claims;
* a production deployment, real keys, real agent/runtime data, external security audit, or independent implementation interoperability matrix; and
* an empirical privacy, usability, or decision-quality study.

## 15. Standards and source snapshots

An internal reproducibility manifest, not published on this site, pins the URLs, retrieval date, byte counts, and SHA-256 digests of the primary reference texts consulted for this profile.

* [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html): JSON Canonicalization Scheme. This profile uses only a restricted compatible subset and does not claim full JCS conformance.
* [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html): Ed25519 definition and test vectors.
* [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html): recursive Merkle hash and inclusion-path structure. It obsoletes RFC 6962; this profile does not implement the CT protocol or wire format.
* [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html): RATS terminology explaining why a signed statement is not remote attestation evidence or an appraisal result.

