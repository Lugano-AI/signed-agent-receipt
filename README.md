# Signed Agent Receipt v0.2

> This is the reference implementation of Signed Agent Receipt v0.2, with its tests and fixtures, published by Lugano Labs. The research behind it is at [lugano.ai/research/attested-agent-receipt](https://lugano.ai/research/attested-agent-receipt/), and our internal review of an earlier verifier is at [lugano.ai/research/receipt-verifier](https://lugano.ai/research/receipt-verifier/). The keys in `fixtures/test-keys.mjs` are public test keys. Never use them for anything real.

This directory contains a bounded offline **Signed Agent Receipt** reference profile and verifier. It checks a strict signed statement plus membership in a separately signed Merkle tree head using trust files supplied by the verifier's caller.

It is not called “attested” because it does not validate hardware roots, appraise a runtime, or establish a remote-attestation result. It also does not operate or query a public append-only log.

Read the complete wire contract, exact byte preimages, bounds, threat model, privacy limits, migration rules, and standards references in [SPEC.md](SPEC.md).

## Quick use

Requires Node.js 22 or newer and has no runtime dependency on a network service.

```bash
node test/run.mjs

node cli/check.mjs \
  --receipt RECEIPT.json \
  --issuer-trust ISSUER-TRUST.json \
  --log-trust LOG-TRUST.json \
  --tree-head TREE-HEAD.json
```

The checker accepts these outcomes:

| Exit | Result | Meaning |
|---:|---|---|
| 0 | `ARTIFACT CHECKS PASSED` | The strict schema, caller-pinned issuer signature, caller-pinned tree-head signature, and bounded inclusion proof all pass. |
| 1 | `ARTIFACT CHECKS FAILED` | An input is malformed, exceeds a bound, has an invalid signature/proof, or does not match the supplied trust. |
| 3 | `ARTIFACT CHECKS UNTRUSTED` | A required external trust input or signed tree head was not supplied; no authenticity conclusion follows. |
| 2 | Usage error | The command invocation cannot start a verification attempt. |

An exit 0 does not establish that the signed fields are true, complete, fresh, observed, retained, deleted, hardware-attested, or publicly logged. The checker prints that limited scope with a pass result.

## Trust boundary

The receipt contains only key and log identifiers. The trusted Ed25519 SPKIs live in separate issuer and log trust files chosen by the relying party. Nothing embedded in a receipt can enroll, replace, or authorize a key. The checker refuses a trust key that is a small-order or non-canonical Ed25519 point, since anyone can make a signature that verifies under a small-order key ([SPEC.md](SPEC.md#8-trust-file-schemas) section 8). Trust-file delivery, rotation, revocation, and compromise response are out of scope.

The tree head is a profile-specific signed root snapshot. The profile reuses the bounded RFC 9162 Merkle tree recurrence, but is not an RFC 9162/Certificate Transparency implementation. There is no timestamp, consistency proof, monitor, public-log query, or append-only-history result.

## Synthetic fixtures only

The `fixtures/` and `test/` material is deterministic conformance data. It uses test keys and opaque digest identifiers only. It is not a real run, customer task, payment, runtime measurement, hardware quote, event ledger, public log, or research study. Do not add production secrets or real task data to it.

## Compatibility

v0.2 is intentionally incompatible with the historical AAR v0.1 draft and verifier. Do not convert, relabel, or feed a v0.1 receipt to this checker. See [SPEC.md](SPEC.md#13-migration-from-aar-v01) for the migration boundary and [SPEC.md](SPEC.md#14-deliberately-missing-integrations) for the work still required before broader assurance claims.

The portable validation bundle is described in [validation/README.txt](validation/README.txt). It records the deterministic fixture/test evidence distributed with this profile; it is not a production or research-study record.


## Release and review

| | |
|---|---|
| Specification | [SPEC.md](SPEC.md), profile v0.2: `sar-ri-statement-v0.2`, `sar-ri-tree-head-v0.2`, `sar-ri-issuer-trust-v0.2`, `sar-ri-log-trust-v0.2` |
| Code, tests and fixtures | Commit `3ccd846ca2fe7d83d8eb17ceb3f3de60366cacdc`. [SHA256SUMS](SHA256SUMS) lists the hash of every file except itself, LICENSE and CITATION.cff. |
| Verifier | `src/` and `cli/check.mjs`, 1,026 lines of JavaScript |
| Dependencies | Node.js 22 or newer and its built-in modules. There's no package.json, lockfile or third-party code. Ed25519 and SHA-256 come from the OpenSSL inside Node. |
| Fixtures | `fixtures/valid/size-1`, `size-8` and `size-17`: 26 synthetic receipts, made with the public test keys in `fixtures/test-keys.mjs` |
| Tests | `node test/run.mjs` runs six suites. On 11 November 2026, on Node v22.22.3 (OpenSSL 3.5.6, macOS arm64), all six passed. |
| Hostile-input cases | `node validation/independent-v02-audit.mjs --output /tmp/sar-v02-run.json` runs 12 cases. All 12 passed in the same run. The FIFO case needs a POSIX system with `mkfifo`. |
| Review | The internal review of 2 November 2026 ([validation/README.txt](validation/README.txt); cases and file hashes in `validation/results.json`) covers commit `221cfcf407b31ed719f1541230d44ac64f3002fe`. The trust-key rule in SPEC.md section 8 (`src/encoding.mjs`, `test/weak-keys.test.mjs`) is in commit `3ccd846`. The shipped tests cover it, and the review doesn't. |
| Outside review | None yet, of the cryptographic design or the code |
| What a pass means | [SPEC.md section 1](SPEC.md#1-what-an-artifact-check-pass-establishes) |

## License

Apache License 2.0. See [LICENSE](LICENSE). Copyright 2026 Lugano AI Holdings LLC.
