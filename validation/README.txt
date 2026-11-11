NOTE (4 November 2026): The source code, tests, fixtures, results.json,
implementation-tests.txt and SHA256SUMS this file names are not published on
lugano.ai, so the commands below can't be run from the site. This file is a
summary of an internal review record.

NOTE (11 November 2026): Three source files and two tests changed after the
review, and one test was added, so that the checker refuses weak trust keys.
See "Changes" in README.md. Of the 64 files in results.json, 56 still match
their recorded hashes. The other 8 are those five files and three documents
edited after the review: README.md, SPEC.md and this file. SHA256SUMS lists
the current files.

Signed Agent Receipt v0.2 — internal review record
2 November 2026

WHAT THIS IS

Executable reference code, a wire contract, synthetic conformance fixtures,
and reproducible local tests. This record is an agent-assisted internal
engineering review. A separate reviewer authored the hostile-input harness;
it is not an independent external human audit or a security certification.

WHAT THE CODE CHECKS

Required structure and input bounds; a statement signed by a caller-selected
issuer key; a root snapshot signed by a separate caller-selected log key; and
the statement's membership under that root. See ../SPEC.md for exact bytes,
required fields, limits, and trust assumptions.

The checker does not observe agent execution, validate hardware attestation,
establish event truth or completeness, measure retention/deletion, authenticate
time, check a log's consistency history, or operate a public log. Digest fields
are issuer assertions, not measured artifacts. A signature cannot make an
unobserved or dishonest statement true.

REPRODUCE

From the receipt-v0.2 directory, with Node.js 22 or newer:

  node test/run.mjs
  node validation/independent-v02-audit.mjs --output /tmp/sar-v02-review.json

Inspect /tmp/sar-v02-review.json for the individual cases, failures, environment,
and before/after source manifests. Use another output path if this one already
contains a record you want to keep. The harness runs locally and uses Node's
built-in crypto; it does not contact a network service or install dependencies.
The FIFO-input regression test requires a POSIX environment with mkfifo.

A supplied fixture can be checked directly:

  node cli/check.mjs \
    --receipt fixtures/valid/size-17/receipt-8.json \
    --issuer-trust fixtures/valid/size-17/issuer-trust.json \
    --log-trust fixtures/valid/size-17/log-trust.json \
    --tree-head fixtures/valid/size-17/tree-head.json

These files use disclosed test keys and deterministic synthetic inputs. They
are not customer data, observed agent runs, payments, or a research study.
Never use the fixture keys for production.

RECORDED COVERAGE

The packaged results.json and implementation-tests.txt record the final local
execution. The separately authored harness covers:

- Every leaf index in independently constructed trees of sizes 1 through 64:
  2,080 valid receipt vectors.
- 8,264 path-length dimensions, including the maximum allowed tree size.
  These are path-shape checks, not execution of a two-billion-leaf tree.
- 18 hostile raw-parser cases and 17 signature/proof/encoding mutations.
- Key substitution, key type and issuer/log separation; fixed schema checks;
  absent-trust behavior; Unicode ordering and fixed Ed25519 test material.
- A fixture tree made with fresh independent test keys, checked through the
  shipped command-line program for all 17 receipts.
- CLI status codes, oversized and nonregular inputs, including FIFO rejection;
  the shipped tests and JavaScript syntax checks.

The harness constructs expected canonical bytes and Merkle roots without
importing the implementation's canonicalizer, Merkle generator, or test keys.
It still shares Node/OpenSSL's cryptographic primitives with the implementation.
That common dependency is a limit; this is not cross-provider validation.

DEFECTS FOUND AND CORRECTED DURING THIS REVIEW

- Historical AAR v0.1 mishandled valid inclusion paths and accepted incomplete
  and duplicate-member inputs. The new profile is deliberately incompatible;
  archived v0.1 code and dated failure records remain unchanged elsewhere in
  the site's materials. v0.2 does not retroactively validate v0.1 receipts.
- An early v0.2 check compared SPKI text rather than key identity. Alternate
  encodings of one key could bypass role separation. The corrected code
  validates canonical key material and rejects the tested bypass.
- Early CLI handling classified oversized supplied files as invocation errors
  and could block opening a FIFO. Input failure classification and nonblocking
  regular-file checks were corrected, then tested by the separate harness.
- Documentation was reconciled with the actual flags, exit codes, result
  strings, schema paths, and exact domain-prefix bytes.

No unresolved failure remains in the recorded case set. This is a statement
about those cases and exact files, not proof that no defects remain.

PROVENANCE AND LIMITS

results.json contains before/after hashes of the implementation, fixtures,
tests, specification, and this harness. SHA256SUMS covers all bundled files
except itself, including the recorded results. It detects changes relative to
this package; it is not an externally signed release or authenticity service.

The proposed richer/minimized-record privacy study on the research pages has
not been run. No human-review results, performance benefit, privacy improvement,
runtime security result, or production deployment follows from these tests.

Next outside review should examine the wire contract, parser and cryptographic
bindings, interoperability with an independently maintained implementation,
operational key delivery/revocation, and any future event collector. Real-world
claims require evidence from that collector and its coverage gaps. They cannot
be established by adding more synthetic receipts to this suite.
