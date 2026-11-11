import { timingSafeEqual, verify as edVerify } from "node:crypto";
import { parseStrictJson } from "./strict-json.mjs";
import { safeCode } from "./errors.mjs";
import {
  issuerSignaturePreimage,
  treeHeadSignaturePreimage,
  validateIssuerTrust,
  validateLogTrust,
  validateReceipt,
  validateTreeHead,
} from "./profile.mjs";
import { inclusionRoot, leafHash } from "./merkle.mjs";

const RESULT = Object.freeze({
  PASSED: "ARTIFACT CHECKS PASSED",
  FAILED: "ARTIFACT CHECKS FAILED",
  UNTRUSTED: "ARTIFACT CHECKS UNTRUSTED",
});

export const RESULT_EXIT_CODE = Object.freeze({
  [RESULT.PASSED]: 0,
  [RESULT.FAILED]: 1,
  [RESULT.UNTRUSTED]: 3,
});

function check(checks, name, status, detail) {
  checks.push(Object.freeze({ name, status, detail }));
}

function load(bytes, validator, checks, name) {
  try {
    const parsed = parseStrictJson(bytes);
    const validated = validator(parsed);
    check(checks, name, "PASS", "bounded profile accepted");
    return validated;
  } catch (error) {
    check(checks, name, "FAIL", safeCode(error));
    return null;
  }
}

function cryptoVerify(preimage, key, signature) {
  try {
    return edVerify(null, preimage, key, signature);
  } catch {
    return false;
  }
}

function hasFailure(checks) {
  return checks.some((entry) => entry.status === "FAIL");
}

function hasUntrusted(checks) {
  return checks.some((entry) => entry.status === "UNTRUSTED");
}

/**
 * Offline bounded artifact checking. No receipt data is ever used as a trust
 * source; issuer and log trust snapshots are separate caller-supplied inputs.
 */
export function checkArtifacts({ receiptBytes, issuerTrustBytes = null, logTrustBytes = null, treeHeadBytes = null }) {
  const checks = [];
  const receipt = load(receiptBytes, validateReceipt, checks, "receipt_profile");
  if (!receipt) return Object.freeze({ checks, result: RESULT.FAILED, exitCode: RESULT_EXIT_CODE[RESULT.FAILED] });
  check(checks, "stated_scope", "PASS", "artifact-digest-only; non-observation limits are signed");

  let issuerTrust = null;
  if (issuerTrustBytes === null) {
    check(checks, "issuer_trust", "UNTRUSTED", "no external issuer trust snapshot supplied");
  } else {
    issuerTrust = load(issuerTrustBytes, validateIssuerTrust, checks, "issuer_trust");
  }

  let logTrust = null;
  if (logTrustBytes === null) {
    check(checks, "log_trust", "UNTRUSTED", "no external log trust snapshot supplied");
  } else {
    logTrust = load(logTrustBytes, validateLogTrust, checks, "log_trust");
  }

  let treeHead = null;
  if (treeHeadBytes === null) {
    check(checks, "tree_head", "UNTRUSTED", "no external signed tree-head snapshot supplied");
  } else {
    treeHead = load(treeHeadBytes, validateTreeHead, checks, "tree_head");
  }

  let selectedIssuer = null;
  if (issuerTrust) {
    const keyId = receipt.statement.issuer.key_id;
    const key = issuerTrust.byId.get(keyId);
    if (!key) {
      check(checks, "issuer_signature", "FAIL", "issuer key id is absent from supplied issuer trust");
    } else {
      selectedIssuer = key;
      const valid = cryptoVerify(issuerSignaturePreimage(receipt.statement), key.publicKey, receipt.signature);
      check(checks, "issuer_signature", valid ? "PASS" : "FAIL", valid ? "trusted Ed25519 issuer signature" : "signature mismatch");
    }
  } else if (!hasFailure(checks)) {
    check(checks, "issuer_signature", "UNTRUSTED", "receipt key id is not a trust source");
  }

  if (treeHead) {
    const sameLog = receipt.statement.receipt.log_id === treeHead.head.log_id;
    check(checks, "log_binding", sameLog ? "PASS" : "FAIL", sameLog ? "signed receipt log id matches tree head" : "receipt log id and tree head log id differ");
    const sameSize = receipt.treeSize === treeHead.treeSize;
    check(checks, "tree_size_binding", sameSize ? "PASS" : "FAIL", sameSize ? "inclusion tree size matches tree head" : "inclusion tree size and tree head size differ");

    try {
      const calculated = inclusionRoot(leafHash(receipt.statementBytes), receipt.leafIndex, receipt.treeSize, receipt.path);
      const validRoot = timingSafeEqual(calculated, treeHead.root);
      check(checks, "merkle_inclusion", validRoot ? "PASS" : "FAIL", validRoot ? "path reaches supplied tree-head root" : "path does not reach supplied tree-head root");
    } catch (error) {
      check(checks, "merkle_inclusion", "FAIL", safeCode(error));
    }

    let selectedLog = null;
    if (logTrust) {
      const key = logTrust.byId.get(treeHead.head.log_id);
      if (!key) {
        check(checks, "tree_head_signature", "FAIL", "log id is absent from supplied log trust");
      } else {
        selectedLog = key;
        const valid = cryptoVerify(treeHeadSignaturePreimage(treeHead.head), key.publicKey, treeHead.signature);
        check(checks, "tree_head_signature", valid ? "PASS" : "FAIL", valid ? "trusted Ed25519 tree-head signature" : "signature mismatch");
      }
    } else if (!hasFailure(checks)) {
      check(checks, "tree_head_signature", "UNTRUSTED", "tree-head key is not a trust source");
    }
    if (selectedIssuer && selectedLog) {
      const sameKeyMaterial = selectedIssuer.publicKeyDer.length === selectedLog.publicKeyDer.length
        && timingSafeEqual(selectedIssuer.publicKeyDer, selectedLog.publicKeyDer);
      const separate = !sameKeyMaterial;
      check(
        checks,
        "issuer_log_key_separation",
        separate ? "PASS" : "FAIL",
        separate ? "selected issuer and log trust keys differ" : "selected issuer and log trust keys must differ",
      );
    }
  } else if (!hasFailure(checks)) {
    check(checks, "merkle_inclusion", "UNTRUSTED", "no tree-head root is available for comparison");
  }

  let result = RESULT.PASSED;
  if (hasFailure(checks)) result = RESULT.FAILED;
  else if (hasUntrusted(checks)) result = RESULT.UNTRUSTED;
  return Object.freeze({ checks, result, exitCode: RESULT_EXIT_CODE[result] });
}

export function renderReport(report) {
  const lines = report.checks.map((entry) => `${entry.status.padEnd(9)} ${entry.name.padEnd(22)} ${entry.detail}`);
  lines.push("");
  lines.push(`RESULT: ${report.result}`);
  lines.push("ESTABLISHED SCOPE: bounded statement schema, trusted issuer signature, and inclusion against a separately trusted signed tree-head snapshot only when RESULT is ARTIFACT CHECKS PASSED.");
  lines.push("NOT ESTABLISHED: that the issuer is honest, that any artifact digest matches a real artifact, that the inventory is complete, agent execution, event observation, a runtime measurement or hardware attestation, deletion or retention, hardware key protection, trusted time, freshness or uniqueness, a public log, append-only history or consistency, production safety, or completed research.");
  return `${lines.join("\n")}\n`;
}

export { RESULT };
