#!/usr/bin/env node
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { RESULT, checkArtifacts, renderReport } from "../src/verify.mjs";
import { LIMITS } from "../src/limits.mjs";

const FLAGS = new Set(["--receipt", "--issuer-trust", "--log-trust", "--tree-head"]);
const USAGE = "usage: node cli/check.mjs --receipt RECEIPT [--issuer-trust ISSUER_TRUST] [--log-trust LOG_TRUST] [--tree-head TREE_HEAD]";

function failedUsage(code) {
  return {
    checks: [{ name: "invocation", status: "FAIL", detail: code }],
    result: RESULT.FAILED,
    exitCode: 2,
  };
}

function failedInput(name, code) {
  return {
    checks: [{ name, status: "FAIL", detail: code }],
    result: RESULT.FAILED,
    exitCode: 1,
  };
}

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === "--help") return { help: true };
  const options = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!FLAGS.has(flag)) return { error: "unknown-or-positional-argument" };
    if (options.has(flag)) return { error: "repeated-option" };
    const value = argv[index + 1];
    if (typeof value !== "string" || value.startsWith("--")) return { error: "missing-option-value" };
    options.set(flag, value);
    index += 1;
  }
  if (!options.has("--receipt")) return { error: "missing-receipt-option" };
  return { options };
}

function readInput(path) {
  let descriptor;
  try {
    // O_NONBLOCK prevents a named pipe from hanging the checker before the
    // subsequent regular-file admission test.
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile()) return { error: "input-file-not-regular" };
    if (!Number.isSafeInteger(metadata.size) || metadata.size > LIMITS.maxInputBytes) {
      return { error: "input-file-too-large" };
    }
    // Allocate no more than the profile's input ceiling. Reading into this
    // fixed buffer also remains bounded if a regular file grows after fstat.
    const bytes = Buffer.allocUnsafe(metadata.size);
    const count = readSync(descriptor, bytes, 0, bytes.length, 0);
    if (count !== bytes.length) return { error: "input-file-read-error" };
    return { bytes };
  } catch {
    return { error: "input-file-unavailable" };
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // The input was already accepted or rejected; no exception text is safe output.
      }
    }
  }
}

export function main(argv) {
  const parsed = parseArguments(argv);
  if (parsed.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (parsed.error) {
    const report = failedUsage(parsed.error);
    process.stdout.write(`${renderReport(report)}${USAGE}\n`);
    return report.exitCode;
  }

  const inputs = Object.create(null);
  const mapped = [
    ["--receipt", "receiptBytes"],
    ["--issuer-trust", "issuerTrustBytes"],
    ["--log-trust", "logTrustBytes"],
    ["--tree-head", "treeHeadBytes"],
  ];
  for (const [flag, property] of mapped) {
    if (!parsed.options.has(flag)) continue;
    const loaded = readInput(parsed.options.get(flag));
    if (loaded.error) {
      const report = failedInput(`${property.slice(0, -"Bytes".length)}_input`, loaded.error);
      process.stdout.write(renderReport(report));
      return report.exitCode;
    }
    inputs[property] = loaded.bytes;
  }
  const report = checkArtifacts(inputs);
  process.stdout.write(renderReport(report));
  return report.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
