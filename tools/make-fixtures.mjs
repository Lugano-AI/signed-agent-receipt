#!/usr/bin/env node
// Generate a fresh, public-safe fixture directory from caller-provided Ed25519
// test keys. Existing output directories are refused rather than overwritten.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { buildFixtureSet, writeFixtureSet } from "./fixture-api.mjs";

const FLAGS = new Set([
  "--out",
  "--size",
  "--issuer-private-key",
  "--issuer-public-key",
  "--log-private-key",
  "--log-public-key",
]);
const REQUIRED = [...FLAGS];
const USAGE = "usage: node tools/make-fixtures.mjs --out DIR --size 1..64 --issuer-private-key PEM --issuer-public-key PEM --log-private-key PEM --log-public-key PEM";

function parse(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!FLAGS.has(flag) || values.has(flag) || typeof value !== "string" || value.startsWith("--")) return null;
    values.set(flag, value);
    index += 1;
  }
  return REQUIRED.every((flag) => values.has(flag)) ? values : null;
}

function parseSize(value) {
  if (!/^(?:[1-9]|[1-5][0-9]|6[0-4])$/.test(value)) throw new Error("invalid fixture size");
  return Number(value);
}

export function main(argv) {
  if (argv.length === 1 && argv[0] === "--help") {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  const values = parse(argv);
  if (!values) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  try {
    const fixtureSet = buildFixtureSet({
      size: parseSize(values.get("--size")),
      issuerPrivateKey: readFileSync(values.get("--issuer-private-key")),
      issuerPublicKey: readFileSync(values.get("--issuer-public-key")),
      logPrivateKey: readFileSync(values.get("--log-private-key")),
      logPublicKey: readFileSync(values.get("--log-public-key")),
    });
    writeFixtureSet(values.get("--out"), fixtureSet);
    process.stdout.write("fixture set written\n");
    return 0;
  } catch {
    // Paths, PEM errors, and internal crypto details are deliberately not
    // reflected into an automation transcript.
    process.stderr.write("fixture generation failed\n");
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
