import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  ISSUER_PRIVATE_PEM,
  ISSUER_PUBLIC_PEM,
  LOG_PRIVATE_PEM,
  LOG_PUBLIC_PEM,
} from "../fixtures/test-keys.mjs";
import { assert } from "./assertions.mjs";

const cli = fileURLToPath(new URL("../cli/check.mjs", import.meta.url));
const fixtureTool = fileURLToPath(new URL("../tools/make-fixtures.mjs", import.meta.url));
const fixtureDirectory = fileURLToPath(new URL("../fixtures/valid/size-8/", import.meta.url));

function execute(script, argumentsList) {
  return spawnSync(process.execPath, [script, ...argumentsList], { encoding: "utf8", timeout: 5_000 });
}

const checkArguments = (receiptPath) => [
  "--receipt", receiptPath,
  "--issuer-trust", join(fixtureDirectory, "issuer-trust.json"),
  "--log-trust", join(fixtureDirectory, "log-trust.json"),
  "--tree-head", join(fixtureDirectory, "tree-head.json"),
];

export function runCliTests() {
  const receipt = join(fixtureDirectory, "receipt-3.json");
  const passed = execute(cli, checkArguments(receipt));
  assert.equal(passed.status, 0);
  assert.match(passed.stdout, /RESULT: ARTIFACT CHECKS PASSED/);
  assert.doesNotMatch(passed.stdout, /VERIFIED/);

  const untrusted = execute(cli, ["--receipt", receipt]);
  assert.equal(untrusted.status, 3);
  assert.match(untrusted.stdout, /RESULT: ARTIFACT CHECKS UNTRUSTED/);
  for (const argv of [[], ["--unknown"], ["--receipt"], ["--receipt", receipt, "--receipt", receipt], ["--sth", "x"]]) {
    const output = execute(cli, argv);
    assert.equal(output.status, 2, argv.join(" "));
    assert.match(output.stdout, /RESULT: ARTIFACT CHECKS FAILED/);
  }

  const temporary = mkdtempSync(join(tmpdir(), "sar-ri-v02-cli-"));
  try {
    const huge = join(temporary, "huge.json");
    writeFileSync(huge, Buffer.alloc(256 * 1024 + 1, 0x20));
    const hugeResult = execute(cli, ["--receipt", huge]);
    assert.equal(hugeResult.status, 1);
    assert.match(hugeResult.stdout, /receipt_input\s+input-file-too-large/);
    assert.doesNotMatch(hugeResult.stdout, new RegExp(temporary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));

    const missingResult = execute(cli, ["--receipt", join(temporary, "missing.json")]);
    assert.equal(missingResult.status, 1);
    assert.match(missingResult.stdout, /input-file-unavailable/);

    const fifo = join(temporary, "input.fifo");
    const madeFifo = spawnSync("mkfifo", [fifo], { encoding: "utf8", timeout: 5_000 });
    assert.equal(madeFifo.status, 0);
    const fifoResult = execute(cli, ["--receipt", fifo]);
    assert.equal(fifoResult.status, 1);
    assert.match(fifoResult.stdout, /input-file-not-regular/);

    const issuerPrivate = join(temporary, "issuer-private.pem");
    const issuerPublic = join(temporary, "issuer-public.pem");
    const logPrivate = join(temporary, "log-private.pem");
    const logPublic = join(temporary, "log-public.pem");
    writeFileSync(issuerPrivate, ISSUER_PRIVATE_PEM);
    writeFileSync(issuerPublic, ISSUER_PUBLIC_PEM);
    writeFileSync(logPrivate, LOG_PRIVATE_PEM);
    writeFileSync(logPublic, LOG_PUBLIC_PEM);
    const generated = join(temporary, "independent-fixtures");
    const fixtureArguments = [
      "--out", generated,
      "--size", "3",
      "--issuer-private-key", issuerPrivate,
      "--issuer-public-key", issuerPublic,
      "--log-private-key", logPrivate,
      "--log-public-key", logPublic,
    ];
    const generatedResult = execute(fixtureTool, fixtureArguments);
    assert.equal(generatedResult.status, 0, generatedResult.stderr);
    const independentlyGenerated = execute(cli, [
      "--receipt", join(generated, "receipt-2.json"),
      "--issuer-trust", join(generated, "issuer-trust.json"),
      "--log-trust", join(generated, "log-trust.json"),
      "--tree-head", join(generated, "tree-head.json"),
    ]);
    assert.equal(independentlyGenerated.status, 0, independentlyGenerated.stdout);
    const overwrite = execute(fixtureTool, fixtureArguments);
    assert.equal(overwrite.status, 1);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
