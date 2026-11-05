import assert from "node:assert/strict";

export { assert };

export function expectCode(operation, expected) {
  assert.throws(operation, (error) => error?.code === expected, `expected error code ${expected}`);
}

export function bytes(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

export function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function checkStatus(report, name, expected) {
  const entry = report.checks.find((item) => item.name === name);
  assert.ok(entry, `missing ${name}`);
  assert.equal(entry.status, expected, `${name}: ${entry.detail}`);
}
