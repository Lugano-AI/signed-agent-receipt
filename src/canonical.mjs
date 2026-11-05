import { fail } from "./errors.mjs";
import { assertUnicodeScalars } from "./strict-json.mjs";

function compareUtf16(left, right) {
  const shortest = Math.min(left.length, right.length);
  for (let index = 0; index < shortest; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function quote(value) {
  assertUnicodeScalars(value);
  // JSON.stringify's string escaping is the restricted JCS-compatible subset
  // used here. Number serialization is deliberately not in this profile.
  return JSON.stringify(value);
}

/**
 * Restricted JCS-compatible serialization for parser-produced values: objects,
 * arrays, strings, null, and booleans only. JSON number values are forbidden.
 */
export function canonical(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return quote(value);
  if (typeof value === "number") fail("json-number-not-allowed");
  if (typeof value !== "object") fail("unsupported-canonical-type");
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const keys = Object.keys(value).sort(compareUtf16);
  return `{${keys.map((key) => `${quote(key)}:${canonical(value[key])}`).join(",")}}`;
}

export function canonicalBytes(value) {
  return Buffer.from(canonical(value), "utf8");
}

export { compareUtf16 };
