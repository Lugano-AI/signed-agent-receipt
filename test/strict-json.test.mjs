import { canonical } from "../src/canonical.mjs";
import { parseDecimal } from "../src/encoding.mjs";
import { LIMITS } from "../src/limits.mjs";
import { parseStrictJson } from "../src/strict-json.mjs";
import { assert, expectCode } from "./assertions.mjs";

const utf8 = (value) => Buffer.from(value, "utf8");

export function runStrictJsonTests() {
  const unicode = parseStrictJson(utf8(
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
  ));
  // RFC 8785 §3.2.3 ordering uses unsigned UTF-16 code units; this fixed
  // expected string also exercises control-character escaping.
  assert.equal(
    canonical(unicode),
    '{"\\r":"Carriage Return","1":"One","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
  );

  expectCode(() => parseStrictJson(utf8('{"x":null,"\\u0078":null}')), "duplicate-json-key");
  expectCode(() => parseStrictJson(utf8('{"outer":{"x":null,"\\u0078":null}}')), "duplicate-json-key");
  const prototypeObject = parseStrictJson(utf8('{"__proto__":true,"constructor":false}'));
  assert.equal(Object.getPrototypeOf(prototypeObject), null);
  assert.equal(prototypeObject.__proto__, true);

  for (const value of ["1", "1.00000000000000001", "1e-1000", "1e+30", "-0", "9007199254740993", "0.5"]) {
    expectCode(() => parseStrictJson(utf8(`{"n":${value}}`)), "json-number-not-allowed");
  }
  expectCode(() => canonical({ n: 1 }), "json-number-not-allowed");
  expectCode(() => canonical("\ud800"), "lone-surrogate");

  expectCode(() => parseStrictJson(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), "json-bom-not-allowed");
  expectCode(() => parseStrictJson(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d])), "invalid-utf8");
  expectCode(() => parseStrictJson(utf8('{"x":"\\uD800"}')), "lone-surrogate");
  expectCode(() => parseStrictJson(utf8('{"x":"\\uDC00"}')), "lone-surrogate");
  expectCode(() => parseStrictJson(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0x01, 0x22, 0x7d])), "unescaped-json-control");
  expectCode(() => parseStrictJson(utf8('{}{}')), "trailing-json-data");

  const array32 = `${"[".repeat(32)}${"]".repeat(32)}`;
  const array33 = `${"[".repeat(33)}${"]".repeat(33)}`;
  assert.doesNotThrow(() => parseStrictJson(utf8(array32)));
  expectCode(() => parseStrictJson(utf8(array33)), "json-depth-limit");
  const object32 = `${'{"x":'.repeat(31)}{}${"}".repeat(31)}`;
  const object33 = `${'{"x":'.repeat(32)}{}${"}".repeat(32)}`;
  assert.doesNotThrow(() => parseStrictJson(utf8(object32)));
  expectCode(() => parseStrictJson(utf8(object33)), "json-depth-limit");

  assert.doesNotThrow(() => parseStrictJson(utf8(`[${Array(64).fill("null").join(",")}]`)));
  expectCode(() => parseStrictJson(utf8(`[${Array(65).fill("null").join(",")}]`)), "json-array-item-limit");
  const members = (count) => `{${Array.from({ length: count }, (_, index) => `"k${index}":null`).join(",")}}`;
  assert.doesNotThrow(() => parseStrictJson(utf8(members(32))));
  expectCode(() => parseStrictJson(utf8(members(33))), "json-object-member-limit");
  const childArray = (count) => `[${Array(count).fill("null").join(",")}]`;
  const exactly1024Nodes = `[${[...Array(63).fill(childArray(15)), childArray(14)].join(",")}]`;
  const nodes1025 = `[${Array(64).fill(childArray(15)).join(",")}]`;
  assert.doesNotThrow(() => parseStrictJson(utf8(exactly1024Nodes)));
  expectCode(() => parseStrictJson(utf8(nodes1025)), "json-node-limit");
  assert.doesNotThrow(() => parseStrictJson(utf8(`"${"a".repeat(LIMITS.maxStringCodeUnits)}"`)));
  expectCode(() => parseStrictJson(utf8(`"${"a".repeat(LIMITS.maxStringCodeUnits + 1)}"`)), "json-string-limit");
  expectCode(() => parseStrictJson(Buffer.alloc(LIMITS.maxInputBytes + 1, 0x20)), "json-input-byte-limit");
  assert.equal(parseDecimal("2147483647"), 2147483647);
  expectCode(() => parseDecimal("2147483648"), "invalid-decimal");
}
