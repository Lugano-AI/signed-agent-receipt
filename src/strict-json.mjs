import { TextDecoder } from "node:util";
import { fail } from "./errors.mjs";
import { LIMITS } from "./limits.mjs";

const WHITESPACE = new Set([" ", "\n", "\r", "\t"]);
const HEX = /^[0-9a-fA-F]{4}$/;

function isHighSurrogate(code) {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code) {
  return code >= 0xdc00 && code <= 0xdfff;
}

/** Rejects lone UTF-16 surrogates in a JavaScript string. */
export function assertUnicodeScalars(value) {
  if (typeof value !== "string") fail("expected-string");
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (isHighSurrogate(code)) {
      if (index + 1 >= value.length || !isLowSurrogate(value.charCodeAt(index + 1))) {
        fail("lone-surrogate");
      }
      index += 1;
    } else if (isLowSurrogate(code)) {
      fail("lone-surrogate");
    }
  }
}

class Parser {
  constructor(text, limits) {
    this.text = text;
    this.limits = limits;
    this.index = 0;
    this.nodes = 0;
  }

  skipWhitespace() {
    while (this.index < this.text.length && WHITESPACE.has(this.text[this.index])) this.index += 1;
  }

  addNode() {
    this.nodes += 1;
    if (this.nodes > this.limits.maxNodes) fail("json-node-limit");
  }

  parse() {
    this.skipWhitespace();
    if (this.index >= this.text.length) fail("empty-json");
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) fail("trailing-json-data");
    return value;
  }

  parseValue(depth) {
    if (depth > this.limits.maxDepth) fail("json-depth-limit");
    const current = this.text[this.index];
    if (current === "{") return this.parseObject(depth + 1);
    if (current === "[") return this.parseArray(depth + 1);
    if (current === '"') {
      this.addNode();
      return this.parseString();
    }
    if (this.text.startsWith("true", this.index)) {
      this.addNode();
      this.index += 4;
      return true;
    }
    if (this.text.startsWith("false", this.index)) {
      this.addNode();
      this.index += 5;
      return false;
    }
    if (this.text.startsWith("null", this.index)) {
      this.addNode();
      this.index += 4;
      return null;
    }
    // SAR-RI carries all quantities as canonical decimal strings.  Rejecting
    // the token before Number() prevents overflow, -0, exponent, and precision
    // differences from becoming signed values.
    if (current === "-" || (current >= "0" && current <= "9")) fail("json-number-not-allowed");
    fail("invalid-json-token");
  }

  parseObject(depth) {
    if (depth > this.limits.maxDepth) fail("json-depth-limit");
    this.addNode();
    this.index += 1; // {
    this.skipWhitespace();
    const output = Object.create(null);
    const seen = new Set();
    let members = 0;
    if (this.text[this.index] === "}") {
      this.index += 1;
      return output;
    }
    while (true) {
      if (this.text[this.index] !== '"') fail("object-key-not-string");
      const key = this.parseString();
      if (seen.has(key)) fail("duplicate-json-key");
      seen.add(key);
      members += 1;
      if (members > this.limits.maxObjectMembers) fail("json-object-member-limit");
      this.skipWhitespace();
      if (this.text[this.index] !== ":") fail("object-missing-colon");
      this.index += 1;
      this.skipWhitespace();
      output[key] = this.parseValue(depth);
      this.skipWhitespace();
      if (this.text[this.index] === "}") {
        this.index += 1;
        return output;
      }
      if (this.text[this.index] !== ",") fail("object-missing-comma");
      this.index += 1;
      this.skipWhitespace();
    }
  }

  parseArray(depth) {
    if (depth > this.limits.maxDepth) fail("json-depth-limit");
    this.addNode();
    this.index += 1; // [
    this.skipWhitespace();
    const output = [];
    if (this.text[this.index] === "]") {
      this.index += 1;
      return output;
    }
    while (true) {
      output.push(this.parseValue(depth));
      if (output.length > this.limits.maxArrayItems) fail("json-array-item-limit");
      this.skipWhitespace();
      if (this.text[this.index] === "]") {
        this.index += 1;
        return output;
      }
      if (this.text[this.index] !== ",") fail("array-missing-comma");
      this.index += 1;
      this.skipWhitespace();
    }
  }

  parseString() {
    if (this.text[this.index] !== '"') fail("expected-string");
    this.index += 1;
    let output = "";
    while (this.index < this.text.length) {
      const current = this.text[this.index];
      if (current === '"') {
        this.index += 1;
        if (output.length > this.limits.maxStringCodeUnits) fail("json-string-limit");
        return output;
      }
      const code = current.charCodeAt(0);
      if (code <= 0x1f) fail("unescaped-json-control");
      if (current === "\\") {
        this.index += 1;
        const escaped = this.text[this.index];
        if (escaped === '"' || escaped === "\\" || escaped === "/") {
          output += escaped;
          this.index += 1;
          continue;
        }
        if (escaped === "b") {
          output += "\b";
          this.index += 1;
          continue;
        }
        if (escaped === "f") {
          output += "\f";
          this.index += 1;
          continue;
        }
        if (escaped === "n") {
          output += "\n";
          this.index += 1;
          continue;
        }
        if (escaped === "r") {
          output += "\r";
          this.index += 1;
          continue;
        }
        if (escaped === "t") {
          output += "\t";
          this.index += 1;
          continue;
        }
        if (escaped !== "u") fail("invalid-json-escape");
        const first = this.text.slice(this.index + 1, this.index + 5);
        if (!HEX.test(first)) fail("invalid-json-unicode-escape");
        const firstCode = Number.parseInt(first, 16);
        this.index += 5;
        if (isHighSurrogate(firstCode)) {
          if (this.text[this.index] !== "\\" || this.text[this.index + 1] !== "u") fail("lone-surrogate");
          const second = this.text.slice(this.index + 2, this.index + 6);
          if (!HEX.test(second)) fail("invalid-json-unicode-escape");
          const secondCode = Number.parseInt(second, 16);
          if (!isLowSurrogate(secondCode)) fail("lone-surrogate");
          output += String.fromCharCode(firstCode, secondCode);
          this.index += 6;
          continue;
        }
        if (isLowSurrogate(firstCode)) fail("lone-surrogate");
        output += String.fromCharCode(firstCode);
        continue;
      }
      if (isHighSurrogate(code)) {
        const following = this.text.charCodeAt(this.index + 1);
        if (!isLowSurrogate(following)) fail("lone-surrogate");
        output += current + this.text[this.index + 1];
        this.index += 2;
        continue;
      }
      if (isLowSurrogate(code)) fail("lone-surrogate");
      output += current;
      this.index += 1;
    }
    fail("unterminated-json-string");
  }
}

/**
 * Parse one bounded UTF-8 JSON text without JSON.parse().  In particular,
 * duplicate decoded member names fail before any ordinary-object semantics.
 */
export function parseStrictJson(bytes, overrides = {}) {
  const limits = { ...LIMITS, ...overrides };
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) fail("json-input-not-bytes");
  const source = Buffer.from(bytes);
  if (source.length > limits.maxInputBytes) fail("json-input-byte-limit");
  if (source.length === 0) fail("empty-json");
  // RFC 8259 permits parsers to ignore a BOM, but this profile rejects it so
  // the exact admitted byte domain is not implementation-dependent.
  if (source.length >= 3 && source[0] === 0xef && source[1] === 0xbb && source[2] === 0xbf) {
    fail("json-bom-not-allowed");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(source);
  } catch {
    fail("invalid-utf8");
  }
  assertUnicodeScalars(text);
  return new Parser(text, limits).parse();
}
