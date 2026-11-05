/** A deliberately small, safe error surface for untrusted artifact input. */
export class SarError extends Error {
  constructor(code) {
    super(code);
    this.name = "SarError";
    this.code = code;
  }
}

export const fail = (code) => {
  throw new SarError(code);
};

export const isSarError = (value) => value instanceof SarError;

// Do not expose exception text from parsers or crypto implementations to the CLI.
export const safeCode = (value, fallback = "invalid-input") =>
  isSarError(value) ? value.code : fallback;
