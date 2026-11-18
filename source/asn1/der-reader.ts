export type DerTagClass = 0 | 1 | 2 | 3;

export type DerErrorCode =
  | "input-too-large"
  | "invalid-tag"
  | "invalid-length"
  | "indefinite-length"
  | "unexpected-end"
  | "container-overrun"
  | "trailing-data"
  | "limit-exceeded";

export interface ByteRange {
  readonly offset: number;
  readonly length: number;
}

export interface DerLimits {
  readonly maxDepth?: number;
  readonly maxElements?: number;
  readonly maxInputBytes?: number;
  readonly maxWorkBytes?: number;
}

export interface DerElement {
  readonly tagClass: DerTagClass;
  readonly tagNumber: number;
  readonly constructed: boolean;
  readonly start: number;
  readonly headerLength: number;
  readonly valueStart: number;
  readonly end: number;
  readonly value: Uint8Array;
  readonly context: DerReaderContext;
}

interface ReaderState {
  elements: number;
  workBytes: number;
}

export interface DerReaderContext {
  readonly input: Uint8Array;
  readonly limits: Required<DerLimits>;
  readonly depth: number;
  readonly state: ReaderState;
}

export const DEFAULT_DER_LIMITS = Object.freeze({
  maxDepth: 24,
  maxElements: 4096,
  maxInputBytes: 1024 * 1024,
  maxWorkBytes: 4 * 1024 * 1024,
});

const makeRange = (offset: number, length: number): ByteRange => Object.freeze({ offset, length });

export class DerParseError extends Error {
  readonly code: DerErrorCode;
  readonly offset: number;

  constructor(code: DerErrorCode, message: string, offset: number) {
    super(`${message} at offset ${offset}`);
    this.name = "DerParseError";
    this.code = code;
    this.offset = offset;
  }
}

export class DerReader {
  readonly input: Uint8Array;
  readonly start: number;
  readonly end: number;
  readonly depth: number;
  readonly limits: Required<DerLimits>;

  private position: number;
  private readonly state: ReaderState;

  constructor(
    input: Uint8Array,
    options: DerLimits = {},
    start = 0,
    end = input.byteLength,
    depth = 0,
    state: ReaderState = { elements: 0, workBytes: 0 },
  ) {
    if (!(input instanceof Uint8Array)) {
      throw new TypeError("DER input must be a Uint8Array");
    }

    const limits = {
      ...DEFAULT_DER_LIMITS,
      ...options,
    };

    if (input.byteLength > limits.maxInputBytes) {
      throw new DerParseError("input-too-large", "DER input exceeds the configured limit", 0);
    }
    if (start < 0 || end < start || end > input.byteLength) {
      throw new RangeError("DER reader bounds are invalid");
    }
    if (depth > limits.maxDepth) {
      throw new DerParseError(
        "limit-exceeded",
        "DER nesting depth exceeds the configured limit",
        start,
      );
    }

    this.input = input;
    this.start = start;
    this.end = end;
    this.depth = depth;
    this.limits = limits;
    this.position = start;
    this.state = state;
  }

  get remaining(): number {
    return this.end - this.position;
  }

  readElement(): DerElement {
    const start = this.position;
    if (start >= this.end) {
      throw new DerParseError("unexpected-end", "Expected another DER element", start);
    }

    this.incrementWork(start);

    const tag = this.readTag(start);
    const length = this.readLength(this.position);
    const valueStart = this.position;
    const end = valueStart + length;

    if (end > this.end) {
      throw new DerParseError(
        "container-overrun",
        "DER element exceeds its parent container",
        valueStart,
      );
    }

    this.state.workBytes += end - start;
    if (this.state.workBytes > this.limits.maxWorkBytes) {
      throw new DerParseError("limit-exceeded", "DER work exceeds the configured limit", start);
    }

    this.position = end;
    return Object.freeze({
      ...tag,
      start,
      headerLength: valueStart - start,
      valueStart,
      end,
      value: this.input.subarray(valueStart, end),
      context: Object.freeze({
        input: this.input,
        limits: this.limits,
        depth: this.depth,
        state: this.state,
      }),
    });
  }

  readOptionalElement(): DerElement | undefined {
    return this.position < this.end ? this.readElement() : undefined;
  }

  readChildren(element: DerElement, callback: (reader: DerReader) => void): void {
    if (!element.constructed) {
      throw new DerParseError("invalid-tag", "Constructed DER element expected", element.start);
    }

    const child = new DerReader(
      this.input,
      this.limits,
      element.valueStart,
      element.end,
      this.depth + 1,
      this.state,
    );
    callback(child);
    child.assertEnd();
  }

  assertEnd(): void {
    if (this.position !== this.end) {
      throw new DerParseError(
        "trailing-data",
        "Unexpected bytes after DER elements",
        this.position,
      );
    }
  }

  range(element: DerElement): ByteRange {
    return makeRange(element.start, element.end - element.start);
  }

  valueRange(element: DerElement): ByteRange {
    return makeRange(element.valueStart, element.end - element.valueStart);
  }

  private incrementWork(start: number): void {
    this.state.elements += 1;
    this.state.workBytes += 1;
    if (this.state.elements > this.limits.maxElements) {
      throw new DerParseError(
        "limit-exceeded",
        "DER element count exceeds the configured limit",
        start,
      );
    }
    if (this.state.workBytes > this.limits.maxWorkBytes) {
      throw new DerParseError("limit-exceeded", "DER work exceeds the configured limit", start);
    }
  }

  private readTag(start: number): Pick<DerElement, "tagClass" | "tagNumber" | "constructed"> {
    const first = this.readByte("invalid-tag", "Missing DER tag");
    const tagClass = ((first >>> 6) & 0x03) as DerTagClass;
    const constructed = (first & 0x20) !== 0;
    let tagNumber = first & 0x1f;

    if (tagNumber === 0x1f) {
      tagNumber = 0;
      let count = 0;
      let firstHighByte = true;
      let byte: number;
      do {
        byte = this.readByte("invalid-tag", "Truncated high-tag-number form");
        count += 1;
        if (firstHighByte && byte === 0x80) {
          throw new DerParseError(
            "invalid-tag",
            "Non-canonical high-tag-number form",
            this.position - 1,
          );
        }
        firstHighByte = false;
        tagNumber = tagNumber * 128 + (byte & 0x7f);
        if (tagNumber > 0x1fffff || count > 4) {
          throw new DerParseError("limit-exceeded", "DER tag number is too large", start);
        }
      } while ((byte & 0x80) !== 0);

      if (tagNumber < 31) {
        throw new DerParseError("invalid-tag", "Non-canonical high-tag-number form", start);
      }
    }

    return { tagClass, tagNumber, constructed };
  }

  private readLength(offset: number): number {
    const first = this.readByte("invalid-length", "Missing DER length");
    if (first === 0x80) {
      throw new DerParseError("indefinite-length", "Indefinite DER length is not allowed", offset);
    }
    if ((first & 0x80) === 0) {
      return first;
    }

    const byteCount = first & 0x7f;
    if (byteCount === 0 || byteCount > 4) {
      throw new DerParseError("invalid-length", "DER length uses too many bytes", offset);
    }

    const firstLengthByte = this.readByte("invalid-length", "Truncated DER length");
    if (firstLengthByte === 0) {
      throw new DerParseError("invalid-length", "Non-canonical DER length", this.position - 1);
    }

    let length = firstLengthByte;
    for (let index = 1; index < byteCount; index += 1) {
      length = length * 256 + this.readByte("invalid-length", "Truncated DER length");
    }
    if (length < 128) {
      throw new DerParseError("invalid-length", "Non-canonical DER length", offset);
    }
    return length;
  }

  private readByte(code: DerErrorCode, message: string): number {
    if (this.position >= this.end) {
      throw new DerParseError(
        code === "invalid-tag" ? "unexpected-end" : code,
        message,
        this.position,
      );
    }
    const value = this.input[this.position];
    this.position += 1;
    return value ?? 0;
  }
}

export const derRange = (offset: number, length: number): ByteRange => makeRange(offset, length);
