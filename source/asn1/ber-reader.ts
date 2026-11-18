export type BerTagClass = 0 | 1 | 2 | 3;

export type BerErrorCode =
  | "invalid-tag"
  | "invalid-length"
  | "indefinite-primitive"
  | "unexpected-end"
  | "container-overrun"
  | "trailing-data"
  | "limit-exceeded";

export interface BerLimits {
  readonly maxDepth?: number;
  readonly maxElements?: number;
  readonly maxInputBytes?: number;
  readonly maxWorkBytes?: number;
}

interface BerState {
  elements: number;
  workBytes: number;
}

export const DEFAULT_BER_LIMITS = Object.freeze({
  maxDepth: 32,
  maxElements: 8192,
  maxInputBytes: 4 * 1024 * 1024,
  maxWorkBytes: 16 * 1024 * 1024,
});

export class BerParseError extends Error {
  readonly code: BerErrorCode;
  readonly offset: number;

  constructor(code: BerErrorCode, message: string, offset: number) {
    super(`${message} at offset ${offset}`);
    this.name = "BerParseError";
    this.code = code;
    this.offset = offset;
  }
}

export interface BerElement {
  readonly tagClass: BerTagClass;
  readonly tagNumber: number;
  readonly constructed: boolean;
  readonly indefiniteLength: boolean;
  readonly start: number;
  readonly headerLength: number;
  readonly valueStart: number;
  /** End of the content, excluding the EOC marker for indefinite elements. */
  readonly contentEnd: number;
  /** End of the complete TLV, including the EOC marker when present. */
  readonly end: number;
  readonly value: Uint8Array;
  readonly limits: Required<BerLimits>;
}

const readHighTagNumber = (
  input: Uint8Array,
  position: { value: number },
  end: number,
  start: number,
): number => {
  let tagNumber = 0;
  let count = 0;
  let firstByte = true;
  let byte = 0;
  do {
    if (position.value >= end) {
      throw new BerParseError(
        "unexpected-end",
        "Truncated BER high-tag-number form",
        position.value,
      );
    }
    byte = input[position.value] ?? 0;
    position.value += 1;
    count += 1;
    if (firstByte && byte === 0x80) {
      throw new BerParseError(
        "invalid-tag",
        "Non-canonical BER high-tag-number form",
        position.value - 1,
      );
    }
    firstByte = false;
    tagNumber = tagNumber * 128 + (byte & 0x7f);
    if (tagNumber > 0x1fffff || count > 4) {
      throw new BerParseError("limit-exceeded", "BER tag number is too large", start);
    }
  } while ((byte & 0x80) !== 0);
  if (tagNumber < 31) {
    throw new BerParseError("invalid-tag", "Non-canonical BER high-tag-number form", start);
  }
  return tagNumber;
};

const readTag = (
  input: Uint8Array,
  position: { value: number },
  end: number,
): Pick<BerElement, "tagClass" | "tagNumber" | "constructed"> => {
  if (position.value >= end) {
    throw new BerParseError("unexpected-end", "Missing BER tag", position.value);
  }
  const start = position.value;
  const first = input[position.value] ?? 0;
  position.value += 1;
  if (first === 0) {
    throw new BerParseError("invalid-tag", "Unexpected BER end-of-contents marker", start);
  }
  const tagNumber =
    (first & 0x1f) === 0x1f ? readHighTagNumber(input, position, end, start) : first & 0x1f;
  return {
    tagClass: ((first >>> 6) & 0x03) as BerTagClass,
    tagNumber,
    constructed: (first & 0x20) !== 0,
  };
};

const readLength = (
  input: Uint8Array,
  position: { value: number },
  end: number,
): { readonly length?: number; readonly indefinite: boolean } => {
  if (position.value >= end) {
    throw new BerParseError("unexpected-end", "Missing BER length", position.value);
  }
  const offset = position.value;
  const first = input[position.value] ?? 0;
  position.value += 1;
  if (first === 0x80) return { indefinite: true };
  if ((first & 0x80) === 0) return { indefinite: false, length: first };

  const byteCount = first & 0x7f;
  if (byteCount === 0 || byteCount > 4) {
    throw new BerParseError("invalid-length", "BER length uses too many bytes", offset);
  }
  if (position.value >= end) {
    throw new BerParseError("unexpected-end", "Truncated BER length", position.value);
  }
  const firstLengthByte = input[position.value] ?? 0;
  if (firstLengthByte === 0) {
    throw new BerParseError("invalid-length", "Non-canonical BER length", position.value);
  }
  let length = firstLengthByte;
  position.value += 1;
  for (let index = 1; index < byteCount; index += 1) {
    if (position.value >= end) {
      throw new BerParseError("unexpected-end", "Truncated BER length", position.value);
    }
    length = length * 256 + (input[position.value] ?? 0);
    position.value += 1;
  }
  return { indefinite: false, length };
};

export class BerCursor {
  readonly input: Uint8Array;
  readonly start: number;
  readonly end: number;
  readonly depth: number;
  readonly limits: Required<BerLimits>;

  private position: number;
  private readonly state: BerState;

  constructor(
    input: Uint8Array,
    options: BerLimits = {},
    start = 0,
    end = input.byteLength,
    depth = 0,
    state: BerState = { elements: 0, workBytes: 0 },
  ) {
    if (!(input instanceof Uint8Array)) {
      throw new TypeError("BER input must be a Uint8Array");
    }
    const limits = { ...DEFAULT_BER_LIMITS, ...options };
    if (input.byteLength > limits.maxInputBytes) {
      throw new BerParseError("limit-exceeded", "BER input exceeds the configured limit", 0);
    }
    if (start < 0 || end < start || end > input.byteLength) {
      throw new RangeError("BER cursor bounds are invalid");
    }
    if (depth > limits.maxDepth) {
      throw new BerParseError(
        "limit-exceeded",
        "BER nesting depth exceeds the configured limit",
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

  readElement(): BerElement {
    const element = this.parseElement(this.position, this.end, this.depth);
    this.position = element.end;
    return element;
  }

  readOptionalElement(): BerElement | undefined {
    return this.position < this.end ? this.readElement() : undefined;
  }

  assertEnd(): void {
    if (this.position !== this.end) {
      throw new BerParseError(
        "trailing-data",
        "Unexpected bytes after BER elements",
        this.position,
      );
    }
  }

  private parseIndefiniteContent(
    valueStart: number,
    boundary: number,
    depth: number,
  ): { readonly contentEnd: number; readonly end: number } {
    let childPosition = valueStart;
    for (;;) {
      if (childPosition + 2 > boundary) {
        throw new BerParseError(
          "unexpected-end",
          "Missing BER end-of-contents marker",
          childPosition,
        );
      }
      if (this.input[childPosition] === 0 && this.input[childPosition + 1] === 0) {
        return { contentEnd: childPosition, end: childPosition + 2 };
      }
      childPosition = this.parseElement(childPosition, boundary, depth + 1).end;
    }
  }

  private parseDefiniteContent(
    valueStart: number,
    length: number,
    boundary: number,
    constructed: boolean,
    depth: number,
  ): { readonly contentEnd: number; readonly end: number } {
    const contentEnd = valueStart + length;
    if (contentEnd > boundary) {
      throw new BerParseError(
        "container-overrun",
        "BER element exceeds its parent container",
        valueStart,
      );
    }
    if (constructed) {
      let childPosition = valueStart;
      while (childPosition < contentEnd) {
        childPosition = this.parseElement(childPosition, contentEnd, depth + 1).end;
      }
      if (childPosition !== contentEnd) {
        throw new BerParseError("trailing-data", "BER container has trailing bytes", childPosition);
      }
    }
    return { contentEnd, end: contentEnd };
  }

  private parseElement(start: number, boundary: number, depth: number): BerElement {
    if (depth > this.limits.maxDepth) {
      throw new BerParseError(
        "limit-exceeded",
        "BER nesting depth exceeds the configured limit",
        start,
      );
    }
    this.state.elements += 1;
    if (this.state.elements > this.limits.maxElements) {
      throw new BerParseError(
        "limit-exceeded",
        "BER element count exceeds the configured limit",
        start,
      );
    }

    const position = { value: start };
    const tag = readTag(this.input, position, boundary);
    const length = readLength(this.input, position, boundary);
    const valueStart = position.value;
    if (length.indefinite && !tag.constructed) {
      throw new BerParseError(
        "indefinite-primitive",
        "Indefinite BER length is only valid for constructed elements",
        start,
      );
    }

    const content = length.indefinite
      ? this.parseIndefiniteContent(valueStart, boundary, depth)
      : this.parseDefiniteContent(valueStart, length.length ?? 0, boundary, tag.constructed, depth);
    const { contentEnd, end } = content;

    this.state.workBytes += end - start;
    if (this.state.workBytes > this.limits.maxWorkBytes) {
      throw new BerParseError("limit-exceeded", "BER work exceeds the configured limit", start);
    }
    return Object.freeze({
      ...tag,
      indefiniteLength: length.indefinite,
      start,
      headerLength: valueStart - start,
      valueStart,
      contentEnd,
      end,
      value: this.input.subarray(valueStart, contentEnd),
      limits: this.limits,
    });
  }
}
