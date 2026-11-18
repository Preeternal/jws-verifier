const scalarBytes = 32;

const writeDerInteger = (output: Uint8Array, offset: number, scalar: Uint8Array): number => {
  let start = 0;
  while (start < scalarBytes - 1 && scalar[start] === 0) start += 1;
  const padding = (scalar[start] ?? 0) >= 0x80 ? 1 : 0;
  const length = scalarBytes - start + padding;
  output[offset] = 0x02;
  output[offset + 1] = length;
  output.set(scalar.subarray(start), offset + 2 + padding);
  return offset + 2 + length;
};

/** Encode the two unsigned 32-byte scalars of a length-checked ES256 signature. */
export const es256SignatureToDer = (signature: Uint8Array): Uint8Array => {
  // Each DER INTEGER may need one sign byte, in addition to its tag and length.
  const output = new Uint8Array(72);
  const offset = writeDerInteger(output, 2, signature.subarray(0, scalarBytes));
  const end = writeDerInteger(output, offset, signature.subarray(scalarBytes));
  output[0] = 0x30;
  output[1] = end - 2;
  return output.subarray(0, end);
};
