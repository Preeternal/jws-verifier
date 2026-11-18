import { Buffer } from "node:buffer";

// This matcher only accepts the unsigned, single-CertID requests in the replay suite.
const cursor = (bytes) => {
  let offset = 0;
  return {
    take(tag) {
      if (bytes[offset++] !== tag || offset >= bytes.length)
        throw new Error("Invalid OCSP request");
      let length = bytes[offset++];
      if (length >= 128) {
        const width = length & 127;
        if (width === 0 || width > 2 || offset + width > bytes.length || bytes[offset] === 0) {
          throw new Error("Invalid OCSP request length");
        }
        length = 0;
        for (let index = 0; index < width; index += 1) length = length * 256 + bytes[offset++];
        if (length < 128) throw new Error("Non-canonical OCSP request length");
      }
      if (length > bytes.length - offset) throw new Error("Truncated OCSP request");
      const value = bytes.subarray(offset, offset + length);
      offset += length;
      return value;
    },
    done: () => offset === bytes.length,
    end() {
      if (offset !== bytes.length) throw new Error("Unexpected OCSP request fields");
    },
  };
};

const singleSequence = (input) => {
  const fields = cursor(input);
  const contents = fields.take(0x30);
  fields.end();
  return contents;
};

export const ocspRequestKey = (bytes) => {
  const tbs = singleSequence(singleSequence(bytes));
  const request = singleSequence(singleSequence(tbs));
  const certId = cursor(singleSequence(request));
  const algorithm = cursor(certId.take(0x30));
  const oid = algorithm.take(0x06);
  if (!algorithm.done() && algorithm.take(0x05).length !== 0) {
    throw new Error("Invalid OCSP hash algorithm parameters");
  }
  algorithm.end();
  const fields = [oid, certId.take(0x04), certId.take(0x04), certId.take(0x02)];
  certId.end();
  return fields.map((field) => Buffer.from(field).toString("hex")).join(":");
};
