import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";

const tlv = (tag: number, ...values: Buffer[]): Buffer => {
  const value = Buffer.concat(values);
  const length = value.length;
  const encodedLength =
    length < 128 ? [length] : length < 256 ? [0x81, length] : [0x82, length >> 8, length & 255];
  return Buffer.concat([Buffer.from([tag, ...encodedLength]), value]);
};

const sequence = (...values: Buffer[]): Buffer => tlv(0x30, ...values);
const oid = (hex: string): Buffer => tlv(0x06, Buffer.from(hex, "hex"));
const integer = (n: number): Buffer => tlv(0x02, Buffer.from([n]));
const derTrue = tlv(0x01, Buffer.from([255]));
const bitString = (value: Buffer, unusedBits = 0): Buffer =>
  tlv(0x03, Buffer.from([unusedBits]), value);
const name = (cn: string): Buffer =>
  sequence(tlv(0x31, sequence(oid("550403"), tlv(0x0c, Buffer.from(cn)))));
const extension = (id: string, value: Buffer, critical: boolean): Buffer =>
  sequence(oid(id), ...(critical ? [derTrue] : []), tlv(0x04, value));
const signingAlgorithm = sequence(oid("2a8648ce3d040302"));
const publicKeyPair = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });

const rootName = name("Fixture Root");
const intermediateName = name("Fixture Intermediate");
const leafName = name("Fixture Signer");
const utcTime = (value: string): Buffer => tlv(0x17, Buffer.from(value));

interface CertificateFields {
  readonly serial: number;
  readonly issuer: Buffer;
  readonly subject: Buffer;
  readonly issuerKey: KeyObject;
  readonly subjectKey: KeyObject;
  readonly ca: boolean;
  readonly expires?: string;
  readonly extraExtensions?: readonly Buffer[];
}

const certificate = (fields: CertificateFields): Buffer => {
  const tbs = sequence(
    tlv(0xa0, integer(2)),
    integer(fields.serial),
    signingAlgorithm,
    fields.issuer,
    sequence(utcTime("200101000000Z"), utcTime(fields.expires ?? "400101000000Z")),
    fields.subject,
    fields.subjectKey.export({ type: "spki", format: "der" }),
    tlv(
      0xa3,
      sequence(
        extension("551d13", fields.ca ? sequence(derTrue) : sequence(), true),
        extension(
          "551d0f",
          bitString(Buffer.from([fields.ca ? 0x04 : 0x80]), fields.ca ? 2 : 7),
          true,
        ),
        ...(fields.extraExtensions ?? []),
      ),
    ),
  );
  return sequence(tbs, signingAlgorithm, bitString(sign("sha256", tbs, fields.issuerKey)));
};

export const signedFixtureTime = Date.UTC(2025, 0, 1);
export const fixtureMarkerOid = "1.2.3.4";
export const signedOcspEndpoints = [
  "https://leaf.ocsp.example.test/",
  "https://intermediate.ocsp.example.test/",
] as const;

const aia = (url: string): Buffer =>
  extension(
    "2b06010505070101",
    sequence(sequence(oid("2b06010505073001"), tlv(0x86, Buffer.from(url)))),
    false,
  );

const keyHash = (algorithm: "sha1" | "sha256", key: KeyObject): Buffer => {
  const spki = key.export({ type: "spki", format: "der" });
  // The synthetic P-256 keys end with the 65-byte uncompressed point.
  return createHash(algorithm).update(spki.subarray(-65)).digest();
};

const responseTime = (value: string) => tlv(0x18, Buffer.from(value));

/** Generates independent synthetic keys in memory with fixed certificate dates. */
export const makeSignedFixture = (criticalExtension?: "leaf" | "intermediate") => {
  const root = publicKeyPair();
  const rotated = publicKeyPair();
  const issuer = publicKeyPair();
  const signer = publicKeyPair();
  const rootCertificate = (serial: number, key: typeof root, expires?: string) =>
    certificate({
      serial,
      issuer: rootName,
      subject: rootName,
      issuerKey: key.privateKey,
      subjectKey: key.publicKey,
      ca: true,
      expires,
    });
  const rootDer = rootCertificate(1, root);
  const rotatedRootDer = rootCertificate(2, rotated);
  const expiredRootDer = rootCertificate(3, root, "210101000000Z");
  const shortLivedRootDer = rootCertificate(8, root, "250101000001Z");
  const intermediate = certificate({
    serial: 4,
    issuer: rootName,
    subject: intermediateName,
    issuerKey: root.privateKey,
    subjectKey: issuer.publicKey,
    ca: true,
    extraExtensions: [
      aia(signedOcspEndpoints[1]),
      ...(criticalExtension === "intermediate"
        ? [extension("551d25", sequence(oid("2b06010505070309")), true)]
        : []),
    ],
  });
  const leaf = certificate({
    serial: 5,
    issuer: intermediateName,
    subject: leafName,
    issuerKey: issuer.privateKey,
    subjectKey: signer.publicKey,
    ca: false,
    extraExtensions: [
      aia(signedOcspEndpoints[0]),
      extension("2a0304", sequence(), criticalExtension === "leaf"),
    ],
  });
  const signJws = (
    payload: unknown,
    header: Readonly<Record<string, unknown>> = {},
    presentedRoot?: Uint8Array,
  ): string => {
    const x5c = [leaf, intermediate].map((der) => der.toString("base64"));
    if (presentedRoot !== undefined) x5c.push(Buffer.from(presentedRoot).toString("base64"));
    const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const input = `${segment({ alg: "ES256", x5c, ...header })}.${segment(payload)}`;
    const signature = sign("sha256", Buffer.from(input), {
      key: signer.privateKey,
      dsaEncoding: "ieee-p1363",
    });
    return `${input}.${signature.toString("base64url")}`;
  };
  const ocspResponse = (
    url: string,
    scenario: "byKey" | "issuer-name" | "delegate-name" | "unauthorized",
    nextUpdate = "20250102000000Z",
  ): Buffer => {
    const forLeaf = url === signedOcspEndpoints[0];
    if (!forLeaf && url !== signedOcspEndpoints[1]) throw new Error("Unexpected replay URL");
    const ca = forLeaf ? issuer : root;
    const caName = forLeaf ? intermediateName : rootName;
    const responderName = scenario === "issuer-name" ? caName : name("Fixture OCSP Delegate");
    const signingDelegate = forLeaf && scenario !== "byKey";
    const responseSigner = signingDelegate ? publicKeyPair() : ca;
    const delegatedCertificate = (key: KeyObject, serial: number, authorized: boolean) =>
      certificate({
        serial,
        issuer: caName,
        subject: responderName,
        issuerKey: ca.privateKey,
        subjectKey: key,
        ca: false,
        extraExtensions: authorized
          ? [extension("551d25", sequence(oid("2b06010505070309")), true)]
          : [],
      });
    const embedded = signingDelegate
      ? [
          delegatedCertificate(publicKeyPair().publicKey, 6, scenario !== "unauthorized"),
          delegatedCertificate(responseSigner.publicKey, 7, scenario !== "unauthorized"),
        ]
      : [];
    const responder =
      scenario === "byKey"
        ? tlv(0xa2, tlv(0x04, keyHash("sha1", responseSigner.publicKey)))
        : tlv(0xa1, signingDelegate ? responderName : caName);
    const certId = sequence(
      sequence(oid("608648016503040201"), tlv(0x05)),
      tlv(0x04, createHash("sha256").update(caName).digest()),
      tlv(0x04, keyHash("sha256", ca.publicKey)),
      integer(forLeaf ? 5 : 4),
    );
    const thisUpdate = responseTime("20241231235900Z");
    const data = sequence(
      responder,
      thisUpdate,
      sequence(sequence(certId, tlv(0x80), thisUpdate, tlv(0xa0, responseTime(nextUpdate)))),
    );
    const basic = sequence(
      data,
      signingAlgorithm,
      bitString(sign("sha256", data, responseSigner.privateKey)),
      ...(embedded.length ? [tlv(0xa0, sequence(...embedded))] : []),
    );
    return sequence(
      tlv(0x0a, Buffer.from([0])),
      tlv(0xa0, sequence(oid("2b0601050507300101"), tlv(0x04, basic))),
    );
  };
  return { rootDer, rotatedRootDer, expiredRootDer, shortLivedRootDer, signJws, ocspResponse };
};
