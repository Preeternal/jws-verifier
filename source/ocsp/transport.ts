export interface OcspFetchOptions {
  readonly maxResponseBytes: number;
}

const contentType = "application/ocsp-response";

const cancelBody = (body: ReadableStream | ReadableStreamDefaultReader | null): void => {
  // Cancellation is best-effort. Preserve the validation error even if cleanup fails.
  void body?.cancel().catch(() => {});
};

const readBody = async (response: Response, maxBytes: number): Promise<Uint8Array> => {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > maxBytes) {
      cancelBody(response.body);
      throw new Error("OCSP response exceeds the configured body limit");
    }
  }

  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.byteLength;
      if (total > maxBytes) {
        cancelBody(reader);
        throw new Error("OCSP response exceeds the configured body limit");
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
};

/** Default standards-only OCSP POST transport for Node and Workers. */
export const fetchOcspResponse = async (
  url: string,
  body: Uint8Array,
  signal: AbortSignal,
  options: OcspFetchOptions,
): Promise<Uint8Array> => {
  const fetchFunction = globalThis.fetch;
  if (typeof fetchFunction !== "function") throw new Error("The host does not provide fetch");
  const response = await fetchFunction(url, {
    method: "POST",
    body: body as unknown as BodyInit,
    signal,
    redirect: "error",
    headers: {
      accept: contentType,
      "content-type": "application/ocsp-request",
    },
  });
  if (!response.ok) {
    cancelBody(response.body);
    throw new Error(`OCSP responder returned HTTP ${response.status}`);
  }
  const responseContentType = response.headers.get("content-type");
  if (responseContentType !== null && !responseContentType.toLowerCase().startsWith(contentType)) {
    cancelBody(response.body);
    throw new Error("OCSP responder returned an unexpected content type");
  }
  return readBody(response, options.maxResponseBytes);
};
