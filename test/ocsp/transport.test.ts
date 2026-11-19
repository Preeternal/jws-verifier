import { once } from "node:events";
import { createServer, type ServerResponse } from "node:http";

import { afterEach, describe, expect, it, onTestFinished, vi } from "vitest";

import { createVerifier, fetchOcspResponse } from "../../source/index.js";
import { makeSignedFixture, signedFixtureTime } from "../fixtures/signed-jws.js";

describe("OCSP fetch transport", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts an OCSP request and bounds the streamed body", async () => {
    const fetch = vi.fn(
      async () =>
        new Response(Uint8Array.of(1, 2, 3), {
          status: 200,
          headers: { "content-type": "application/ocsp-response", "content-length": "3" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    await expect(
      fetchOcspResponse(
        "https://ocsp.example.test",
        Uint8Array.of(9),
        new AbortController().signal,
        { maxResponseBytes: 3 },
      ),
    ).resolves.toEqual(Uint8Array.of(1, 2, 3));
    expect(fetch).toHaveBeenCalledWith(
      "https://ocsp.example.test",
      expect.objectContaining({ method: "POST", redirect: "manual" }),
    );
  });

  it.each<[ResponseInit, string]>([
    [{ status: 302 }, "returned HTTP 302"],
    [{ status: 307 }, "returned HTTP 307"],
    [{ status: 500 }, "returned HTTP"],
    [{ status: 200, headers: { "content-type": "text/plain" } }, "content type"],
    [{ status: 200, headers: { "content-length": "4" } }, "body limit"],
    [{ status: 200 }, "body limit"],
  ])("cancels the body of an unsafe response (%s)", async (init, message) => {
    const cancel = vi.fn(() => Promise.reject(new Error("cleanup failed")));
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(Uint8Array.of(1, 2, 3, 4));
      },
      cancel,
    });
    const response = new Response(body, init);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response),
    );
    await expect(
      fetchOcspResponse(
        "https://ocsp.example.test",
        Uint8Array.of(9),
        new AbortController().signal,
        { maxResponseBytes: 3 },
      ),
    ).rejects.toThrow(message);
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("accepts an empty body and rejects an oversized streamed body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(null, {
            status: 200,
            headers: { "content-type": "application/ocsp-response" },
          }),
      ),
    );
    await expect(
      fetchOcspResponse(
        "https://ocsp.example.test",
        Uint8Array.of(9),
        new AbortController().signal,
        {
          maxResponseBytes: 3,
        },
      ),
    ).resolves.toEqual(new Uint8Array());
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(Uint8Array.of(1, 2, 3, 4), {
            status: 200,
            headers: { "content-type": "application/ocsp-response" },
          }),
      ),
    );
    await expect(
      fetchOcspResponse(
        "https://ocsp.example.test",
        Uint8Array.of(9),
        new AbortController().signal,
        {
          maxResponseBytes: 3,
        },
      ),
    ).rejects.toThrow("body limit");
  });

  it("allows a response without content type and reports a missing fetch host", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(Uint8Array.of(1), { status: 200 })),
    );
    await expect(
      fetchOcspResponse(
        "https://ocsp.example.test",
        Uint8Array.of(9),
        new AbortController().signal,
        {
          maxResponseBytes: 3,
        },
      ),
    ).resolves.toEqual(Uint8Array.of(1));
    vi.stubGlobal("fetch", undefined);
    await expect(
      fetchOcspResponse(
        "https://ocsp.example.test",
        Uint8Array.of(9),
        new AbortController().signal,
        {
          maxResponseBytes: 3,
        },
      ),
    ).rejects.toThrow("fetch");
  });
});

const startResponder = async (
  respondToLeaf: (response: ServerResponse) => void,
  timeoutMs = 5_000,
) => {
  const requests: { path: string | undefined; method: string | undefined }[] = [];
  let intermediateResponse: Buffer;
  const server = createServer((request, response) => {
    requests.push({ path: request.url, method: request.method });
    request.resume();
    switch (request.url) {
      case "/leaf":
        respondToLeaf(response);
        break;
      case "/intermediate":
        response.writeHead(200, { "content-type": "application/ocsp-response" });
        response.end(intermediateResponse);
        break;
      default:
        response.writeHead(404).end();
    }
  });
  await once(server.listen(0, "127.0.0.1"), "listening");
  onTestFinished(async () => {
    const closed = new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    server.closeAllConnections();
    await closed;
  });

  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Expected a TCP address");
  const origin = `http://127.0.0.1:${address.port}`;
  const endpoints = [`${origin}/leaf`, `${origin}/intermediate`] as const;
  const fixture = makeSignedFixture(undefined, endpoints);
  intermediateResponse = fixture.ocspResponse(endpoints[1], "byKey");
  const verifier = createVerifier({
    trustedRoots: [fixture.rootDer],
    clock: () => signedFixtureTime,
    policy: { mode: "online", ocsp: { allowedEndpoints: endpoints, timeoutMs } },
  });

  return { requests, verify: () => verifier.verify(fixture.signJws({ sequence: 1 })) };
};

describe("online verification with native Node fetch", () => {
  it.each([302, 307])("rejects HTTP %s without following Location", async (status) => {
    const { requests, verify } = await startResponder((response) => {
      response.writeHead(status, { location: "/redirect-target" }).end("redirect");
    });

    await expect(verify()).rejects.toMatchObject({
      code: "transport-error",
      cause: expect.objectContaining({ message: `OCSP responder returned HTTP ${status}` }),
    });
    expect(requests.filter(({ path }) => path === "/leaf")).toEqual([
      { path: "/leaf", method: "POST" },
    ]);
    expect(requests).not.toContainEqual(expect.objectContaining({ path: "/redirect-target" }));
  });

  it.each(["headers", "body"])(
    "aborts the request when the responder stalls at %s",
    async (phase) => {
      const disconnected = vi.fn();
      const { requests, verify } = await startResponder((response) => {
        response.once("close", disconnected);
        if (phase === "body") {
          response.writeHead(200, { "content-type": "application/ocsp-response" });
          response.write(Buffer.of(0x30));
        }
      }, 750);

      await expect(verify()).rejects.toMatchObject({
        code: "transport-error",
        cause: expect.objectContaining({ message: expect.stringMatching(/aborted|timed out/i) }),
      });
      expect(requests).toContainEqual({ path: "/leaf", method: "POST" });
      await vi.waitFor(() => expect(disconnected).toHaveBeenCalledOnce());
    },
  );
});
