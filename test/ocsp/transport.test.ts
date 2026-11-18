import { describe, expect, it, vi } from "vitest";

import { fetchOcspResponse } from "../../source/index.js";

describe("OCSP fetch transport", () => {
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
      expect.objectContaining({ method: "POST", redirect: "error" }),
    );
    vi.unstubAllGlobals();
  });

  it.each([
    [new Response("x", { status: 500 }), 100, "returned HTTP"],
    [
      new Response("x", { status: 200, headers: { "content-type": "text/plain" } }),
      100,
      "content type",
    ],
    [
      new Response("1234", {
        status: 200,
        headers: { "content-length": "4", "content-type": "application/ocsp-response" },
      }),
      3,
      "body limit",
    ],
  ])("rejects unsafe response (%s)", async (response, maxBytes, message) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response),
    );
    await expect(
      fetchOcspResponse(
        "https://ocsp.example.test",
        Uint8Array.of(9),
        new AbortController().signal,
        { maxResponseBytes: maxBytes },
      ),
    ).rejects.toThrow(message);
    vi.unstubAllGlobals();
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
    vi.unstubAllGlobals();
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
    vi.unstubAllGlobals();
  });
});
