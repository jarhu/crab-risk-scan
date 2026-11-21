import { describe, expect, it } from "vitest";
import { ApiError, TOKEN_KEY, filenameFromDisposition } from "../api/client";
import { fakeClient, jsonResponse } from "./helpers";

describe("ApiClient auth", () => {
  it("stores the login token in sessionStorage and sends it as a bearer token", async () => {
    const { client, fetchSpy } = fakeClient((url) => {
      if (url.pathname === "/api/v1/auth/login") return jsonResponse({ token: "s3ss10n", expires_at: "2026-11-22T00:00:00Z", user: { id: 1, username: "a", role: "admin", active: true } });
      return jsonResponse({ id: 1, username: "a", role: "admin", active: true, memberships: [] });
    });
    await client.login("a", "pw");
    expect(sessionStorage.getItem(TOKEN_KEY)).toBe("s3ss10n");
    const loginInit = fetchSpy.mock.calls[0]?.[1];
    expect(loginInit?.method).toBe("POST");
    expect(JSON.parse(String(loginInit?.body))).toEqual({ username: "a", password: "pw" });

    await client.me();
    const headers = fetchSpy.mock.calls[1]?.[1]?.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer s3ss10n");
  });

  it("clears the token and signals the login redirect on 401", async () => {
    sessionStorage.setItem(TOKEN_KEY, "expired");
    const { client, onUnauthorized } = fakeClient(() => jsonResponse({ detail: "Invalid or expired token" }, 401));
    await expect(client.projects()).rejects.toMatchObject({ status: 401, detail: "Invalid or expired token" });
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("does not redirect when the login itself is rejected", async () => {
    const { client, onUnauthorized } = fakeClient(() => jsonResponse({ detail: "Invalid username or password" }, 401));
    await expect(client.login("a", "bad")).rejects.toThrow("Invalid username or password");
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});

describe("ApiClient errors and lists", () => {
  it("surfaces the server detail message", async () => {
    const { client } = fakeClient(() => jsonResponse({ detail: "Maintainer role required" }, 403));
    const error = await client.deleteException("demo", "a".repeat(64)).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(403);
    expect((error as ApiError).message).toBe("Maintainer role required");
  });

  it("joins FastAPI validation details", async () => {
    const { client } = fakeClient(() => jsonResponse({ detail: [{ loc: ["body", "reason"], msg: "Field required" }] }, 422));
    await expect(client.putException("demo", "f", { status: "accepted", reason: "" })).rejects.toThrow("reason: Field required");
  });

  it("falls back to the status when the body is not JSON", async () => {
    const { client } = fakeClient(() => new Response("<html>", { status: 502 }));
    await expect(client.dashboard()).rejects.toThrow("Request failed (502)");
  });

  it("sends page parameters and filters, and omits empty filters", async () => {
    const { client, fetchSpy } = fakeClient(() => jsonResponse({ items: [{ fingerprint: "x" }], total: 120 }));
    const page = await client.findings(7, { severity: "high", category: "", q: "app.py" }, { page: 3, page_size: 50 });
    expect(page).toEqual({ items: [{ fingerprint: "x" }], total: 120 });
    const url = new URL(String(fetchSpy.mock.calls[0]?.[0]), "http://localhost");
    expect(url.pathname).toBe("/api/v1/scans/7/findings");
    expect(url.searchParams.get("severity")).toBe("high");
    expect(url.searchParams.get("q")).toBe("app.py");
    expect(url.searchParams.has("category")).toBe(false);
    expect(url.searchParams.get("page")).toBe("3");
    expect(url.searchParams.get("page_size")).toBe("50");
  });

  it("encodes path segments", async () => {
    const { client, fetchSpy } = fakeClient(() => jsonResponse({}, 200));
    await client.project("../admin");
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe("/api/v1/projects/..%2Fadmin");
  });

  it("downloads files as blobs with a sanitized file name", async () => {
    const { client, fetchSpy } = fakeClient(
      () => new Response("PK", { status: 200, headers: { "Content-Disposition": 'attachment; filename="../../evil report.docx"' } }),
    );
    const download = await client.report(9, "docx", "executive");
    expect(await download.blob.text()).toBe("PK");
    expect(download.filename).toBe("evil_report.docx");
    const url = new URL(String(fetchSpy.mock.calls[0]?.[0]), "http://localhost");
    expect(url.searchParams.get("format")).toBe("docx");
    expect(url.searchParams.get("template")).toBe("executive");
  });

  it("uses a fallback file name without Content-Disposition", () => {
    expect(filenameFromDisposition(null, "scan-1-report.sarif")).toBe("scan-1-report.sarif");
    expect(filenameFromDisposition("attachment; filename*=UTF-8''r%C3%A9port.json", "x")).toBe("r_port.json");
  });
});
