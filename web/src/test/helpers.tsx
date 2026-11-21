import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { vi } from "vitest";
import { ApiClient } from "../api/client";
import type { User } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

export type Handler = (url: URL, init: RequestInit) => Response | Promise<Response>;

/** An ApiClient whose fetch is a spy routed through `handler`. */
export function fakeClient(handler: Handler) {
  const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => handler(new URL(String(input), "http://localhost"), init ?? {}));
  const onUnauthorized = vi.fn();
  const client = new ApiClient({ fetch: fetchSpy, storage: sessionStorage, onUnauthorized });
  return { client, fetchSpy, onUnauthorized };
}

export const ADMIN: User = { id: 1, username: "admin", role: "admin", active: true, memberships: [] };
export const MEMBER: User = { id: 2, username: "dev", role: "member", active: true, memberships: [{ project: "demo", role: "viewer" }] };
export const MAINTAINER: User = { id: 3, username: "lead", role: "member", active: true, memberships: [{ project: "demo", role: "maintainer" }] };

export function renderRoute(element: ReactNode, { path, url, client, user }: { path: string; url: string; client: ApiClient; user: User }) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <AuthProvider client={client} initialUser={user}>
        <Routes>
          <Route path={path} element={element} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}
