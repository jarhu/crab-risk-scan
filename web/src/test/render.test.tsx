import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityCards } from "../components/charts";
import { ExternalLink } from "../components/ui";
import { safeHref } from "../lib/safe";
import Projects from "../pages/Projects";
import { ADMIN, MEMBER, fakeClient, jsonResponse, renderRoute } from "./helpers";

describe("severity summary", () => {
  it("renders a card per severity in order with counts", () => {
    render(<SeverityCards counts={{ critical: 2, high: 5, medium: 0, low: 1, info: 0, unknown: 3 }} />);
    const cards = screen.getAllByRole("listitem");
    expect(cards.map((card) => card.textContent)).toEqual(["2critical", "5high", "0medium", "1low", "0info", "3unknown"]);
    expect(screen.getByTestId("severity-unknown")).toHaveTextContent("3");
  });

  it("shows zero for missing counts", () => {
    render(<SeverityCards counts={undefined} />);
    expect(screen.getByTestId("severity-critical")).toHaveTextContent("0");
  });
});

describe("untrusted strings", () => {
  it("allows only http and https links", () => {
    expect(safeHref("https://example.com/a")).toBe("https://example.com/a");
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("data:text/html,x")).toBeNull();
    expect(safeHref("/relative")).toBeNull();
    render(<ExternalLink href="javascript:alert(1)" />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("javascript:alert(1)")).toBeInTheDocument();
  });

  it("renders markup in API strings as text", async () => {
    const { client } = fakeClient(() => jsonResponse({ items: [{ key: "x", name: "<img src=x onerror=alert(1)>", repository_url: "javascript:alert(1)", latest_scan: null, role: "viewer" }], total: 1 }));
    const { container } = renderRoute(<Projects />, { path: "/projects", url: "/projects", client, user: MEMBER });
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector('a[href^="javascript"]')).toBeNull();
  });
});

describe("role-gated controls", () => {
  const projects = () => fakeClient(() => jsonResponse({ items: [], total: 0 }));

  it("shows project creation to administrators", async () => {
    renderRoute(<Projects />, { path: "/projects", url: "/projects", client: projects().client, user: ADMIN });
    expect(await screen.findByRole("button", { name: "Create project" })).toBeInTheDocument();
  });

  it("hides project creation from members", async () => {
    renderRoute(<Projects />, { path: "/projects", url: "/projects", client: projects().client, user: MEMBER });
    await waitFor(() => expect(screen.getByText(/not a member of any project/)).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Create project" })).not.toBeInTheDocument();
  });
});
