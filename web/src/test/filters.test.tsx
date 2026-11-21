import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { EMPTY_FILTERS } from "../api/types";
import { filtersFromParams, filtersToParams } from "../lib/filters";
import Findings, { FindingFiltersForm } from "../pages/Findings";
import { MEMBER, fakeClient, jsonResponse, renderRoute } from "./helpers";

describe("finding filter state", () => {
  it("round-trips through URL parameters and drops unknown values", () => {
    const filters = filtersFromParams(new URLSearchParams("severity=high&category=bogus&status=open&kind=review&new=true&q=app.py&producer=bandit"));
    expect(filters).toEqual({ severity: "high", category: "", status: "open", producer: "bandit", kind: "review", new: "true", q: "app.py" });
    expect(filtersToParams(filters, 2).toString()).toBe("severity=high&status=open&producer=bandit&kind=review&new=true&q=app.py&page=2");
    expect(filtersToParams(EMPTY_FILTERS).toString()).toBe("");
  });

  it("applies selects immediately and text on submit", async () => {
    const onChange = vi.fn();
    render(<FindingFiltersForm filters={EMPTY_FILTERS} producers={["bandit", "gitleaks"]} onChange={onChange} />);
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "critical" } });
    expect(onChange).toHaveBeenLastCalledWith({ ...EMPTY_FILTERS, severity: "critical" });
    fireEvent.change(screen.getByLabelText("Producer"), { target: { value: "gitleaks" } });
    expect(onChange).toHaveBeenLastCalledWith({ ...EMPTY_FILTERS, producer: "gitleaks" });
    await userEvent.type(screen.getByLabelText("Text"), "  config/app.env ");
    expect(onChange).toHaveBeenCalledTimes(2);
    await userEvent.click(screen.getByRole("button", { name: "Search" }));
    expect(onChange).toHaveBeenLastCalledWith({ ...EMPTY_FILTERS, q: "config/app.env" });
  });

  it("requests findings with the filters from the URL and refetches on change", async () => {
    const { client, fetchSpy } = fakeClient((url) => {
      if (url.pathname === "/api/v1/scans/7") return jsonResponse({ id: 7, project: "demo", imports: [{ input: 1, producer: "sarif" }], producers: ["gosec"] });
      return jsonResponse({ items: [], total: 0 });
    });
    renderRoute(<Findings />, { path: "/scans/:id/findings", url: "/scans/7/findings?severity=high&q=app", client, user: MEMBER });
    const findingUrls = () =>
      fetchSpy.mock.calls.map((call) => new URL(String(call[0]), "http://localhost")).filter((url) => url.pathname === "/api/v1/scans/7/findings");
    await waitFor(() => expect(findingUrls()).toHaveLength(1));
    expect(findingUrls()[0]?.searchParams.get("severity")).toBe("high");
    expect(findingUrls()[0]?.searchParams.get("q")).toBe("app");

    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "secrets" } });
    await waitFor(() => expect(findingUrls()).toHaveLength(2));
    const second = findingUrls()[1];
    expect(second?.searchParams.get("category")).toBe("secrets");
    expect(second?.searchParams.get("severity")).toBe("high");
    expect(await screen.findByText("No findings match.")).toBeInTheDocument();
  });
});
