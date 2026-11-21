import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Outlet, Route, Routes } from "react-router";
import { describe, expect, it } from "vitest";
import type { Project, User } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import type { ProjectContext } from "../components/Layout";
import { Details } from "../pages/ProjectSettings";
import { ADMIN, MAINTAINER, fakeClient, jsonResponse } from "./helpers";

const PROJECT: Project = { key: "demo", name: "Demo", scan_path: "/srv/repos/demo", role: "maintainer" };

function renderDetails(user: User) {
  const { client, fetchSpy } = fakeClient(async (_url, init) => jsonResponse({ ...PROJECT, ...JSON.parse(String(init.body ?? "{}")) }));
  const context: ProjectContext = { project: PROJECT, canMaintain: true, reloadProject: () => undefined };
  render(
    <MemoryRouter initialEntries={["/projects/demo/settings"]}>
      <AuthProvider client={client} initialUser={user}>
        <Routes>
          <Route element={<Outlet context={context} />}>
            <Route path="/projects/:key/settings" element={<Details />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
  // Bodies of the PATCH requests sent so far.
  return () => fetchSpy.mock.calls.filter(([, init]) => init?.method === "PATCH").map(([, init]) => JSON.parse(String(init?.body)));
}

describe("project scan path", () => {
  it("is shown read-only to maintainers and never sent by them", async () => {
    const patchBodies = renderDetails(MAINTAINER);
    const field = screen.getByLabelText(/^Scan path/);
    expect(field).toHaveValue("/srv/repos/demo");
    expect(field).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Save details" }));
    await waitFor(() => expect(patchBodies()).toHaveLength(1));
    expect(patchBodies()[0]).not.toHaveProperty("scan_path");
  });

  it("is editable by administrators", async () => {
    const patchBodies = renderDetails(ADMIN);
    const field = screen.getByLabelText(/^Scan path/);
    expect(field).toBeEnabled();
    await userEvent.clear(field);
    await userEvent.type(field, "/srv/repos/other");
    await userEvent.click(screen.getByRole("button", { name: "Save details" }));
    await waitFor(() => expect(patchBodies()).toHaveLength(1));
    expect(patchBodies()[0].scan_path).toBe("/srv/repos/other");
  });
});
