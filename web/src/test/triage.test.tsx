import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { TriageForm, buildExceptionPayload } from "../components/TriageForm";

describe("triage form", () => {
  it("builds the minimal payload for an accepted risk", () => {
    expect(buildExceptionPayload({ status: "accepted", justification: "code_not_reachable", reason: " Compensating control ", expires: "", ticket: " " })).toEqual({
      status: "accepted",
      reason: "Compensating control",
    });
  });

  it("submits status, justification, reason, expiry and ticket", async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(<TriageForm onSubmit={onSubmit} />);
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "not_affected" } });
    fireEvent.change(screen.getByLabelText("Justification"), { target: { value: "code_not_reachable" } });
    await userEvent.type(screen.getByLabelText("Reason"), "Feature disabled");
    fireEvent.change(screen.getByLabelText("Expires"), { target: { value: "2027-03-31" } });
    await userEvent.type(screen.getByLabelText("Ticket"), "SEC-42");
    await userEvent.click(screen.getByRole("button", { name: "Save exception" }));
    expect(onSubmit).toHaveBeenCalledWith({
      status: "not_affected",
      justification: "code_not_reachable",
      reason: "Feature disabled",
      expires: "2027-03-31",
      ticket: "SEC-42",
    });
  });

  it("prefills from an existing exception and shows server errors", async () => {
    const onSubmit = vi.fn().mockRejectedValue(new Error("Maintainer role required"));
    render(<TriageForm initial={{ status: "false_positive", reason: "Test fixture", reviewer: "dev", ticket: "QA-1" }} onSubmit={onSubmit} />);
    expect(screen.getByLabelText("Status")).toHaveValue("false_positive");
    expect(screen.queryByLabelText("Justification")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save exception" }));
    expect(onSubmit).toHaveBeenCalledWith({ status: "false_positive", reason: "Test fixture", ticket: "QA-1" });
    expect(await screen.findByRole("alert")).toHaveTextContent("Maintainer role required");
  });
});
