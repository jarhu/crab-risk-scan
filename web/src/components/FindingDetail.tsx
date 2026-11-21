import type { ReactNode } from "react";
import type { ExceptionInput, Finding } from "../api/types";
import { findingLocation } from "../lib/format";
import { TriageForm } from "./TriageForm";
import { ExternalLink, SeverityBadge, StatusBadge, useAction, ErrorMessage, confirmAction } from "./ui";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export interface FindingDetailProps {
  finding: Finding;
  canTriage: boolean;
  onTriage?: (payload: ExceptionInput) => Promise<unknown>;
  onRemoveException?: () => Promise<unknown>;
}

export function FindingDetail({ finding, canTriage, onTriage, onRemoveException }: FindingDetailProps) {
  const removal = useAction();
  const status = finding.status ?? (finding.suppressed ? "suppressed" : "open");
  return (
    <div className="finding-detail">
      <p className="finding-message">{finding.message}</p>
      <dl className="detail-list">
        <Row label="Severity">
          <SeverityBadge severity={finding.severity} />
          {finding.original_severity && finding.original_severity !== finding.severity ? (
            <span className="muted"> (producer: {finding.original_severity})</span>
          ) : null}
        </Row>
        <Row label="Status">
          <StatusBadge status={status} />
          {finding.new ? <span className="badge badge-new">new</span> : null}
        </Row>
        <Row label="Rule">
          <span className="mono">{finding.rule}</span>
        </Row>
        <Row label="Producer">
          {finding.producer}
          {finding.producer_version ? ` ${finding.producer_version}` : ""}
          {finding.rule_pack ? ` (${finding.rule_pack})` : ""}
        </Row>
        <Row label="Module and category">
          {finding.module} · {finding.category} · {finding.kind}
        </Row>
        <Row label="Location">
          <span className="mono">{findingLocation(finding)}</span>
          {finding.end_line && finding.end_line !== finding.line ? <span className="muted"> to line {finding.end_line}</span> : null}
        </Row>
        {finding.resource ? (
          <Row label="Resource">
            <span className="mono">{finding.resource}</span>
            {finding.framework ? ` (${finding.framework})` : ""}
          </Row>
        ) : null}
        {finding.package ? (
          <Row label="Package">
            <span className="mono">
              {finding.package.name}
              {finding.package.version ? `@${finding.package.version}` : ""}
            </span>
            {finding.package.ecosystem ? ` (${finding.package.ecosystem})` : ""}
            {finding.package.purl ? <div className="mono small">{finding.package.purl}</div> : null}
          </Row>
        ) : null}
        {finding.manifest ? (
          <Row label="Manifest">
            <span className="mono">{finding.manifest}</span>
          </Row>
        ) : null}
        {finding.image_digest ? (
          <Row label="Image digest">
            <span className="mono small">{finding.image_digest}</span>
          </Row>
        ) : null}
        {finding.risk_type ? <Row label="Risk type">{finding.risk_type}</Row> : null}
        {finding.fixed_version ? (
          <Row label="Fixed version">
            <span className="mono">{finding.fixed_version}</span>
          </Row>
        ) : null}
        {finding.license ? <Row label="License">{finding.license}</Row> : null}
        {finding.aliases?.length ? (
          <Row label="Aliases">
            <span className="mono">{finding.aliases.join(", ")}</span>
          </Row>
        ) : null}
        {finding.cwe?.length ? <Row label="CWE">{finding.cwe.join(", ")}</Row> : null}
        {finding.cvss ? (
          <Row label="CVSS">
            {finding.cvss.score}
            {finding.cvss.vector ? <span className="mono small"> {finding.cvss.vector}</span> : null}
            {finding.cvss.source ? ` (${finding.cvss.source})` : ""}
          </Row>
        ) : null}
        {finding.epss ? (
          <Row label="EPSS">
            {finding.epss.score}
            {finding.epss.percentile !== null ? `, percentile ${finding.epss.percentile}` : ""}
            {finding.epss.date ? ` (${finding.epss.date})` : ""}
          </Row>
        ) : null}
        {finding.kev ? <Row label="Known exploited">Listed in CISA KEV</Row> : null}
        {finding.confidence ? <Row label="Confidence">{finding.confidence}</Row> : null}
        {finding.help_uri ? (
          <Row label="Reference">
            <ExternalLink href={finding.help_uri} />
          </Row>
        ) : null}
        <Row label="Fingerprint">
          <span className="mono small">{finding.fingerprint}</span>
        </Row>
      </dl>
      {finding.exception ? (
        <section className="card inset" aria-label="Current exception">
          <h3>Current exception</h3>
          <dl className="detail-list">
            <Row label="Status">{finding.exception.status.replace(/_/g, " ")}</Row>
            {finding.exception.justification ? <Row label="Justification">{finding.exception.justification.replace(/_/g, " ")}</Row> : null}
            <Row label="Reason">{finding.exception.reason}</Row>
            <Row label="Reviewer">{finding.exception.reviewer}</Row>
            {finding.exception.expires ? <Row label="Expires">{finding.exception.expires}</Row> : null}
            {finding.exception.ticket ? <Row label="Ticket">{finding.exception.ticket}</Row> : null}
          </dl>
          {canTriage && onRemoveException ? (
            <>
              <ErrorMessage error={removal.error} />
              <button
                type="button"
                className="btn btn-danger"
                disabled={removal.busy}
                onClick={() => {
                  if (confirmAction("Remove this exception? The finding becomes open again.")) void removal.run(onRemoveException);
                }}
              >
                Remove exception
              </button>
            </>
          ) : null}
        </section>
      ) : null}
      {canTriage && onTriage ? (
        <section aria-labelledby="triage-title">
          <h3 id="triage-title">{finding.exception ? "Update exception" : "Triage"}</h3>
          <TriageForm key={finding.fingerprint} initial={finding.exception} onSubmit={onTriage} />
        </section>
      ) : null}
    </div>
  );
}
