import { useState } from "react";
import type { CreatedToken } from "../api/types";

/** Show a newly created token secret once, with a copy button. */
export function TokenSecret({ token, onDismiss }: { token: CreatedToken; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="alert alert-success secret" role="status">
      <p>
        Token <strong>{token.name}</strong> created. Copy the secret now; it is not shown again.
      </p>
      <code className="secret-value">{token.token}</code>
      <div className="form-actions">
        <button
          type="button"
          className="btn"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(token.token);
              setCopied(true);
            } catch {
              setCopied(false);
            }
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
        <button type="button" className="btn" onClick={onDismiss}>
          Done
        </button>
      </div>
    </div>
  );
}
