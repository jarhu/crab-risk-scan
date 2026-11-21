import { useState, type FormEvent } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router";
import { useAuth } from "../auth/AuthContext";
import { ErrorMessage } from "../components/ui";

/** Accept only same-origin application paths as a post-login destination. */
function nextPath(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\") || value.startsWith("/login")) return "/";
  return value;
}

export default function Login() {
  const { status, login } = useAuth();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const destination = nextPath(params.get("next"));

  if (status === "authenticated") return <Navigate to={destination} replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
      navigate(destination, { replace: true });
    } catch (reason) {
      setError(reason);
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login" id="main">
      <form className="card login-card" onSubmit={submit} aria-labelledby="login-title">
        <h1 id="login-title">Sign in to CRAB</h1>
        <ErrorMessage error={error} />
        <label className="field">
          <span>Username</span>
          <input name="username" autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label className="field">
          <span>Password</span>
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
