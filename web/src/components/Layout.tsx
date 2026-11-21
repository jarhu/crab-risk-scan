import { useEffect, useState } from "react";
import { Link, NavLink, Navigate, Outlet, useLocation, useNavigate, useOutletContext, useParams } from "react-router";
import type { Project } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useAsync } from "../lib/useAsync";
import { ErrorMessage, Loading } from "./ui";

type Theme = "system" | "light" | "dark";
const THEME_KEY = "crab.theme";

function useTheme(): [Theme, (theme: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = typeof localStorage === "undefined" ? null : localStorage.getItem(THEME_KEY);
    return stored === "light" || stored === "dark" ? stored : "system";
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") {
      root.removeAttribute("data-theme");
      localStorage.removeItem(THEME_KEY);
    } else {
      root.setAttribute("data-theme", theme);
      localStorage.setItem(THEME_KEY, theme);
    }
  }, [theme]);
  return [theme, setTheme];
}

/** Redirect anonymous users to the login page, remembering where they were. */
export function RequireAuth() {
  const { status } = useAuth();
  const location = useLocation();
  if (status === "loading") return <Loading label="Checking session" />;
  if (status === "anonymous") {
    const next = `${location.pathname}${location.search}`;
    return <Navigate to={`/login?next=${encodeURIComponent(next)}`} replace />;
  }
  return <Outlet />;
}

export function RequireAdmin() {
  const { isAdmin } = useAuth();
  if (!isAdmin) {
    return (
      <div className="alert alert-error" role="alert">
        This page is available to administrators only.
      </div>
    );
  }
  return <Outlet />;
}

export function AppLayout() {
  const { user, isAdmin, logout } = useAuth();
  const navigate = useNavigate();
  const [theme, setTheme] = useTheme();
  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <Link to="/" className="brand">
          CRAB
        </Link>
        <nav aria-label="Main">
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/projects">Projects</NavLink>
          {isAdmin ? (
            <>
              <NavLink to="/admin/users">Users</NavLink>
              <NavLink to="/admin/tokens">Service tokens</NavLink>
              <NavLink to="/admin/workers">Workers and jobs</NavLink>
            </>
          ) : null}
        </nav>
        <div className="topbar-end">
          <label className="theme-select">
            <span className="visually-hidden">Theme</span>
            <select value={theme} onChange={(event) => setTheme(event.target.value as Theme)}>
              <option value="system">System theme</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </label>
          <span className="user-name" title={user?.role}>
            {user?.username}
          </span>
          <button
            type="button"
            className="btn"
            onClick={async () => {
              await logout();
              navigate("/login", { replace: true });
            }}
          >
            Sign out
          </button>
        </div>
      </header>
      <main id="main" className="content">
        <Outlet />
      </main>
    </div>
  );
}

export interface ProjectContext {
  project: Project;
  canMaintain: boolean;
  reloadProject: () => void;
}

export function useProject(): ProjectContext {
  return useOutletContext<ProjectContext>();
}

export function ProjectLayout() {
  const { key = "" } = useParams();
  const { api, canMaintain } = useAuth();
  const { data: project, error, loading, reload } = useAsync(() => api.project(key), [key]);
  if (error) return <ErrorMessage error={error} />;
  if (loading && !project) return <Loading />;
  if (!project) return null;
  // The server reports the caller's role per project; fall back to memberships from /auth/me.
  const maintain = project.role === "admin" || project.role === "maintainer" || canMaintain(key);
  const base = `/projects/${encodeURIComponent(key)}`;
  const context: ProjectContext = { project, canMaintain: maintain, reloadProject: reload };
  return (
    <div>
      <div className="page-header">
        <p className="breadcrumb">
          <Link to="/projects">Projects</Link> / <span className="mono">{project.key}</span>
        </p>
        <h1>{project.name}</h1>
      </div>
      <nav className="tabs" aria-label="Project">
        <NavLink to={base} end>
          Overview
        </NavLink>
        <NavLink to={`${base}/scans`}>Scans</NavLink>
        <NavLink to={`${base}/exceptions`}>Exceptions</NavLink>
        <NavLink to={`${base}/jobs`}>Jobs</NavLink>
        <NavLink to={`${base}/schedules`}>Schedules</NavLink>
        <NavLink to={`${base}/settings`}>Settings</NavLink>
      </nav>
      <Outlet context={context} />
    </div>
  );
}
