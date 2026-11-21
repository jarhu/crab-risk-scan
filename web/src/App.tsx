import { useEffect } from "react";
import { Link, Route, Routes, useLocation, useNavigate } from "react-router";
import { useAuth } from "./auth/AuthContext";
import { AppLayout, ProjectLayout, RequireAdmin, RequireAuth } from "./components/Layout";
import AdminTokens from "./pages/AdminTokens";
import AdminUsers from "./pages/AdminUsers";
import AdminWorkers from "./pages/AdminWorkers";
import Compare from "./pages/Compare";
import Dashboard from "./pages/Dashboard";
import Exceptions from "./pages/Exceptions";
import Findings from "./pages/Findings";
import Jobs from "./pages/Jobs";
import Login from "./pages/Login";
import ProjectOverview from "./pages/ProjectOverview";
import Projects from "./pages/Projects";
import ProjectSettings from "./pages/ProjectSettings";
import ScanDetail from "./pages/ScanDetail";
import ScanHistory from "./pages/ScanHistory";
import Schedules from "./pages/Schedules";

/** Send the user to the login page when any API call returns 401. */
function UnauthorizedRedirect() {
  const { api, expire } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  useEffect(() => {
    api.onUnauthorized(() => {
      expire();
      if (location.pathname === "/login") return;
      const next = `${location.pathname}${location.search}`;
      navigate(`/login?next=${encodeURIComponent(next)}`, { replace: true });
    });
    return () => api.onUnauthorized(undefined);
  }, [api, expire, navigate, location.pathname, location.search]);
  return null;
}

function NotFound() {
  return (
    <div>
      <h1>Page not found</h1>
      <p>
        <Link to="/">Go to the dashboard</Link>
      </p>
    </div>
  );
}

export default function App() {
  return (
    <>
      <UnauthorizedRedirect />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<RequireAuth />}>
          <Route element={<AppLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="projects" element={<Projects />} />
            <Route path="projects/:key" element={<ProjectLayout />}>
              <Route index element={<ProjectOverview />} />
              <Route path="scans" element={<ScanHistory />} />
              <Route path="exceptions" element={<Exceptions />} />
              <Route path="jobs" element={<Jobs />} />
              <Route path="schedules" element={<Schedules />} />
              <Route path="settings" element={<ProjectSettings />} />
            </Route>
            <Route path="scans/:id" element={<ScanDetail />} />
            <Route path="scans/:id/findings" element={<Findings />} />
            <Route path="scans/:id/compare" element={<Compare />} />
            <Route path="admin" element={<RequireAdmin />}>
              <Route path="users" element={<AdminUsers />} />
              <Route path="tokens" element={<AdminTokens />} />
              <Route path="workers" element={<AdminWorkers />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Route>
        </Route>
      </Routes>
    </>
  );
}
