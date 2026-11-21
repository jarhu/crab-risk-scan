import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api as defaultApi, type ApiClient } from "../api/client";
import type { ProjectRole, User } from "../api/types";

export type AuthStatus = "loading" | "anonymous" | "authenticated";

export interface Auth {
  status: AuthStatus;
  user: User | null;
  api: ApiClient;
  isAdmin: boolean;
  /** Effective role on a project: "admin" for global admins, the membership role, or null. */
  projectRole: (key: string) => "admin" | ProjectRole | null;
  /** True when the user may triage, run jobs and change settings for the project. */
  canMaintain: (key: string) => boolean;
  login: (username: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
  /** Drop the local session after the server rejected the token. */
  expire: () => void;
}

const AuthContext = createContext<Auth | null>(null);

export function AuthProvider({ children, client = defaultApi, initialUser }: { children: ReactNode; client?: ApiClient; initialUser?: User }) {
  const [user, setUser] = useState<User | null>(initialUser ?? null);
  const [status, setStatus] = useState<AuthStatus>(initialUser ? "authenticated" : "loading");

  useEffect(() => {
    if (initialUser) return;
    if (!client.getToken()) {
      setStatus("anonymous");
      return;
    }
    let cancelled = false;
    client.me().then(
      (me) => {
        if (cancelled) return;
        setUser(me);
        setStatus("authenticated");
      },
      () => {
        if (cancelled) return;
        client.clearToken();
        setUser(null);
        setStatus("anonymous");
      },
    );
    return () => {
      cancelled = true;
    };
  }, [client, initialUser]);

  const login = useCallback(
    async (username: string, password: string) => {
      const result = await client.login(username, password);
      let me = result.user;
      try {
        me = await client.me();
      } catch {
        // The login response already carries the user; memberships load on the next visit.
      }
      setUser(me);
      setStatus("authenticated");
      return me;
    },
    [client],
  );

  const logout = useCallback(async () => {
    try {
      await client.logout();
    } finally {
      setUser(null);
      setStatus("anonymous");
    }
  }, [client]);

  const expire = useCallback(() => {
    client.clearToken();
    setUser(null);
    setStatus("anonymous");
  }, [client]);

  const value = useMemo<Auth>(() => {
    const isAdmin = user?.role === "admin";
    const projectRole = (key: string) => {
      if (!user) return null;
      if (isAdmin) return "admin" as const;
      return user.memberships?.find((m) => m.project === key)?.role ?? null;
    };
    return {
      status,
      user,
      api: client,
      isAdmin,
      projectRole,
      canMaintain: (key: string) => {
        const role = projectRole(key);
        return role === "admin" || role === "maintainer";
      },
      login,
      logout,
      expire,
    };
  }, [status, user, client, login, logout, expire]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): Auth {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
