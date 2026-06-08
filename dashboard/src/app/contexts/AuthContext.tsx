import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { setUnauthorizedHandler } from '../services/threatDetectionService';

/** The shape of the authenticated user as returned by ``GET /auth/me``. */
export interface AuthUser {
  id: number;
  username: string;
  role: 'admin' | 'analyst';
  is_active: boolean;
  /** True for SOC accounts with an admin-set temporary password — the app
   *  forces a change-password step before anything else is reachable. */
  must_change_password: boolean;
  created_at?: string | null;
  last_login_at: string | null;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  /** Sign in. Throws on failure so the form can surface the error. */
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /** Force a refresh of /auth/me — used after change-password etc. */
  refresh: () => Promise<void>;
}

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const AuthContext = createContext<AuthContextValue | null>(null);

/** Wrap the app in `<AuthProvider>` so every route can `useAuth()`.
 *  On mount, calls /auth/me; until that resolves we render `loading=true`
 *  so the route guard can show a spinner instead of flashing the login
 *  page on a refresh-with-valid-cookie. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/auth/me`, {
        credentials: 'include',
        cache: 'no-store',
      });
      if (res.ok) {
        const me: AuthUser = await res.json();
        setUser(me);
      } else {
        // 401 just means "not logged in" — not an error to surface.
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Wire the service-layer 401 handler so any expired-cookie response on
  // any endpoint clears local user state. RequireAuth observes `user`
  // and bounces to /login the moment we go null — no need to use
  // useNavigate here (which can't run outside the Router anyway).
  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    return () => setUnauthorizedHandler(null);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const res = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      // Backend returns 401 with detail "Invalid credentials" — surface
      // a generic message so we don't reveal user-enumeration signal.
      throw new Error('Invalid credentials');
    }
    const me: AuthUser = await res.json();
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    try {
      await fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch {
      /* network failure on logout is non-fatal */
    }
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === null) {
    throw new Error('useAuth must be used inside <AuthProvider>');
  }
  return ctx;
}
