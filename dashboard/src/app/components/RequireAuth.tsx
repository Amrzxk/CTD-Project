import { Navigate, useLocation, Outlet } from 'react-router';
import { Activity } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

/** Route guard. Renders an outlet for authenticated users; otherwise
 *  bounces to /login carrying the original target so we can redirect
 *  back after a successful sign-in. While the initial /auth/me probe is
 *  in flight, renders a spinner — without this we flash the login page
 *  on refresh-with-valid-cookie. */
export default function RequireAuth() {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-[#0b0f1a] via-[#111a2e] to-[#060a14] flex items-center justify-center">
        <Activity className="w-8 h-8 text-[#00ccff] animate-pulse" />
      </div>
    );
  }

  if (user === null) {
    // Pass the originally-requested path so LoginPage can redirect back.
    return <Navigate to="/login" state={{ from: location.pathname + location.search }} replace />;
  }

  return <Outlet />;
}
