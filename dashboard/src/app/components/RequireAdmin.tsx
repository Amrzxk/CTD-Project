import { Navigate, Outlet } from 'react-router';
import { useAuth } from '../contexts/AuthContext';

/** Role guard for admin-only routes. Assumes <RequireAuth> already ran (so
 *  `user` is resolved and any forced password change has been handled). A
 *  logged-in analyst who lands here — by typing a URL or following a stale
 *  link — is bounced to their home queue rather than shown a forbidden page. */
export default function RequireAdmin() {
  const { user } = useAuth();

  if (!user || user.role !== 'admin') {
    return <Navigate to="/alerts" replace />;
  }

  return <Outlet />;
}
