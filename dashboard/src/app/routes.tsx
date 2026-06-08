import { createBrowserRouter } from 'react-router';
import RootLayout from './layouts/RootLayout';
import RequireAuth from './components/RequireAuth';
import RequireAdmin from './components/RequireAdmin';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import UploadPage from './pages/UploadPage';
import ManualInputPage from './pages/ManualInputPage';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import AnalyticsPage from './pages/AnalyticsPage';
import LiveStreamPage from './pages/LiveStreamPage';
import MitrePage from './pages/MitrePage';
import UserManagementPage from './pages/UserManagementPage';
import ForcePasswordChangePage from './pages/ForcePasswordChangePage';
import NotFoundPage from './pages/NotFoundPage';

// Route shape:
//
//   /            — landing page (public)
//   /login       — auth (public)
//   /*           — every other page is wrapped in <RequireAuth>, which
//                  punts unauthenticated visits to /login and forces a
//                  password change for fresh SOC accounts.
//
//   Within the authenticated area, two pages (alerts, analytics) are open to
//   every role; the rest are nested under <RequireAdmin>. SOC analysts get
//   exactly the Alerts + Analytics surface — the analyst operating model.
export const router = createBrowserRouter([
  {
    path: '/',
    Component: RootLayout,
    children: [
      { index: true, Component: LandingPage },
      { path: 'login', Component: LoginPage },
      {
        Component: RequireAuth,
        children: [
          // Forced-change screen — reachable while must_change_password is set.
          { path: 'force-password-change', Component: ForcePasswordChangePage },
          // Analyst-allowed surface.
          { path: 'alerts', Component: AlertsPage },
          { path: 'analytics', Component: AnalyticsPage },
          // Admin-only surface.
          {
            Component: RequireAdmin,
            children: [
              { path: 'upload', Component: UploadPage },
              { path: 'manual', Component: ManualInputPage },
              { path: 'live', Component: LiveStreamPage },
              { path: 'dashboard', Component: DashboardPage },
              { path: 'mitre', Component: MitrePage },
              { path: 'admin/users', Component: UserManagementPage },
            ],
          },
        ],
      },
      { path: '*', Component: NotFoundPage },
    ],
  },
]);
