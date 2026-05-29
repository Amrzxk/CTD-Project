import { createBrowserRouter } from 'react-router';
import RootLayout from './layouts/RootLayout';
import RequireAuth from './components/RequireAuth';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import UploadPage from './pages/UploadPage';
import ManualInputPage from './pages/ManualInputPage';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import AnalyticsPage from './pages/AnalyticsPage';
import LiveStreamPage from './pages/LiveStreamPage';
import MitrePage from './pages/MitrePage';
import NotFoundPage from './pages/NotFoundPage';

// Route shape:
//
//   /            — landing page (public)
//   /login       — auth (public)
//   /*           — every other page is wrapped in <RequireAuth>, which
//                  punts unauthenticated visits to /login carrying the
//                  original path so we can redirect back after sign-in.
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
          { path: 'upload', Component: UploadPage },
          { path: 'manual', Component: ManualInputPage },
          { path: 'live', Component: LiveStreamPage },
          { path: 'dashboard', Component: DashboardPage },
          { path: 'alerts', Component: AlertsPage },
          { path: 'analytics', Component: AnalyticsPage },
          { path: 'mitre', Component: MitrePage },
        ],
      },
      { path: '*', Component: NotFoundPage },
    ],
  },
]);
