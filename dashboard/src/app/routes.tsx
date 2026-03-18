import { createBrowserRouter } from 'react-router';
import RootLayout from './layouts/RootLayout';
import LandingPage from './pages/LandingPage';
import UploadPage from './pages/UploadPage';
import ManualInputPage from './pages/ManualInputPage';
import DashboardPage from './pages/DashboardPage';
import AnalyticsPage from './pages/AnalyticsPage';
import MitrePage from './pages/MitrePage';
import NotFoundPage from './pages/NotFoundPage';

export const router = createBrowserRouter([
  {
    path: '/',
    Component: RootLayout,
    children: [
      {
        index: true,
        Component: LandingPage,
      },
      {
        path: 'upload',
        Component: UploadPage,
      },
      {
        path: 'manual',
        Component: ManualInputPage,
      },
      {
        path: 'dashboard',
        Component: DashboardPage,
      },
      {
        path: 'analytics',
        Component: AnalyticsPage,
      },
      {
        path: 'mitre',
        Component: MitrePage,
      },
      {
        path: '*',
        Component: NotFoundPage,
      },
    ],
  },
]);
