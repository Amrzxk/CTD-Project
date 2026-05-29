import { Link, useLocation, useNavigate } from 'react-router';
import { Shield, Home, Upload, PenLine, BarChart3, Bell, Moon, Sun, Activity, Target, ShieldAlert, LogOut, Radio, User as UserIcon } from 'lucide-react';
import { Button } from './ui/button';
import { useState, useEffect } from 'react';
import { Badge } from './ui/badge';
import { threatService } from '../services/threatDetectionService';
import { useAuth } from '../contexts/AuthContext';

export function Navigation() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [darkMode, setDarkMode] = useState(true);
  const [alertCount, setAlertCount] = useState(0);

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  useEffect(() => {
    // Update alert count
    const alerts = threatService.getAlerts();
    setAlertCount(alerts.filter(a => a.type === 'critical').length);
  }, [location]);

  const navItems = [
    { path: '/', label: 'Home', icon: Home },
    { path: '/upload', label: 'Upload', icon: Upload },
    { path: '/manual', label: 'Manual', icon: PenLine },
    { path: '/live', label: 'Live', icon: Radio },
    { path: '/dashboard', label: 'Dashboard', icon: BarChart3 },
    { path: '/alerts', label: 'Alerts', icon: ShieldAlert },
    { path: '/analytics', label: 'Analytics', icon: Activity },
    { path: '/mitre', label: 'MITRE', icon: Target },
  ];

  return (
    <nav className="bg-[#080c14]/95 border-b border-[#1a2540] backdrop-blur-xl sticky top-0 z-50">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-[#00ff88]/20">
              <Shield className="w-6 h-6 text-[#00ff88]" />
            </div>
            <span className="font-bold text-white text-lg hidden md:block">
              Cyber Threat Detection
            </span>
          </Link>

          {/* Navigation Links */}
          <div className="flex items-center gap-1">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path;
              return (
                <Link key={item.path} to={item.path}>
                  <Button
                    variant="ghost"
                    className={`gap-2 ${
                      isActive
                        ? 'bg-[#00ff88]/15 text-[#00ff88] hover:bg-[#00ff88]/20'
                        : 'text-gray-400 hover:text-white hover:bg-[#1a2540]'
                    }`}
                  >
                    <item.icon className="w-4 h-4" />
                    <span className="hidden md:inline">{item.label}</span>
                  </Button>
                </Link>
              );
            })}

            {/* Alerts */}
            <Button
              variant="ghost"
              className="text-gray-400 hover:text-white hover:bg-[#1a2540] relative"
            >
              <Bell className="w-4 h-4" />
              {alertCount > 0 && (
                <Badge className="absolute -top-1 -right-1 h-5 w-5 flex items-center justify-center p-0 bg-red-500 text-white text-xs">
                  {alertCount}
                </Badge>
              )}
            </Button>

            {/* Theme Toggle */}
            <Button
              variant="ghost"
              onClick={() => setDarkMode(!darkMode)}
              className="text-gray-400 hover:text-white hover:bg-[#1a2540]"
            >
              {darkMode ? (
                <Sun className="w-4 h-4" />
              ) : (
                <Moon className="w-4 h-4" />
              )}
            </Button>

            {/* User chip + logout. Shown only when authenticated so the
                public landing/login pages stay clean. */}
            {user && (
              <div className="ml-2 flex items-center gap-2 pl-2 border-l border-[#1a2540]">
                <div className="hidden md:flex flex-col text-right leading-tight">
                  <span className="text-xs text-white font-mono">{user.username}</span>
                  <span className="text-[10px] uppercase tracking-wide text-gray-500">
                    {user.role}
                  </span>
                </div>
                <div className="flex md:hidden items-center justify-center w-7 h-7 rounded-full bg-[#1a2540] text-[#00ccff]">
                  <UserIcon className="w-3.5 h-3.5" />
                </div>
                <Button
                  variant="ghost"
                  onClick={handleLogout}
                  className="text-gray-400 hover:text-white hover:bg-[#1a2540]"
                  title="Sign out"
                >
                  <LogOut className="w-4 h-4" />
                </Button>
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}