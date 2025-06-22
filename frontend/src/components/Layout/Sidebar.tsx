import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Home, 
  Camera, 
  History, 
  User, 
  Settings,
  Users,
  TestTube,
  BarChart3,
  Shield,
  X
} from 'lucide-react';

interface SidebarProps {
  isAdmin?: boolean;
  onClose?: () => void;
  isMobile?: boolean;
}

const Sidebar: React.FC<SidebarProps> = ({ isAdmin = false, onClose, isMobile = false }) => {
  const location = useLocation();

  const userNavItems = [
    { path: '/dashboard', label: 'Dashboard', icon: Home },
    { path: '/scan', label: 'Scan Test', icon: Camera },
    { path: '/history', label: 'Test History', icon: History },
    { path: '/profile', label: 'Profile', icon: User },
    { path: '/settings', label: 'Settings', icon: Settings }
  ];

  const adminNavItems = [
    { path: '/admin', label: 'Dashboard', icon: Home },
    { path: '/admin/users', label: 'Users', icon: Users },
    { path: '/admin/tests', label: 'Tests', icon: TestTube },
    { path: '/admin/analytics', label: 'Analytics', icon: BarChart3 },
    { path: '/admin/settings', label: 'Settings', icon: Settings }
  ];

  const navItems = isAdmin ? adminNavItems : userNavItems;

  const handleLinkClick = () => {
    if (isMobile && onClose) {
      onClose();
    }
  };

  return (
    <div className="w-80 bg-white h-screen shadow-lg border-r border-gray-200 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-6 border-b border-gray-200">
        <h2 className="text-lg font-semibold text-gray-900">
          {isAdmin ? 'Admin Menu' : 'Navigation'}
        </h2>
        {isMobile && (
          <button
            onClick={onClose}
            className="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100"
          >
            <X className="h-5 w-5" />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-6 space-y-2">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={item.path}
              to={item.path}
              onClick={handleLinkClick}
              className={`flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
              }`}
            >
              <item.icon className="h-5 w-5 mr-3" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-gray-200">
        <div className="flex items-center px-3 py-2">
          <Shield className="h-5 w-5 text-green-500 mr-3" />
          <div>
            <p className="text-xs font-medium text-gray-900">Secure & Private</p>
            <p className="text-xs text-gray-500">GDPR Compliant</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;