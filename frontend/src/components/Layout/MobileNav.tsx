import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Home, Camera, History, User, BarChart3 } from 'lucide-react';

interface MobileNavProps {
  isAdmin?: boolean;
}

const MobileNav: React.FC<MobileNavProps> = ({ isAdmin = false }) => {
  const location = useLocation();

  const userNavItems = [
    { path: '/dashboard', label: 'Home', icon: Home },
    { path: '/scan', label: 'Scan', icon: Camera },
    { path: '/history', label: 'History', icon: History },
    { path: '/profile', label: 'Profile', icon: User }
  ];

  const adminNavItems = [
    { path: '/admin', label: 'Dashboard', icon: Home },
    { path: '/admin/users', label: 'Users', icon: User },
    { path: '/admin/tests', label: 'Tests', icon: Camera },
    { path: '/admin/analytics', label: 'Analytics', icon: BarChart3 }
  ];

  const navItems = isAdmin ? adminNavItems : userNavItems;

  return (
    <div className="lg:hidden fixed bottom-0 left-0 right-0 bg-white border-t border-gray-200 safe-area z-50">
      <div className="flex justify-around items-center py-2">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex flex-col items-center py-2 px-3 rounded-lg transition-colors ${
                isActive
                  ? 'text-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              <item.icon className={`h-5 w-5 mb-1 ${isActive ? 'text-blue-600' : 'text-gray-600'}`} />
              <span className={`text-xs font-medium ${isActive ? 'text-blue-600' : 'text-gray-600'}`}>
                {item.label}
              </span>
            </Link>
          );
        })}
      </div>
    </div>
  );
};

export default MobileNav;