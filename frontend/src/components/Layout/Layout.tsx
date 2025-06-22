import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Header from './Header';
import Sidebar from './Sidebar';
import MobileNav from './MobileNav';
import { useAuth } from '../../contexts/AuthContext';

interface LayoutProps {
  children: React.ReactNode;
  isAdmin?: boolean;
}

const Layout: React.FC<LayoutProps> = ({ children, isAdmin = false }) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { isAuthenticated } = useAuth();

  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  const closeSidebar = () => {
    setIsSidebarOpen(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Header */}
      <Header 
        onMenuClick={toggleSidebar}
        isAdmin={isAdmin}
      />

      <div className="flex">
        {/* Desktop Sidebar */}
        {isAuthenticated && (
          <AnimatePresence>
            <motion.div
              className="hidden lg:flex lg:flex-shrink-0"
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
            >
              <Sidebar isAdmin={isAdmin} />
            </motion.div>
          </AnimatePresence>
        )}

        {/* Mobile Sidebar Overlay */}
        {isAuthenticated && (
          <AnimatePresence>
            {isSidebarOpen && (
              <>
                {/* Backdrop */}
                <motion.div
                  className="fixed inset-0 z-40 bg-black/50 lg:hidden"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  onClick={closeSidebar}
                />
                
                {/* Mobile Sidebar */}
                <motion.div
                  className="fixed inset-y-0 left-0 z-50 w-80 lg:hidden"
                  initial={{ x: -320 }}
                  animate={{ x: 0 }}
                  exit={{ x: -320 }}
                  transition={{ duration: 0.3, ease: "easeInOut" }}
                >
                  <Sidebar 
                    isAdmin={isAdmin}
                    onClose={closeSidebar}
                    isMobile
                  />
                </motion.div>
              </>
            )}
          </AnimatePresence>
        )}

        {/* Main Content */}
        <div className="flex-1 min-w-0">
          <main className="relative">
            <motion.div
              className="px-4 py-6 sm:px-6 lg:px-8"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.1 }}
            >
              {children}
            </motion.div>
          </main>
        </div>
      </div>

      {/* Mobile Navigation */}
      {isAuthenticated && (
        <MobileNav isAdmin={isAdmin} />
      )}

      {/* PWA Install Banner */}
      <InstallBanner />
    </div>
  );
};

// PWA Install Banner Component
const InstallBanner: React.FC = () => {
  const [showInstallBanner, setShowInstallBanner] = useState(false);
  const [deferredPrompt, setDeferredPrompt] = useState<any>(null);

  React.useEffect(() => {
    const handleBeforeInstallPrompt = (e: Event) => {
      // Prevent Chrome 67 and earlier from automatically showing the prompt
      e.preventDefault();
      // Stash the event so it can be triggered later
      setDeferredPrompt(e);
      // Show the install banner
      setShowInstallBanner(true);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    };
  }, []);

  const handleInstallClick = async () => {
    if (!deferredPrompt) return;

    // Show the install prompt
    deferredPrompt.prompt();
    
    // Wait for the user to respond to the prompt
    const { outcome } = await deferredPrompt.userChoice;
    
    console.log(`User response to the install prompt: ${outcome}`);
    
    // We no longer need the prompt. Clear it up.
    setDeferredPrompt(null);
    setShowInstallBanner(false);
  };

  const handleDismiss = () => {
    setShowInstallBanner(false);
    localStorage.setItem('installBannerDismissed', 'true');
  };

  // Don't show if user has dismissed it before
  React.useEffect(() => {
    const dismissed = localStorage.getItem('installBannerDismissed');
    if (dismissed) {
      setShowInstallBanner(false);
    }
  }, []);

  if (!showInstallBanner || !deferredPrompt) {
    return null;
  }

  return (
    <AnimatePresence>
      <motion.div
        className="fixed bottom-4 left-4 right-4 z-50 lg:left-auto lg:right-4 lg:w-96"
        initial={{ y: 100, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: 100, opacity: 0 }}
        transition={{ duration: 0.3 }}
      >
        <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-4">
          <div className="flex items-start">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-primary-100 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-primary-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                </svg>
              </div>
            </div>
            <div className="ml-3 flex-1">
              <h3 className="text-sm font-medium text-gray-900">
                Install RDT Reader
              </h3>
              <p className="mt-1 text-sm text-gray-500">
                Install our app for quick access and offline functionality.
              </p>
              <div className="mt-3 flex space-x-2">
                <button
                  onClick={handleInstallClick}
                  className="bg-primary-600 text-white px-3 py-1 rounded text-sm font-medium hover:bg-primary-700 transition-colors"
                >
                  Install
                </button>
                <button
                  onClick={handleDismiss}
                  className="bg-gray-100 text-gray-700 px-3 py-1 rounded text-sm font-medium hover:bg-gray-200 transition-colors"
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  );
};

export default Layout;