import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';

// Contexts
import { AuthProvider, useAuth } from './contexts/AuthContext';

// Components
import Layout from './components/Layout/Layout';
import LoadingSpinner from './components/UI/LoadingSpinner';

// Pages
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import ScanTest from './pages/ScanTest';
import TestHistory from './pages/TestHistory';
import TestDetails from './pages/TestDetails';
import Profile from './pages/Profile';
import AdminDashboard from './pages/AdminDashboard';
import AdminUsers from './pages/AdminUsers';
import AdminTests from './pages/AdminTests';
import AdminAnalytics from './pages/AdminAnalytics';
import NotFound from './pages/NotFound';

// Styles
import './index.css';

// Error Boundary Component
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error?: Error }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('App Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50">
          <div className="text-center p-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Something went wrong</h2>
            <p className="text-gray-600 mb-4">There was an error loading the application.</p>
            <button
              onClick={() => window.location.reload()}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
            >
              Reload Page
            </button>
            {this.state.error && (
              <details className="mt-4 text-left">
                <summary className="cursor-pointer text-sm text-gray-500">Error Details</summary>
                <pre className="mt-2 text-xs text-red-600 bg-red-50 p-2 rounded">
                  {this.state.error.message}
                </pre>
              </details>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Create a client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

// Protected Route component
interface ProtectedRouteProps {
  children: React.ReactNode;
  adminOnly?: boolean;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, adminOnly = false }) => {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (adminOnly && user?.role !== 'ADMIN' && user?.role !== 'SUPER_ADMIN') {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
};

// Public Route component (redirects authenticated users)
interface PublicRouteProps {
  children: React.ReactNode;
}

const PublicRoute: React.FC<PublicRouteProps> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
};

// App Routes component
const AppRoutes: React.FC = () => {
  return (
    <Routes>
      {/* Public routes */}
      <Route 
        path="/" 
        element={
          <Layout>
            <Home />
          </Layout>
        } 
      />
      
      <Route 
        path="/login" 
        element={
          <PublicRoute>
            <Login />
          </PublicRoute>
        } 
      />
      
      <Route 
        path="/register" 
        element={
          <PublicRoute>
            <Register />
          </PublicRoute>
        } 
      />

      {/* Protected user routes */}
      <Route 
        path="/dashboard" 
        element={
          <ProtectedRoute>
            <Layout>
              <Dashboard />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/scan" 
        element={
          <ProtectedRoute>
            <Layout>
              <ScanTest />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/history" 
        element={
          <ProtectedRoute>
            <Layout>
              <TestHistory />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/test/:testId" 
        element={
          <ProtectedRoute>
            <Layout>
              <TestDetails />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/profile" 
        element={
          <ProtectedRoute>
            <Layout>
              <Profile />
            </Layout>
          </ProtectedRoute>
        } 
      />

      {/* Admin routes */}
      <Route 
        path="/admin" 
        element={
          <ProtectedRoute adminOnly>
            <Layout isAdmin>
              <AdminDashboard />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/admin/users" 
        element={
          <ProtectedRoute adminOnly>
            <Layout isAdmin>
              <AdminUsers />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/admin/tests" 
        element={
          <ProtectedRoute adminOnly>
            <Layout isAdmin>
              <AdminTests />
            </Layout>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/admin/analytics" 
        element={
          <ProtectedRoute adminOnly>
            <Layout isAdmin>
              <AdminAnalytics />
            </Layout>
          </ProtectedRoute>
        } 
      />

      {/* 404 route */}
      <Route 
        path="*" 
        element={
          <Layout>
            <NotFound />
          </Layout>
        } 
      />
    </Routes>
  );
};

// Main App component
const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <Router>
            <div className="App min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
              <AppRoutes />
              
              {/* Toast notifications */}
              <Toaster
                position="top-right"
                toastOptions={{
                  duration: 4000,
                  style: {
                    background: '#ffffff',
                    color: '#1f2937',
                    boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
                    border: '1px solid #e5e7eb',
                    borderRadius: '12px',
                    padding: '16px',
                    fontSize: '14px',
                    fontWeight: '500',
                  },
                  success: {
                    iconTheme: {
                      primary: '#10b981',
                      secondary: '#ffffff',
                    },
                  },
                  error: {
                    iconTheme: {
                      primary: '#ef4444',
                      secondary: '#ffffff',
                    },
                  },
                }}
              />
            </div>
          </Router>
        </AuthProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
};

export default App;