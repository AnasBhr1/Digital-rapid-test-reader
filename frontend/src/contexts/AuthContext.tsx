import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, LoginCredentials, RegisterData, AuthResponse } from '../types';
import { authAPI, apiUtils } from '../services/api';
import toast from 'react-hot-toast';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
  updateProfile: (data: Partial<User>) => Promise<void>;
  changePassword: (data: { currentPassword: string; newPassword: string }) => Promise<void>;
  deleteAccount: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Initialize auth state on mount
  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    try {
      const tokens = apiUtils.getAuthTokens();
      
      if (tokens.accessToken) {
        // Try to get user profile with existing token
        const userProfile = await authAPI.getProfile();
        setUser(userProfile);
        setIsAuthenticated(true);
      }
    } catch (error) {
      // Token might be expired, clear it
      apiUtils.clearAuthTokens();
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (credentials: LoginCredentials): Promise<void> => {
    try {
      setIsLoading(true);
      const response: AuthResponse = await authAPI.login(credentials);
      
      // Store tokens
      apiUtils.setAuthTokens(response.tokens);
      
      // Set user state
      setUser(response.user);
      setIsAuthenticated(true);
      
      toast.success('Login successful!');
    } catch (error) {
      setUser(null);
      setIsAuthenticated(false);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (data: RegisterData): Promise<void> => {
    try {
      setIsLoading(true);
      const response: AuthResponse = await authAPI.register(data);
      
      // Store tokens
      apiUtils.setAuthTokens(response.tokens);
      
      // Set user state
      setUser(response.user);
      setIsAuthenticated(true);
      
      toast.success('Registration successful! Welcome to RDT Reader!');
    } catch (error) {
      setUser(null);
      setIsAuthenticated(false);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      const tokens = apiUtils.getAuthTokens();
      
      if (tokens.refreshToken) {
        await authAPI.logout(tokens.refreshToken);
      }
    } catch (error) {
      // Ignore logout errors, clear local state anyway
      console.error('Logout error:', error);
    } finally {
      // Clear local state
      apiUtils.clearAuthTokens();
      setUser(null);
      setIsAuthenticated(false);
      toast.success('Logged out successfully');
    }
  };

  const updateProfile = async (data: Partial<User>): Promise<void> => {
    try {
      const updatedUser = await authAPI.updateProfile(data);
      setUser(updatedUser);
      toast.success('Profile updated successfully!');
    } catch (error) {
      throw error;
    }
  };

  const changePassword = async (data: { currentPassword: string; newPassword: string }): Promise<void> => {
    try {
      await authAPI.changePassword(data);
      
      // After password change, user needs to login again
      await logout();
      toast.success('Password changed successfully. Please login again.');
    } catch (error) {
      throw error;
    }
  };

  const deleteAccount = async (): Promise<void> => {
    try {
      await authAPI.deleteAccount();
      
      // Clear local state
      apiUtils.clearAuthTokens();
      setUser(null);
      setIsAuthenticated(false);
      
      toast.success('Account deleted successfully');
    } catch (error) {
      throw error;
    }
  };

  const refreshUser = async (): Promise<void> => {
    try {
      if (isAuthenticated) {
        const userProfile = await authAPI.getProfile();
        setUser(userProfile);
      }
    } catch (error) {
      console.error('Failed to refresh user:', error);
      // If refresh fails, user might need to login again
      await logout();
    }
  };

  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated,
    login,
    register,
    logout,
    updateProfile,
    changePassword,
    deleteAccount,
    refreshUser
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;