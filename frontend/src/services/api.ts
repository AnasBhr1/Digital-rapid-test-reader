import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import toast from 'react-hot-toast';
import { 
  ApiResponse, 
  AuthResponse, 
  LoginCredentials, 
  RegisterData, 
  User, 
  Test,
  CreateTestData,
  UserTestStats,
  DashboardStats,
  PaginatedResponse,
  QueryParams
} from '../types';

// Create axios instance with base configuration
const createApiInstance = (): AxiosInstance => {
  const baseURL = import.meta.env.VITE_API_URL || '/api';
  
  const instance = axios.create({
    baseURL,
    timeout: 30000,
    headers: {
      'Content-Type': 'application/json',
    },
  });

  // Request interceptor to add auth token
  instance.interceptors.request.use(
    (config) => {
      const token = localStorage.getItem('accessToken');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    },
    (error) => {
      return Promise.reject(error);
    }
  );

  // Response interceptor to handle auth errors and token refresh
  instance.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config;

      if (error.response?.status === 401 && !originalRequest._retry) {
        originalRequest._retry = true;

        try {
          const refreshToken = localStorage.getItem('refreshToken');
          if (refreshToken) {
            const response = await axios.post(`${baseURL}/auth/refresh-token`, {
              refreshToken
            });

            const { accessToken, refreshToken: newRefreshToken } = response.data.data.tokens;
            
            localStorage.setItem('accessToken', accessToken);
            localStorage.setItem('refreshToken', newRefreshToken);

            // Retry original request with new token
            originalRequest.headers.Authorization = `Bearer ${accessToken}`;
            return instance(originalRequest);
          }
        } catch (refreshError) {
          // Refresh failed, redirect to login
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      }

      // Handle other errors
      if (error.response?.data?.message) {
        toast.error(error.response.data.message);
      } else if (error.message) {
        toast.error(error.message);
      }

      return Promise.reject(error);
    }
  );

  return instance;
};

const api = createApiInstance();

// Helper function to handle API responses
const handleResponse = <T>(response: AxiosResponse<ApiResponse<T>>): T => {
  if (!response.data.success) {
    throw new Error(response.data.message || 'Request failed');
  }
  return response.data.data as T;
};

// Helper function to build query string
const buildQueryString = (params: QueryParams): string => {
  const searchParams = new URLSearchParams();
  
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.append(key, value.toString());
    }
  });
  
  return searchParams.toString();
};

// Auth API
export const authAPI = {
  register: async (data: RegisterData): Promise<AuthResponse> => {
    const response = await api.post<ApiResponse<AuthResponse>>('/auth/register', data);
    return handleResponse(response);
  },

  login: async (credentials: LoginCredentials): Promise<AuthResponse> => {
    const response = await api.post<ApiResponse<AuthResponse>>('/auth/login', credentials);
    return handleResponse(response);
  },

  refreshToken: async (refreshToken: string): Promise<{ tokens: AuthTokens }> => {
    const response = await api.post<ApiResponse<{ tokens: AuthTokens }>>('/auth/refresh-token', {
      refreshToken
    });
    return handleResponse(response);
  },

  logout: async (refreshToken?: string): Promise<void> => {
    const response = await api.post<ApiResponse<void>>('/auth/logout', {
      refreshToken
    });
    return handleResponse(response);
  },

  getProfile: async (): Promise<User> => {
    const response = await api.get<ApiResponse<User>>('/auth/profile');
    return handleResponse(response);
  },

  updateProfile: async (data: Partial<User>): Promise<User> => {
    const response = await api.put<ApiResponse<User>>('/auth/profile', data);
    return handleResponse(response);
  },

  changePassword: async (data: { currentPassword: string; newPassword: string }): Promise<void> => {
    const response = await api.put<ApiResponse<void>>('/auth/change-password', data);
    return handleResponse(response);
  },

  deleteAccount: async (): Promise<void> => {
    const response = await api.delete<ApiResponse<void>>('/auth/account');
    return handleResponse(response);
  }
};

// Tests API
export const testsAPI = {
  create: async (data: CreateTestData, file: File): Promise<{
    test: Test;
    analysis: any;
    imageData: any;
  }> => {
    const formData = new FormData();
    formData.append('testImage', file);
    
    Object.entries(data).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        formData.append(key, value.toString());
      }
    });

    const response = await api.post<ApiResponse<{
      test: Test;
      analysis: any;
      imageData: any;
    }>>('/tests', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
    
    return handleResponse(response);
  },

  getAll: async (params: QueryParams = {}): Promise<PaginatedResponse<Test>> => {
    const queryString = buildQueryString(params);
    const url = queryString ? `/tests?${queryString}` : '/tests';
    const response = await api.get<PaginatedResponse<Test>>(url);
    return response.data;
  },

  getById: async (id: string): Promise<Test> => {
    const response = await api.get<ApiResponse<Test>>(`/tests/${id}`);
    return handleResponse(response);
  },

  update: async (id: string, data: Partial<Test>): Promise<Test> => {
    const response = await api.put<ApiResponse<Test>>(`/tests/${id}`, data);
    return handleResponse(response);
  },

  delete: async (id: string): Promise<void> => {
    const response = await api.delete<ApiResponse<void>>(`/tests/${id}`);
    return handleResponse(response);
  },

  getStats: async (): Promise<UserTestStats> => {
    const response = await api.get<ApiResponse<UserTestStats>>('/tests/stats');
    return handleResponse(response);
  },

  reanalyze: async (id: string): Promise<{
    test: Test;
    analysis: any;
  }> => {
    const response = await api.post<ApiResponse<{
      test: Test;
      analysis: any;
    }>>(`/tests/${id}/reanalyze`);
    return handleResponse(response);
  }
};

// Admin API
export const adminAPI = {
  login: async (credentials: LoginCredentials): Promise<AuthResponse> => {
    const response = await api.post<ApiResponse<AuthResponse>>('/admin/login', credentials);
    return handleResponse(response);
  },

  getDashboardStats: async (): Promise<DashboardStats> => {
    const response = await api.get<ApiResponse<DashboardStats>>('/admin/dashboard/stats');
    return handleResponse(response);
  },

  getUsers: async (params: QueryParams = {}): Promise<PaginatedResponse<User>> => {
    const queryString = buildQueryString(params);
    const url = queryString ? `/admin/users?${queryString}` : '/admin/users';
    const response = await api.get<PaginatedResponse<User>>(url);
    return response.data;
  },

  getAllTests: async (params: QueryParams = {}): Promise<PaginatedResponse<Test>> => {
    const queryString = buildQueryString(params);
    const url = queryString ? `/admin/tests?${queryString}` : '/admin/tests';
    const response = await api.get<PaginatedResponse<Test>>(url);
    return response.data;
  },

  getTestStatistics: async (params: QueryParams = {}): Promise<any> => {
    const queryString = buildQueryString(params);
    const url = queryString ? `/admin/tests/statistics?${queryString}` : '/admin/tests/statistics';
    const response = await api.get<ApiResponse<any>>(url);
    return handleResponse(response);
  },

  deleteUser: async (userId: string): Promise<void> => {
    const response = await api.delete<ApiResponse<void>>(`/admin/users/${userId}`);
    return handleResponse(response);
  },

  exportData: async (params: { format?: string; type?: string; startDate?: string; endDate?: string } = {}): Promise<Blob> => {
    const queryString = buildQueryString(params);
    const url = queryString ? `/admin/export?${queryString}` : '/admin/export';
    
    const response = await api.get(url, {
      responseType: 'blob'
    });
    
    return response.data;
  },

  getSystemHealth: async (): Promise<any> => {
    const response = await api.get<ApiResponse<any>>('/admin/dashboard/health');
    return handleResponse(response);
  }
};

// Utility functions
export const apiUtils = {
  // Set auth tokens
  setAuthTokens: (tokens: { accessToken: string; refreshToken: string }) => {
    localStorage.setItem('accessToken', tokens.accessToken);
    localStorage.setItem('refreshToken', tokens.refreshToken);
  },

  // Clear auth tokens
  clearAuthTokens: () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  },

  // Get auth tokens
  getAuthTokens: () => {
    return {
      accessToken: localStorage.getItem('accessToken'),
      refreshToken: localStorage.getItem('refreshToken')
    };
  },

  // Check if user is authenticated
  isAuthenticated: (): boolean => {
    const token = localStorage.getItem('accessToken');
    return !!token;
  },

  // Upload file with progress
  uploadFile: async (
    file: File, 
    onProgress?: (progress: number) => void
  ): Promise<{ url: string; filename: string }> => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await api.post<ApiResponse<{ url: string; filename: string }>>(
      '/upload', 
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          if (onProgress && progressEvent.total) {
            const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            onProgress(progress);
          }
        }
      }
    );

    return handleResponse(response);
  },

  // Download file
  downloadFile: async (url: string, filename: string): Promise<void> => {
    const response = await api.get(url, {
      responseType: 'blob'
    });

    const blob = new Blob([response.data]);
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  }
};

export default api;