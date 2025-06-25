// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
  errors?: Record<string, string[]>;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Auth types
export interface AuthResponse {
  user: User;
  tokens: AuthTokens;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  name: string;
  phone?: string;
  dateOfBirth?: string;
  gender?: 'MALE' | 'FEMALE' | 'OTHER';
}

// User types
export interface User {
  id: string;
  email: string;
  name: string;
  role: 'USER' | 'ADMIN' | 'SUPER_ADMIN';
  isVerified: boolean;
  phone?: string;
  dateOfBirth?: string;
  gender?: 'MALE' | 'FEMALE' | 'OTHER';
  createdAt: string;
  updatedAt: string;
}

// Test types
export interface Test {
  id: string;
  userId: string;
  testType: 'COVID_19' | 'PREGNANCY' | 'INFLUENZA_A' | 'STREP_A';
  result: 'POSITIVE' | 'NEGATIVE' | 'INVALID';
  confidence: number;
  imageUrl?: string;
  latitude?: number;
  longitude?: number;
  location?: string;
  testDate: string;
  isAnonymous: boolean;
  isReported: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTestData {
  testType: string;
  location?: string;
  isAnonymous?: boolean;
}

export interface UserTestStats {
  totalTests: number;
  positiveTests: number;
  negativeTests: number;
  invalidTests: number;
  recentTests: Test[];
}

export interface DashboardStats {
  totalUsers: number;
  totalTests: number;
  positiveTests: number;
  testsToday: number;
  testsThisWeek: number;
  testsThisMonth: number;
  userGrowth: number;
  testGrowth: number;
}

// Query params for API requests
export interface QueryParams {
  page?: number;
  limit?: number;
  search?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  startDate?: string;
  endDate?: string;
  testType?: string;
  result?: string;
  [key: string]: any;
}

// Form types
export interface ProfileUpdateRequest {
  name?: string;
  phone?: string;
  dateOfBirth?: string;
  gender?: 'MALE' | 'FEMALE' | 'OTHER';
}

export interface ScanTestRequest {
  image: File;
  testType: string;
  location?: string;
  isAnonymous?: boolean;
}

// Error types
export interface ValidationError {
  field: string;
  message: string;
}

export interface ApiError {
  message: string;
  statusCode: number;
  errors?: ValidationError[];
}

// Admin types
export interface AdminStats {
  totalUsers: number;
  totalTests: number;
  positiveTests: number;
  testsToday: number;
}