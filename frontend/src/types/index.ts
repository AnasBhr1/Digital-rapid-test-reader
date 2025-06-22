// User types
export interface User {
  id: string;
  email: string;
  name: string;
  gender: 'MALE' | 'FEMALE' | 'OTHER' | 'PREFER_NOT_TO_SAY';
  age: number;
  phone?: string;
  nationality?: string;
  role: 'USER' | 'ADMIN' | 'SUPER_ADMIN';
  isVerified: boolean;
  createdAt: string;
  updatedAt: string;
  _count?: {
    tests: number;
  };
}

// Auth types
export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  name: string;
  gender: 'MALE' | 'FEMALE' | 'OTHER' | 'PREFER_NOT_TO_SAY';
  age: number;
  phone?: string;
  nationality?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResponse {
  user: User;
  tokens: AuthTokens;
}

// Test types
export type TestType = 'COVID_19' | 'PREGNANCY' | 'INFLUENZA_A' | 'INFLUENZA_B' | 'STREP_A' | 'OTHER';
export type TestResult = 'POSITIVE' | 'NEGATIVE' | 'INVALID' | 'INCONCLUSIVE';

export interface Test {
  id: string;
  userId: string;
  testType: TestType;
  result: TestResult;
  confidence: number;
  imageUrl?: string;
  latitude?: number;
  longitude?: number;
  location?: string;
  testDate: string;
  createdAt: string;
  updatedAt: string;
  isReported: boolean;
  isAnonymous: boolean;
  user?: {
    id: string;
    name: string;
    email: string;
  };
}

export interface CreateTestData {
  testType: TestType;
  latitude?: number;
  longitude?: number;
  location?: string;
  isAnonymous?: boolean;
}

export interface TestAnalysis {
  result: TestResult;
  confidence: number;
  boundingBoxes?: Array<{
    x: number;
    y: number;
    width: number;
    height: number;
    label: string;
  }>;
  metadata?: Record<string, any>;
}

// API response types
export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  errors?: Array<{
    field: string;
    message: string;
  }>;
}

export interface PaginatedResponse<T> {
  success: boolean;
  message: string;
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

// Dashboard and statistics types
export interface UserTestStats {
  totalTests: number;
  positiveTests: number;
  positivityRate: number;
  resultStats: {
    POSITIVE: number;
    NEGATIVE: number;
    INVALID: number;
    INCONCLUSIVE: number;
  };
  testTypeStats: Record<string, number>;
  recentTests: Test[];
}

export interface DashboardStats {
  totalTests: number;
  totalUsers: number;
  todayTests: number;
  positivityRate: number;
  testsByType: Record<TestType, number>;
  recentTests: Test[];
  geographicData: GeographicData[];
  trendData: Array<{
    date: string;
    tests: number;
    positive: number;
  }>;
}

export interface GeographicData {
  location: string;
  coordinates: {
    lat: number;
    lng: number;
  };
  testCount: number;
  positiveCount: number;
  positivityRate: number;
}

// Form types
export interface LoginFormData {
  email: string;
  password: string;
}

export interface RegisterFormData {
  email: string;
  password: string;
  confirmPassword: string;
  name: string;
  gender: 'MALE' | 'FEMALE' | 'OTHER' | 'PREFER_NOT_TO_SAY';
  age: number;
  phone?: string;
  nationality?: string;
}

export interface ProfileFormData {
  name: string;
  phone?: string;
  nationality?: string;
}

export interface ChangePasswordFormData {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface TestFormData {
  testType: TestType;
  location?: string;
  isAnonymous: boolean;
}

// UI component types
export interface SelectOption {
  value: string;
  label: string;
}

export interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  duration?: number;
}

// File upload types
export interface FileUploadState {
  file: File | null;
  preview: string | null;
  isUploading: boolean;
  progress: number;
  error: string | null;
}

// Location types
export interface Location {
  latitude: number;
  longitude: number;
  accuracy?: number;
  address?: string;
}

export interface LocationError {
  code: number;
  message: string;
}

// Camera types
export interface CameraState {
  isOpen: boolean;
  isCapturing: boolean;
  devices: MediaDeviceInfo[];
  selectedDevice: string | null;
  stream: MediaStream | null;
  error: string | null;
}

// Query parameters
export interface QueryParams {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  search?: string;
  startDate?: string;
  endDate?: string;
  testType?: TestType;
  result?: TestResult;
  location?: string;
}

// Navigation types
export interface NavItem {
  path: string;
  label: string;
  icon: React.ComponentType<any>;
  requiresAuth?: boolean;
  adminOnly?: boolean;
}

// Theme types
export interface Theme {
  isDark: boolean;
  toggle: () => void;
}

// PWA types
export interface PWAInstallPrompt {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

// Error types
export interface AppError {
  message: string;
  code?: string;
  status?: number;
  field?: string;
}

// Filter types
export interface TestFilters {
  testType?: TestType;
  result?: TestResult;
  startDate?: Date;
  endDate?: Date;
  location?: string;
}

// Chart data types
export interface ChartData {
  labels: string[];
  datasets: Array<{
    label: string;
    data: number[];
    backgroundColor?: string | string[];
    borderColor?: string | string[];
    borderWidth?: number;
  }>;
}

// Export types
export interface ExportOptions {
  format: 'csv' | 'json' | 'pdf';
  type: 'tests' | 'users' | 'statistics';
  startDate?: string;
  endDate?: string;
  filters?: Record<string, any>;
}