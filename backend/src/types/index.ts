import { Request } from 'express';
import { User, Admin, Test, TestType, TestResult, Gender, Role } from '@prisma/client';

// Extended Express Request with user
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    name: string;
    role: Role;
    isVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  };
  admin?: {
    id: string;
    email: string;
    name: string;
    role: AdminRole;
    permissions: string[];
    lastLoginAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
  };
}

// Auth Types
export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  name: string;
  gender: Gender;
  age: number;
  phone?: string;
  nationality?: string;
}

export interface TokenPayload {
  id: string;
  email: string;
  role: Role;
  iat?: number;
  exp?: number;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

// Test Types
export interface CreateTestData {
  testType: TestType;
  result: TestResult;
  confidence?: number;
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

// API Response Types
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

// Analytics Types
export interface TestStats {
  total: number;
  positive: number;
  negative: number;
  invalid: number;
  positivityRate: number;
  byTestType: Record<TestType, number>;
  byDate: Array<{
    date: string;
    count: number;
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

// File Upload Types
export interface UploadedFile {
  filename: string;
  originalname: string;
  mimetype: string;
  size: number;
  path: string;
  url: string;
}

// Validation Types
export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

// Configuration Types
export interface DatabaseConfig {
  url: string;
}

export interface JWTConfig {
  secret: string;
  refreshSecret: string;
  expiresIn: string;
  refreshExpiresIn: string;
}

export interface ServerConfig {
  port: number;
  nodeEnv: string;
  corsOrigins: string[];
}

// Health Authority Integration
export interface HealthAuthorityReport {
  testId: string;
  patientId: string;
  testType: TestType;
  result: TestResult;
  testDate: Date;
  location?: {
    latitude: number;
    longitude: number;
    address: string;
  };
  reportedAt: Date;
}

// Alert System Types
export interface AlertData {
  type: 'OUTBREAK' | 'HIGH_POSITIVITY_RATE' | 'SYSTEM_ALERT' | 'DATA_ANOMALY';
  title: string;
  message: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  location?: string;
  coordinates?: {
    lat: number;
    lng: number;
  };
  metadata?: Record<string, any>;
}

// Query Parameters
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

// Webhook Types
export interface WebhookPayload {
  event: string;
  data: any;
  timestamp: Date;
  signature?: string;
}

// Email Types
export interface EmailTemplate {
  subject: string;
  text: string;
  html: string;
}

export interface NotificationData {
  userId: string;
  type: 'TEST_RESULT' | 'SYSTEM_ALERT' | 'HEALTH_REMINDER';
  title: string;
  message: string;
  data?: Record<string, any>;
}

// Export common Prisma types
export type {
  User,
  Admin,
  Test,
  RefreshToken,
  Alert,
  TestType,
  TestResult,
  Gender,
  Role,
  AdminRole
} from '@prisma/client';