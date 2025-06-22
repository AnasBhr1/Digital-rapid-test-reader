import { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '../types';

// Custom error class
export class AppError extends Error {
  public statusCode: number;
  public isOperational: boolean;
  public code?: string;

  constructor(message: string, statusCode: number, code?: string) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    this.code = code;

    Error.captureStackTrace(this, this.constructor);
  }
}

// Error handling middleware
export const errorHandler = (
  error: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let statusCode = 500;
  let message = 'Internal server error';
  let code = 'INTERNAL_ERROR';

  // Handle custom AppError
  if (error instanceof AppError) {
    statusCode = error.statusCode;
    message = error.message;
    code = error.code || 'APP_ERROR';
  }
  // Handle Prisma errors
  else if (error.constructor.name === 'PrismaClientKnownRequestError') {
    const prismaError = error as any;
    
    switch (prismaError.code) {
      case 'P2002':
        statusCode = 409;
        message = 'A record with this information already exists';
        code = 'DUPLICATE_RECORD';
        break;
      case 'P2025':
        statusCode = 404;
        message = 'Record not found';
        code = 'RECORD_NOT_FOUND';
        break;
      case 'P2003':
        statusCode = 400;
        message = 'Invalid reference to related record';
        code = 'INVALID_REFERENCE';
        break;
      default:
        statusCode = 400;
        message = 'Database operation failed';
        code = 'DATABASE_ERROR';
    }
  }
  // Handle Prisma validation errors
  else if (error.constructor.name === 'PrismaClientValidationError') {
    statusCode = 400;
    message = 'Invalid data provided';
    code = 'VALIDATION_ERROR';
  }
  // Handle JWT errors
  else if (error.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
    code = 'INVALID_TOKEN';
  }
  else if (error.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
    code = 'TOKEN_EXPIRED';
  }
  // Handle Multer errors (file upload)
  else if (error.constructor.name === 'MulterError') {
    const multerError = error as any;
    statusCode = 400;
    
    switch (multerError.code) {
      case 'LIMIT_FILE_SIZE':
        message = 'File size too large';
        code = 'FILE_TOO_LARGE';
        break;
      case 'LIMIT_FILE_COUNT':
        message = 'Too many files';
        code = 'TOO_MANY_FILES';
        break;
      case 'LIMIT_UNEXPECTED_FILE':
        message = 'Unexpected file field';
        code = 'UNEXPECTED_FILE';
        break;
      default:
        message = 'File upload error';
        code = 'UPLOAD_ERROR';
    }
  }
  // Handle validation errors from Joi or other validators
  else if (error.name === 'ValidationError') {
    statusCode = 400;
    message = error.message;
    code = 'VALIDATION_ERROR';
  }

  // Log error in development or if it's not operational
  if (process.env.NODE_ENV === 'development' || !(error instanceof AppError)) {
    console.error('Error:', {
      message: error.message,
      stack: error.stack,
      url: req.url,
      method: req.method,
      body: req.body,
      params: req.params,
      query: req.query,
      timestamp: new Date().toISOString()
    });
  }

  // Send error response
  const response: ApiResponse = {
    success: false,
    message,
    error: code
  };

  // Include stack trace in development
  if (process.env.NODE_ENV === 'development') {
    (response as any).stack = error.stack;
  }

  res.status(statusCode).json(response);
};

// 404 handler
export const notFoundHandler = (req: Request, res: Response): void => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
    error: 'ROUTE_NOT_FOUND'
  } as ApiResponse);
};

// Async error wrapper
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Common error creators
export const createError = {
  badRequest: (message: string, code?: string) => new AppError(message, 400, code),
  unauthorized: (message: string = 'Unauthorized', code?: string) => new AppError(message, 401, code),
  forbidden: (message: string = 'Forbidden', code?: string) => new AppError(message, 403, code),
  notFound: (message: string = 'Not found', code?: string) => new AppError(message, 404, code),
  conflict: (message: string, code?: string) => new AppError(message, 409, code),
  tooManyRequests: (message: string = 'Too many requests', code?: string) => new AppError(message, 429, code),
  internal: (message: string = 'Internal server error', code?: string) => new AppError(message, 500, code)
};