import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, extractTokenFromHeader } from '../config/jwt';
import { AuthenticatedRequest, ApiResponse } from '../types';
import prisma from '../config/database';

// Middleware to authenticate users
export const authenticateUser = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Access token required',
        error: 'MISSING_TOKEN'
      } as ApiResponse);
      return;
    }

    // Verify the token
    const payload = verifyAccessToken(token);

    // Find the user in database
    const user = await prisma.user.findUnique({
      where: { id: payload.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isVerified: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (!user) {
      res.status(401).json({
        success: false,
        message: 'User not found',
        error: 'USER_NOT_FOUND'
      } as ApiResponse);
      return;
    }

    if (!user.isVerified) {
      res.status(401).json({
        success: false,
        message: 'Email not verified',
        error: 'EMAIL_NOT_VERIFIED'
      } as ApiResponse);
      return;
    }

    // Attach user to request object
    req.user = user as any;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    if (error instanceof Error) {
      if (error.message === 'Access token expired') {
        res.status(401).json({
          success: false,
          message: 'Access token expired',
          error: 'TOKEN_EXPIRED'
        } as ApiResponse);
        return;
      }
      
      if (error.message === 'Invalid access token') {
        res.status(401).json({
          success: false,
          message: 'Invalid access token',
          error: 'INVALID_TOKEN'
        } as ApiResponse);
        return;
      }
    }

    res.status(401).json({
      success: false,
      message: 'Authentication failed',
      error: 'AUTH_FAILED'
    } as ApiResponse);
  }
};

// Middleware to authenticate admins
export const authenticateAdmin = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Access token required',
        error: 'MISSING_TOKEN'
      } as ApiResponse);
      return;
    }

    // Verify the token
    const payload = verifyAccessToken(token);

    // Find the admin in database
    const admin = await prisma.admin.findUnique({
      where: { id: payload.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        permissions: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (!admin) {
      res.status(401).json({
        success: false,
        message: 'Admin not found',
        error: 'ADMIN_NOT_FOUND'
      } as ApiResponse);
      return;
    }

    // Attach admin to request object
    req.admin = admin;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    
    res.status(401).json({
      success: false,
      message: 'Authentication failed',
      error: 'AUTH_FAILED'
    } as ApiResponse);
  }
};

// Middleware to check if user has specific role
export const requireRole = (allowedRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
        error: 'NOT_AUTHENTICATED'
      } as ApiResponse);
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        error: 'INSUFFICIENT_PERMISSIONS'
      } as ApiResponse);
      return;
    }

    next();
  };
};

// Middleware to check admin permissions
export const requirePermission = (permission: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.admin) {
      res.status(401).json({
        success: false,
        message: 'Admin authentication required',
        error: 'NOT_AUTHENTICATED'
      } as ApiResponse);
      return;
    }

    if (!req.admin.permissions.includes(permission) && req.admin.role !== 'SUPER_ADMIN') {
      res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        error: 'INSUFFICIENT_PERMISSIONS'
      } as ApiResponse);
      return;
    }

    next();
  };
};

// Optional authentication - doesn't fail if no token provided
export const optionalAuth = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      next();
      return;
    }

    // Verify the token
    const payload = verifyAccessToken(token);

    // Find the user in database
    const user = await prisma.user.findUnique({
      where: { id: payload.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isVerified: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (user && user.isVerified) {
      req.user = user as any;
    }

    next();
  } catch (error) {
    // Silently continue without authentication
    next();
  }
};