import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { generateTokens, verifyRefreshToken } from '../config/jwt';
import { AuthenticatedRequest, ApiResponse, LoginCredentials, RegisterData, TokenPayload } from '../types';
import { createError, asyncHandler } from '../middleware/errorHandler';
import prisma from '../config/database';

// Register new user
export const register = asyncHandler(async (req: Request, res: Response) => {
  const { email, password, name, gender, age, phone, nationality }: RegisterData = req.body;

  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email }
  });

  if (existingUser) {
    throw createError.conflict('User with this email already exists', 'EMAIL_ALREADY_EXISTS');
  }

  // Hash password
  const saltRounds = 12;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // Create user
  const user = await prisma.user.create({
    data: {
      email,
      password: hashedPassword,
      name,
      gender,
      age,
      phone,
      nationality,
      isVerified: true // For simplicity, auto-verify. In production, implement email verification
    },
    select: {
      id: true,
      email: true,
      name: true,
      gender: true,
      age: true,
      phone: true,
      nationality: true,
      role: true,
      isVerified: true,
      createdAt: true
    }
  });

  // Generate tokens
  const tokenPayload: TokenPayload = {
    id: user.id,
    email: user.email,
    role: user.role
  };

  const tokens = generateTokens(tokenPayload);

  // Store refresh token in database
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

  await prisma.refreshToken.create({
    data: {
      token: tokens.refreshToken,
      userId: user.id,
      expiresAt
    }
  });

  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: {
      user,
      tokens
    }
  } as ApiResponse);
});

// Login user
export const login = asyncHandler(async (req: Request, res: Response) => {
  const { email, password }: LoginCredentials = req.body;

  // Find user by email
  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      password: true,
      name: true,
      gender: true,
      age: true,
      phone: true,
      nationality: true,
      role: true,
      isVerified: true,
      createdAt: true
    }
  });

  if (!user) {
    throw createError.unauthorized('Invalid email or password', 'INVALID_CREDENTIALS');
  }

  // Check if user is verified
  if (!user.isVerified) {
    throw createError.unauthorized('Please verify your email before logging in', 'EMAIL_NOT_VERIFIED');
  }

  // Verify password
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    throw createError.unauthorized('Invalid email or password', 'INVALID_CREDENTIALS');
  }

  // Generate tokens
  const tokenPayload: TokenPayload = {
    id: user.id,
    email: user.email,
    role: user.role
  };

  const tokens = generateTokens(tokenPayload);

  // Store refresh token in database
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

  await prisma.refreshToken.create({
    data: {
      token: tokens.refreshToken,
      userId: user.id,
      expiresAt
    }
  });

  // Remove password from response
  const { password: _, ...userWithoutPassword } = user;

  res.json({
    success: true,
    message: 'Login successful',
    data: {
      user: userWithoutPassword,
      tokens
    }
  } as ApiResponse);
});

// Refresh access token
export const refreshToken = asyncHandler(async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw createError.badRequest('Refresh token is required');
  }

  // Verify refresh token
  let payload: TokenPayload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch (error) {
    throw createError.unauthorized('Invalid or expired refresh token', 'INVALID_REFRESH_TOKEN');
  }

  // Check if refresh token exists in database
  const storedToken = await prisma.refreshToken.findUnique({
    where: { token: refreshToken },
    include: { user: true }
  });

  if (!storedToken) {
    throw createError.unauthorized('Refresh token not found', 'REFRESH_TOKEN_NOT_FOUND');
  }

  // Check if token is expired
  if (storedToken.expiresAt < new Date()) {
    // Delete expired token
    await prisma.refreshToken.delete({
      where: { id: storedToken.id }
    });
    throw createError.unauthorized('Refresh token expired', 'REFRESH_TOKEN_EXPIRED');
  }

  // Generate new tokens
  const newTokenPayload: TokenPayload = {
    id: storedToken.user.id,
    email: storedToken.user.email,
    role: storedToken.user.role
  };

  const newTokens = generateTokens(newTokenPayload);

  // Update refresh token in database
  const newExpiresAt = new Date();
  newExpiresAt.setDate(newExpiresAt.getDate() + 7); // 7 days

  await prisma.refreshToken.update({
    where: { id: storedToken.id },
    data: {
      token: newTokens.refreshToken,
      expiresAt: newExpiresAt
    }
  });

  res.json({
    success: true,
    message: 'Token refreshed successfully',
    data: {
      tokens: newTokens
    }
  } as ApiResponse);
});

// Logout user
export const logout = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    // Delete specific refresh token
    await prisma.refreshToken.deleteMany({
      where: {
        token: refreshToken,
        userId: req.user?.id
      }
    });
  } else if (req.user) {
    // Delete all refresh tokens for the user
    await prisma.refreshToken.deleteMany({
      where: {
        userId: req.user.id
      }
    });
  }

  res.json({
    success: true,
    message: 'Logout successful'
  } as ApiResponse);
});

// Get current user profile
export const getProfile = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: {
      id: true,
      email: true,
      name: true,
      gender: true,
      age: true,
      phone: true,
      nationality: true,
      role: true,
      isVerified: true,
      createdAt: true,
      updatedAt: true,
      _count: {
        select: {
          tests: true
        }
      }
    }
  });

  if (!user) {
    throw createError.notFound('User not found');
  }

  res.json({
    success: true,
    message: 'Profile retrieved successfully',
    data: user
  } as ApiResponse);
});

// Update user profile
export const updateProfile = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const { name, phone, nationality } = req.body;

  const updatedUser = await prisma.user.update({
    where: { id: req.user.id },
    data: {
      ...(name && { name }),
      ...(phone !== undefined && { phone: phone || null }),
      ...(nationality !== undefined && { nationality: nationality || null })
    },
    select: {
      id: true,
      email: true,
      name: true,
      gender: true,
      age: true,
      phone: true,
      nationality: true,
      role: true,
      isVerified: true,
      createdAt: true,
      updatedAt: true
    }
  });

  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: updatedUser
  } as ApiResponse);
});

// Change password
export const changePassword = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const { currentPassword, newPassword } = req.body;

  // Get user with password
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: {
      id: true,
      password: true
    }
  });

  if (!user) {
    throw createError.notFound('User not found');
  }

  // Verify current password
  const isValidPassword = await bcrypt.compare(currentPassword, user.password);
  if (!isValidPassword) {
    throw createError.badRequest('Current password is incorrect', 'INVALID_CURRENT_PASSWORD');
  }

  // Hash new password
  const saltRounds = 12;
  const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

  // Update password
  await prisma.user.update({
    where: { id: user.id },
    data: {
      password: hashedNewPassword
    }
  });

  // Logout from all devices (delete all refresh tokens)
  await prisma.refreshToken.deleteMany({
    where: {
      userId: user.id
    }
  });

  res.json({
    success: true,
    message: 'Password changed successfully. Please login again.'
  } as ApiResponse);
});

// Delete account
export const deleteAccount = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  // Delete user (cascade will handle related records)
  await prisma.user.delete({
    where: { id: req.user.id }
  });

  res.json({
    success: true,
    message: 'Account deleted successfully'
  } as ApiResponse);
});