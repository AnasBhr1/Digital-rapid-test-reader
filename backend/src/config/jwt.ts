import jwt from 'jsonwebtoken';
import { TokenPayload, AuthTokens } from '../types';

// JWT Configuration
export const jwtConfig = {
  secret: process.env.JWT_SECRET || 'fallback-secret-change-in-production',
  refreshSecret: process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret-change-in-production',
  expiresIn: '15m',
  refreshExpiresIn: '7d',
};

// Generate access token
export const generateAccessToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, jwtConfig.secret, { expiresIn: '15m' });
};

// Generate refresh token
export const generateRefreshToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, jwtConfig.refreshSecret, { expiresIn: '7d' });
};

// Generate both tokens
export const generateTokens = (payload: TokenPayload): AuthTokens => {
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);
  
  return {
    accessToken,
    refreshToken
  };
};

// Verify access token
export const verifyAccessToken = (token: string): TokenPayload => {
  try {
    const decoded = jwt.verify(token, jwtConfig.secret) as TokenPayload;
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Access token expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid access token');
    }
    throw new Error('Token verification failed');
  }
};

// Verify refresh token
export const verifyRefreshToken = (token: string): TokenPayload => {
  try {
    const decoded = jwt.verify(token, jwtConfig.refreshSecret) as TokenPayload;
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Refresh token expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid refresh token');
    }
    throw new Error('Refresh token verification failed');
  }
};

// Extract token from Authorization header
export const extractTokenFromHeader = (authHeader: string | undefined): string | null => {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  return authHeader.substring(7);
};

// Get token expiration date
export const getTokenExpiration = (token: string): Date | null => {
  try {
    const decoded = jwt.decode(token) as any;
    if (decoded && decoded.exp) {
      return new Date(decoded.exp * 1000);
    }
    return null;
  } catch {
    return null;
  }
};

// Check if token is expired
export const isTokenExpired = (token: string): boolean => {
  const expirationDate = getTokenExpiration(token);
  if (!expirationDate) return true;
  
  return expirationDate.getTime() < Date.now();
};