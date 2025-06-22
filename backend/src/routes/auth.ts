import { Router } from 'express';
import { validate, schemas } from '../middleware/validation';
import { authenticateUser } from '../middleware/auth';
import {
  register,
  login,
  refreshToken,
  logout,
  getProfile,
  updateProfile,
  changePassword,
  deleteAccount
} from '../controllers/authController';

const router = Router();

// Public routes
router.post('/register', validate(schemas.register), register);
router.post('/login', validate(schemas.login), login);
router.post('/refresh-token', validate(schemas.refreshToken), refreshToken);

// Protected routes
router.use(authenticateUser); // All routes below require authentication

router.post('/logout', logout);
router.get('/profile', getProfile);
router.put('/profile', validate(schemas.updateProfile), updateProfile);
router.put('/change-password', validate(schemas.changePassword), changePassword);
router.delete('/account', deleteAccount);

export default router;