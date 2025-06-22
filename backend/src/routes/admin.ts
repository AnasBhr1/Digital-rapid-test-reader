import { Router } from 'express';
import { validate, schemas, validateQuery } from '../middleware/validation';
import { authenticateAdmin } from '../middleware/auth';
import {
  adminLogin,
  getDashboardStats,
  getUsers,
  getAllTests,
  getTestStatistics,
  exportData,
  deleteUser,
  getSystemHealth
} from '../controllers/adminController';

const router = Router();

// Public admin routes
router.post('/login', validate(schemas.adminLogin), adminLogin);

// Protected admin routes
router.use(authenticateAdmin); // All routes below require admin authentication

// Dashboard
router.get('/dashboard/stats', getDashboardStats);
router.get('/dashboard/health', getSystemHealth);

// User management
router.get('/users', validateQuery(schemas.queryParams), getUsers);
router.delete('/users/:userId', deleteUser);

// Test management
router.get('/tests', validateQuery(schemas.queryParams), getAllTests);
router.get('/tests/statistics', validateQuery(schemas.queryParams), getTestStatistics);

// Data export
router.get('/export', exportData);

export default router;