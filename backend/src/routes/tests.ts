import { Router } from 'express';
import { validate, schemas, validateQuery } from '../middleware/validation';
import { authenticateUser } from '../middleware/auth';
import { uploadTestImage } from '../middleware/upload';
import {
  createTest,
  getUserTests,
  getTestById,
  deleteTest,
  getUserTestStats,
  updateTest,
  reanalyzeTest
} from '../controllers/testController';

const router = Router();

// All routes require authentication
router.use(authenticateUser);

// Test routes
router.post(
  '/',
  uploadTestImage,
  validate(schemas.createTest),
  createTest
);

router.get(
  '/',
  validateQuery(schemas.queryParams),
  getUserTests
);

router.get('/stats', getUserTestStats);

router.get('/:testId', getTestById);

router.put(
  '/:testId',
  validate(schemas.updateProfile), // Reusing update profile schema for basic fields
  updateTest
);

router.delete('/:testId', deleteTest);

router.post('/:testId/reanalyze', reanalyzeTest);

export default router;