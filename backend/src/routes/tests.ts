import { Router } from 'express';
import { validateQuery } from '../middleware/validation';
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
import { schemas } from '../middleware/validation';

const router = Router();

// All routes require authentication
router.use(authenticateUser);

// Test routes
router.post(
  '/',
  uploadTestImage,
  createTest
);

router.get(
  '/',
  validateQuery(schemas.queryParams),
  getUserTests
);

router.get('/stats', getUserTestStats);

router.get('/:testId', getTestById);

router.put('/:testId', updateTest);

router.delete('/:testId', deleteTest);

router.post('/:testId/reanalyze', reanalyzeTest);

export default router;