import { Response } from 'express';
import { AuthenticatedRequest, ApiResponse, TestAnalysis } from '../types';
import { createError, asyncHandler } from '../middleware/errorHandler';
import { processTestImage, validateRDTImage } from '../middleware/upload';
import prisma from '../config/database';

// Simulate AI analysis (replace with actual AI service)
const analyzeTestImage = async (imageBuffer: Buffer): Promise<TestAnalysis> => {
  // This is a mock implementation. In production, integrate with your AI service
  await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate processing time
  
  // Mock analysis results
  const mockResults = [
    { result: 'POSITIVE' as const, confidence: 0.92 },
    { result: 'NEGATIVE' as const, confidence: 0.88 },
    { result: 'INVALID' as const, confidence: 0.95 },
    { result: 'INCONCLUSIVE' as const, confidence: 0.45 }
  ];
  
  const randomResult = mockResults[Math.floor(Math.random() * mockResults.length)];
  
  return {
    result: randomResult.result,
    confidence: randomResult.confidence,
    boundingBoxes: [
      {
        x: 120,
        y: 80,
        width: 200,
        height: 50,
        label: 'control_line'
      },
      {
        x: 120,
        y: 150,
        width: 200,
        height: 50,
        label: 'test_line'
      }
    ],
    metadata: {
      processingTime: 1.2,
      model: 'rdt-analyzer-v1.0',
      timestamp: new Date().toISOString()
    }
  };
};

// Create new test with image upload
export const createTest = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  if (!req.file) {
    throw createError.badRequest('Test image is required', 'IMAGE_REQUIRED');
  }

  const { testType, latitude, longitude, location, isAnonymous } = req.body;
  
  // Validate image for RDT analysis
  const validation = await validateRDTImage(req.file.buffer);
  if (!validation.isValid) {
    throw createError.badRequest(
      `Image quality issues: ${validation.issues.join(', ')}`,
      'POOR_IMAGE_QUALITY'
    );
  }

  // Process and save image
  const imageData = await processTestImage(
    req.file.buffer,
    req.file.originalname,
    req.user.id
  );

  // Analyze image with AI
  const analysis = await analyzeTestImage(req.file.buffer);

  // Create test record
  const test = await prisma.test.create({
    data: {
      userId: req.user.id,
      testType,
      result: analysis.result,
      confidence: analysis.confidence,
      imageUrl: imageData.url,
      latitude: latitude ? parseFloat(latitude) : null,
      longitude: longitude ? parseFloat(longitude) : null,
      location,
      isAnonymous: isAnonymous === 'true' || isAnonymous === true
    },
    include: {
      user: {
        select: {
          id: true,
          name: true,
          email: true
        }
      }
    }
  });

  res.status(201).json({
    success: true,
    message: 'Test created successfully',
    data: {
      test,
      analysis: {
        confidence: analysis.confidence,
        boundingBoxes: analysis.boundingBoxes,
        metadata: analysis.metadata
      },
      imageData: {
        filename: imageData.filename,
        url: imageData.url,
        metadata: imageData.metadata
      }
    }
  } as ApiResponse);
});

// Get user's tests
export const getUserTests = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const page = parseInt(req.query.page as string) || 1;
  const limit = parseInt(req.query.limit as string) || 10;
  const skip = (page - 1) * limit;

  const { testType, result, startDate, endDate } = req.query;

  // Build filter conditions
  const where: any = {
    userId: req.user.id
  };

  if (testType) {
    where.testType = testType;
  }

  if (result) {
    where.result = result;
  }

  if (startDate || endDate) {
    where.testDate = {};
    if (startDate) {
      where.testDate.gte = new Date(startDate as string);
    }
    if (endDate) {
      where.testDate.lte = new Date(endDate as string);
    }
  }

  // Get tests with pagination
  const [tests, total] = await Promise.all([
    prisma.test.findMany({
      where,
      orderBy: { testDate: 'desc' },
      skip,
      take: limit,
      select: {
        id: true,
        testType: true,
        result: true,
        confidence: true,
        imageUrl: true,
        location: true,
        testDate: true,
        createdAt: true,
        isAnonymous: true
      }
    }),
    prisma.test.count({ where })
  ]);

  const totalPages = Math.ceil(total / limit);

  res.json({
    success: true,
    message: 'Tests retrieved successfully',
    data: tests,
    pagination: {
      page,
      limit,
      total,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  });
});

// Get test by ID
export const getTestById = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const { testId } = req.params;

  const test = await prisma.test.findFirst({
    where: {
      id: testId,
      userId: req.user.id
    },
    include: {
      user: {
        select: {
          id: true,
          name: true,
          email: true
        }
      }
    }
  });

  if (!test) {
    throw createError.notFound('Test not found', 'TEST_NOT_FOUND');
  }

  res.json({
    success: true,
    message: 'Test retrieved successfully',
    data: test
  } as ApiResponse);
});

// Delete test
export const deleteTest = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const { testId } = req.params;

  const test = await prisma.test.findFirst({
    where: {
      id: testId,
      userId: req.user.id
    }
  });

  if (!test) {
    throw createError.notFound('Test not found', 'TEST_NOT_FOUND');
  }

  // Delete test
  await prisma.test.delete({
    where: { id: testId }
  });

  // TODO: Delete associated image file
  // deleteImage(test.imageUrl);

  res.json({
    success: true,
    message: 'Test deleted successfully'
  } as ApiResponse);
});

// Get test statistics for user
export const getUserTestStats = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const stats = await prisma.test.groupBy({
    by: ['result', 'testType'],
    where: {
      userId: req.user.id
    },
    _count: {
      result: true
    }
  });

  const totalTests = await prisma.test.count({
    where: {
      userId: req.user.id
    }
  });

  const positiveTests = await prisma.test.count({
    where: {
      userId: req.user.id,
      result: 'POSITIVE'
    }
  });

  const recentTests = await prisma.test.findMany({
    where: {
      userId: req.user.id
    },
    orderBy: {
      testDate: 'desc'
    },
    take: 5,
    select: {
      id: true,
      testType: true,
      result: true,
      testDate: true,
      location: true
    }
  });

  // Process stats
  const resultStats = {
    POSITIVE: 0,
    NEGATIVE: 0,
    INVALID: 0,
    INCONCLUSIVE: 0
  };

  const testTypeStats: Record<string, number> = {};

  stats.forEach(stat => {
    resultStats[stat.result] = stat._count.result;
    testTypeStats[stat.testType] = (testTypeStats[stat.testType] || 0) + stat._count.result;
  });

  res.json({
    success: true,
    message: 'Test statistics retrieved successfully',
    data: {
      totalTests,
      positiveTests,
      positivityRate: totalTests > 0 ? (positiveTests / totalTests) * 100 : 0,
      resultStats,
      testTypeStats,
      recentTests
    }
  } as ApiResponse);
});

// Update test (limited fields)
export const updateTest = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const { testId } = req.params;
  const { location, isAnonymous } = req.body;

  const test = await prisma.test.findFirst({
    where: {
      id: testId,
      userId: req.user.id
    }
  });

  if (!test) {
    throw createError.notFound('Test not found', 'TEST_NOT_FOUND');
  }

  const updatedTest = await prisma.test.update({
    where: { id: testId },
    data: {
      ...(location !== undefined && { location }),
      ...(isAnonymous !== undefined && { isAnonymous })
    }
  });

  res.json({
    success: true,
    message: 'Test updated successfully',
    data: updatedTest
  } as ApiResponse);
});

// Reanalyze test image (if AI service is updated)
export const reanalyzeTest = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    throw createError.unauthorized('User not authenticated');
  }

  const { testId } = req.params;

  const test = await prisma.test.findFirst({
    where: {
      id: testId,
      userId: req.user.id
    }
  });

  if (!test) {
    throw createError.notFound('Test not found', 'TEST_NOT_FOUND');
  }

  if (!test.imageUrl) {
    throw createError.badRequest('No image found for this test', 'NO_IMAGE_FOUND');
  }

  // For this demo, we'll simulate reanalysis
  // In production, you would fetch the image and reanalyze it
  const mockAnalysis = await analyzeTestImage(Buffer.from('mock'));

  const updatedTest = await prisma.test.update({
    where: { id: testId },
    data: {
      result: mockAnalysis.result,
      confidence: mockAnalysis.confidence
    }
  });

  res.json({
    success: true,
    message: 'Test reanalyzed successfully',
    data: {
      test: updatedTest,
      analysis: mockAnalysis
    }
  } as ApiResponse);
});