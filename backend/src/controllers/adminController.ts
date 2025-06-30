import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { generateTokens } from '../config/jwt';
import { AuthenticatedRequest, ApiResponse, DashboardStats, GeographicData, TestStats } from '../types';
import { createError, asyncHandler } from '../middleware/errorHandler';
import prisma from '../config/database';

// Admin login
export const adminLogin = asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  // Find admin by email
  const admin = await prisma.admin.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      password: true,
      name: true,
      role: true,
      permissions: true,
      lastLoginAt: true,
      createdAt: true
    }
  });

  if (!admin) {
    throw createError.unauthorized('Invalid email or password', 'INVALID_CREDENTIALS');
  }

  // Verify password
  const isValidPassword = await bcrypt.compare(password, admin.password);
  if (!isValidPassword) {
    throw createError.unauthorized('Invalid email or password', 'INVALID_CREDENTIALS');
  }

  // Update last login
  await prisma.admin.update({
    where: { id: admin.id },
    data: { lastLoginAt: new Date() }
  });

  // Generate tokens - Fix the type mismatch by casting AdminRole to Role
  const tokens = generateTokens({
    id: admin.id,
    email: admin.email,
    role: admin.role as any // Cast AdminRole to Role since they serve similar purposes
  });

  // Remove password from response
  const { password: _, ...adminWithoutPassword } = admin;

  res.json({
    success: true,
    message: 'Admin login successful',
    data: {
      admin: adminWithoutPassword,
      tokens
    }
  } as ApiResponse);
});

// Get dashboard statistics
export const getDashboardStats = asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const today = new Date();
  const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const thirtyDaysAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);

  // Get basic counts
  const [totalTests, totalUsers, todayTests, positiveTests] = await Promise.all([
    prisma.test.count(),
    prisma.user.count(),
    prisma.test.count({
      where: {
        testDate: {
          gte: startOfToday
        }
      }
    }),
    prisma.test.count({
      where: {
        result: 'POSITIVE'
      }
    })
  ]);

  // Get tests by type
  const testsByType = await prisma.test.groupBy({
    by: ['testType'],
    _count: {
      testType: true
    }
  });

  const testsByTypeObj: Record<string, number> = {};
  testsByType.forEach(item => {
    testsByTypeObj[item.testType] = item._count.testType;
  });

  // Get recent tests
  const recentTests = await prisma.test.findMany({
    orderBy: {
      testDate: 'desc'
    },
    take: 10,
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

  // Get geographic data (tests with location)
  const testsWithLocation = await prisma.test.findMany({
    where: {
      AND: [
        { latitude: { not: null } },
        { longitude: { not: null } }
      ]
    },
    select: {
      latitude: true,
      longitude: true,
      location: true,
      result: true
    }
  });

  // Group by location for geographic data
  const locationMap = new Map<string, { total: number; positive: number; coords: { lat: number; lng: number } }>();
  
  testsWithLocation.forEach(test => {
    const key = test.location || `${test.latitude},${test.longitude}`;
    const existing = locationMap.get(key) || { total: 0, positive: 0, coords: { lat: test.latitude!, lng: test.longitude! } };
    
    existing.total++;
    if (test.result === 'POSITIVE') {
      existing.positive++;
    }
    
    locationMap.set(key, existing);
  });

  const geographicData: GeographicData[] = Array.from(locationMap.entries()).map(([location, data]) => ({
    location,
    coordinates: data.coords,
    testCount: data.total,
    positiveCount: data.positive,
    positivityRate: data.total > 0 ? (data.positive / data.total) * 100 : 0
  }));

  // Get trend data for the last 30 days
  const trendData = await prisma.test.groupBy({
    by: ['testDate'],
    where: {
      testDate: {
        gte: thirtyDaysAgo
      }
    },
    _count: {
      testDate: true
    },
    _sum: {
      // This is a workaround since Prisma doesn't support conditional aggregation directly
    },
    orderBy: {
      testDate: 'asc'
    }
  });

  // Process trend data
  const trendDataProcessed = await Promise.all(
    trendData.map(async (item) => {
      const positive = await prisma.test.count({
        where: {
          testDate: item.testDate,
          result: 'POSITIVE'
        }
      });
      
      return {
        date: item.testDate.toISOString().split('T')[0],
        tests: item._count.testDate,
        positive
      };
    })
  );

  const dashboardStats: DashboardStats = {
    totalTests,
    totalUsers,
    todayTests,
    positivityRate: totalTests > 0 ? (positiveTests / totalTests) * 100 : 0,
    testsByType: testsByTypeObj,
    recentTests,
    geographicData,
    trendData: trendDataProcessed
  };

  res.json({
    success: true,
    message: 'Dashboard statistics retrieved successfully',
    data: dashboardStats
  } as ApiResponse);
});

// Get all users with pagination
export const getUsers = asyncHandler(async (req: Request, res: Response) => {
  const page = parseInt(req.query.page as string) || 1;
  const limit = parseInt(req.query.limit as string) || 20;
  const skip = (page - 1) * limit;
  const search = req.query.search as string;

  const where: any = {};

  if (search) {
    where.OR = [
      { name: { contains: search, mode: 'insensitive' } },
      { email: { contains: search, mode: 'insensitive' } }
    ];
  }

  const [users, total] = await Promise.all([
    prisma.user.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
      select: {
        id: true,
        email: true,
        name: true,
        gender: true,
        age: true,
        nationality: true,
        role: true,
        isVerified: true,
        createdAt: true,
        _count: {
          select: {
            tests: true
          }
        }
      }
    }),
    prisma.user.count({ where })
  ]);

  const totalPages = Math.ceil(total / limit);

  res.json({
    success: true,
    message: 'Users retrieved successfully',
    data: users,
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

// Get all tests with pagination and filters
export const getAllTests = asyncHandler(async (req: Request, res: Response) => {
  const page = parseInt(req.query.page as string) || 1;
  const limit = parseInt(req.query.limit as string) || 20;
  const skip = (page - 1) * limit;
  
  const { testType, result, startDate, endDate, location } = req.query;

  const where: any = {};

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

  if (location) {
    where.location = {
      contains: location,
      mode: 'insensitive'
    };
  }

  const [tests, total] = await Promise.all([
    prisma.test.findMany({
      where,
      orderBy: { testDate: 'desc' },
      skip,
      take: limit,
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            age: true,
            gender: true
          }
        }
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

// Get detailed test statistics
export const getTestStatistics = asyncHandler(async (req: Request, res: Response) => {
  const { startDate, endDate, testType, location } = req.query;

  const where: any = {};

  if (testType) {
    where.testType = testType;
  }

  if (location) {
    where.location = {
      contains: location,
      mode: 'insensitive'
    };
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

  // Get result statistics
  const resultStats = await prisma.test.groupBy({
    by: ['result'],
    where,
    _count: {
      result: true
    }
  });

  // Get test type statistics
  const testTypeStats = await prisma.test.groupBy({
    by: ['testType'],
    where,
    _count: {
      testType: true
    }
  });

  // Get daily statistics for the last 30 days
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const dailyStats = await prisma.test.groupBy({
    by: ['testDate'],
    where: {
      ...where,
      testDate: {
        gte: thirtyDaysAgo
      }
    },
    _count: {
      testDate: true
    },
    orderBy: {
      testDate: 'asc'
    }
  });

  // Process daily stats to include positive counts
  const dailyStatsWithPositive = await Promise.all(
    dailyStats.map(async (stat) => {
      const positiveCount = await prisma.test.count({
        where: {
          ...where,
          testDate: stat.testDate,
          result: 'POSITIVE'
        }
      });

      return {
        date: stat.testDate.toISOString().split('T')[0],
        count: stat._count.testDate,
        positive: positiveCount
      };
    })
  );

  // Calculate totals
  const total = resultStats.reduce((sum, stat) => sum + stat._count.result, 0);
  const positive = resultStats.find(stat => stat.result === 'POSITIVE')?._count.result || 0;
  const positivityRate = total > 0 ? (positive / total) * 100 : 0;

  // Format result statistics
  const resultStatsFormatted = {
    POSITIVE: 0,
    NEGATIVE: 0,
    INVALID: 0,
    INCONCLUSIVE: 0
  };

  resultStats.forEach(stat => {
    resultStatsFormatted[stat.result] = stat._count.result;
  });

  // Format test type statistics
  const testTypeStatsFormatted: Record<string, number> = {};
  testTypeStats.forEach(stat => {
    testTypeStatsFormatted[stat.testType] = stat._count.testType;
  });

  const statistics: TestStats = {
    total,
    positive,
    negative: resultStatsFormatted.NEGATIVE,
    invalid: resultStatsFormatted.INVALID,
    positivityRate,
    byTestType: testTypeStatsFormatted,
    byDate: dailyStatsWithPositive
  };

  res.json({
    success: true,
    message: 'Test statistics retrieved successfully',
    data: statistics
  } as ApiResponse);
});

// Export data to CSV
export const exportData = asyncHandler(async (req: Request, res: Response) => {
  const { format = 'csv', type, startDate, endDate } = req.query;

  if (format !== 'csv') {
    throw createError.badRequest('Only CSV format is currently supported');
  }

  let data: any[] = [];

  if (type === 'tests' || !type) {
    const where: any = {};
    
    if (startDate || endDate) {
      where.testDate = {};
      if (startDate) {
        where.testDate.gte = new Date(startDate as string);
      }
      if (endDate) {
        where.testDate.lte = new Date(endDate as string);
      }
    }

    data = await prisma.test.findMany({
      where,
      include: {
        user: {
          select: {
            name: true,
            email: true,
            age: true,
            gender: true,
            nationality: true
          }
        }
      },
      orderBy: {
        testDate: 'desc'
      }
    });
  } else if (type === 'users') {
    data = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        gender: true,
        age: true,
        nationality: true,
        createdAt: true,
        _count: {
          select: {
            tests: true
          }
        }
      }
    });
  }

  // Convert to CSV
  const csvHeaders = type === 'users' 
    ? ['ID', 'Email', 'Name', 'Gender', 'Age', 'Nationality', 'Created At', 'Total Tests']
    : ['Test ID', 'User Name', 'User Email', 'Test Type', 'Result', 'Confidence', 'Location', 'Test Date', 'User Age', 'User Gender'];

  const csvRows = data.map(item => {
    if (type === 'users') {
      return [
        item.id,
        item.email,
        item.name,
        item.gender,
        item.age,
        item.nationality || '',
        item.createdAt.toISOString(),
        item._count.tests
      ];
    } else {
      return [
        item.id,
        item.user.name,
        item.user.email,
        item.testType,
        item.result,
        item.confidence,
        item.location || '',
        item.testDate.toISOString(),
        item.user.age,
        item.user.gender
      ];
    }
  });

  const csvContent = [csvHeaders, ...csvRows]
    .map(row => row.map(field => `"${field}"`).join(','))
    .join('\n');

  const filename = `${type || 'tests'}_export_${new Date().toISOString().split('T')[0]}.csv`;

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csvContent);
});

// Delete user (admin action)
export const deleteUser = asyncHandler(async (req: Request, res: Response) => {
  const { userId } = req.params;

  const user = await prisma.user.findUnique({
    where: { id: userId }
  });

  if (!user) {
    throw createError.notFound('User not found');
  }

  await prisma.user.delete({
    where: { id: userId }
  });

  res.json({
    success: true,
    message: 'User deleted successfully'
  } as ApiResponse);
});

// Get system health
export const getSystemHealth = asyncHandler(async (req: Request, res: Response) => {
  const [userCount, testCount, adminCount] = await Promise.all([
    prisma.user.count(),
    prisma.test.count(),
    prisma.admin.count()
  ]);

  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    database: {
      status: 'connected',
      users: userCount,
      tests: testCount,
      admins: adminCount
    },
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.version
  };

  res.json({
    success: true,
    message: 'System health retrieved successfully',
    data: health
  } as ApiResponse);
});