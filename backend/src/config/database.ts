import { PrismaClient } from '@prisma/client';

// Create a single instance of PrismaClient to be reused throughout the application
const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'info', 'warn', 'error'] : ['error'],
  errorFormat: 'minimal',
});

// Handle graceful shutdown
process.on('beforeExit', async () => {
  console.log('Disconnecting from database...');
  await prisma.$disconnect();
});

process.on('SIGINT', async () => {
  console.log('Received SIGINT, disconnecting from database...');
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Received SIGTERM, disconnecting from database...');
  await prisma.$disconnect();
  process.exit(0);
});

// Database connection test
export const testDatabaseConnection = async (): Promise<boolean> => {
  try {
    await prisma.$connect();
    console.log('✅ Database connected successfully');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    return false;
  }
};

// Health check for database
export const getDatabaseHealth = async () => {
  try {
    const start = Date.now();
    await prisma.$queryRaw`SELECT 1`;
    const end = Date.now();
    
    return {
      status: 'healthy',
      responseTime: `${end - start}ms`,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error('Database health check failed:', error);
    return {
      status: 'unhealthy',
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString()
    };
  }
};

// Database statistics
export const getDatabaseStats = async () => {
  try {
    const [userCount, testCount, adminCount] = await Promise.all([
      prisma.user.count(),
      prisma.test.count(),
      prisma.admin.count()
    ]);

    return {
      users: userCount,
      tests: testCount,
      admins: adminCount,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error('Failed to get database stats:', error);
    throw error;
  }
};

// Clean up old refresh tokens (run periodically)
export const cleanupExpiredTokens = async () => {
  try {
    const result = await prisma.refreshToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date()
        }
      }
    });
    
    console.log(`Cleaned up ${result.count} expired refresh tokens`);
    return result.count;
  } catch (error) {
    console.error('Failed to cleanup expired tokens:', error);
    throw error;
  }
};

export default prisma;