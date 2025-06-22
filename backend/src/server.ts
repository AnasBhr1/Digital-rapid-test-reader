import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import path from 'path';
import dotenv from 'dotenv';
import cron from 'node-cron';

// Load environment variables
dotenv.config();

// Import routes
import authRoutes from './routes/auth';
import testRoutes from './routes/tests';
import adminRoutes from './routes/admin';

// Import middleware
import { errorHandler, notFoundHandler } from './middleware/errorHandler';

// Import database and utilities
import { testDatabaseConnection, cleanupExpiredTokens } from './config/database';
import { cleanupOldImages } from './middleware/upload';

// Create Express app
const app = express();

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'), // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
    error: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Serve static files (uploaded images)
app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is healthy',
    data: {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV
    }
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/tests', testRoutes);
app.use('/api/admin', adminRoutes);

// API documentation endpoint
app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'Digital RDT Reader API',
    data: {
      version: '1.0.0',
      endpoints: {
        auth: '/api/auth',
        tests: '/api/tests',
        admin: '/api/admin'
      },
      documentation: 'https://github.com/your-repo/api-docs'
    }
  });
});

// 404 handler for API routes
app.use('/api/*', notFoundHandler);

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
  const frontendPath = path.join(__dirname, '../../frontend/dist');
  app.use(express.static(frontendPath));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(frontendPath, 'index.html'));
  });
}

// Global error handler
app.use(errorHandler);

// Scheduled tasks
if (process.env.NODE_ENV === 'production') {
  // Clean up expired tokens daily at 2 AM
  cron.schedule('0 2 * * *', async () => {
    console.log('Running scheduled cleanup of expired tokens...');
    try {
      await cleanupExpiredTokens();
      console.log('Token cleanup completed successfully');
    } catch (error) {
      console.error('Token cleanup failed:', error);
    }
  });

  // Clean up old images weekly on Sunday at 3 AM
  cron.schedule('0 3 * * 0', async () => {
    console.log('Running scheduled cleanup of old images...');
    try {
      await cleanupOldImages(30); // Delete images older than 30 days
      console.log('Image cleanup completed successfully');
    } catch (error) {
      console.error('Image cleanup failed:', error);
    }
  });
}

// Start server
const PORT = process.env.PORT || 3001;

const startServer = async () => {
  try {
    // Test database connection
    const dbConnected = await testDatabaseConnection();
    if (!dbConnected) {
      console.error('Failed to connect to database. Exiting...');
      process.exit(1);
    }

    // Start the server
    app.listen(PORT, () => {
      console.log(`
🚀 Server is running!
📍 Port: ${PORT}
🌍 Environment: ${process.env.NODE_ENV || 'development'}
📊 API Docs: http://localhost:${PORT}/api
💊 Health Check: http://localhost:${PORT}/health
      `);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start the server
startServer();

export default app;