import multer from 'multer';
import sharp from 'sharp';
import path from 'path';
import fs from 'fs/promises';
import { Request } from 'express';
import { AppError } from './errorHandler';

// Ensure upload directory exists
const uploadDir = path.join(process.cwd(), 'uploads');
const testImagesDir = path.join(uploadDir, 'test-images');

const ensureUploadDirs = async () => {
  try {
    await fs.mkdir(uploadDir, { recursive: true });
    await fs.mkdir(testImagesDir, { recursive: true });
    console.log('Upload directories ensured');
  } catch (error) {
    console.error('Failed to create upload directories:', error);
  }
};

// Initialize upload directories
ensureUploadDirs();

// Storage configuration for test images
const storage = multer.memoryStorage();

// File filter
const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  // Allowed MIME types
  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new AppError('Invalid file type. Only JPEG, PNG, and WebP images are allowed.', 400, 'INVALID_FILE_TYPE'));
  }
};

// Multer configuration
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.UPLOAD_MAX_SIZE || '5242880'), // 5MB default
    files: 1 // Only one file allowed
  }
});

// Process and save test image
export const processTestImage = async (
  buffer: Buffer,
  originalName: string,
  userId: string
): Promise<{ filename: string; url: string; metadata: any }> => {
  try {
    // Generate unique filename
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substring(2, 15);
    const extension = path.extname(originalName).toLowerCase() || '.jpg';
    const filename = `test_${userId}_${timestamp}_${randomString}${extension}`;
    const filepath = path.join(testImagesDir, filename);

    // Get image metadata before processing
    const metadata = await sharp(buffer).metadata();

    // Process image with Sharp
    const processedBuffer = await sharp(buffer)
      .rotate() // Auto-rotate based on EXIF
      .resize(1024, 1024, {
        fit: 'inside',
        withoutEnlargement: true
      })
      .jpeg({
        quality: 85,
        progressive: true
      })
      .toBuffer();

    // Save processed image
    await fs.writeFile(filepath, processedBuffer);

    // Generate URL (adjust based on your server setup)
    const baseUrl = process.env.BASE_URL || 'http://localhost:3001';
    const url = `${baseUrl}/uploads/test-images/${filename}`;

    return {
      filename,
      url,
      metadata: {
        originalName,
        originalSize: buffer.length,
        processedSize: processedBuffer.length,
        width: metadata.width,
        height: metadata.height,
        format: metadata.format,
        hasAlpha: metadata.hasAlpha,
        orientation: metadata.orientation
      }
    };
  } catch (error) {
    console.error('Image processing error:', error);
    throw new AppError('Failed to process image', 500, 'IMAGE_PROCESSING_ERROR');
  }
};

// Middleware for uploading test images
export const uploadTestImage = upload.single('testImage');

// Clean up old test images (run periodically)
export const cleanupOldImages = async (daysOld: number = 30): Promise<number> => {
  try {
    const files = await fs.readdir(testImagesDir);
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);
    
    let deletedCount = 0;
    
    for (const file of files) {
      const filePath = path.join(testImagesDir, file);
      const stats = await fs.stat(filePath);
      
      if (stats.mtime < cutoffDate) {
        await fs.unlink(filePath);
        deletedCount++;
      }
    }
    
    console.log(`Cleaned up ${deletedCount} old test images`);
    return deletedCount;
  } catch (error) {
    console.error('Failed to cleanup old images:', error);
    throw error;
  }
};

// Get image file info
export const getImageInfo = async (filename: string) => {
  try {
    const filepath = path.join(testImagesDir, filename);
    const stats = await fs.stat(filepath);
    const buffer = await fs.readFile(filepath);
    const metadata = await sharp(buffer).metadata();
    
    return {
      exists: true,
      size: stats.size,
      createdAt: stats.birthtime,
      modifiedAt: stats.mtime,
      metadata
    };
  } catch (error) {
    return {
      exists: false
    };
  }
};

// Delete image file
export const deleteImage = async (filename: string): Promise<boolean> => {
  try {
    const filepath = path.join(testImagesDir, filename);
    await fs.unlink(filepath);
    return true;
  } catch (error) {
    console.error('Failed to delete image:', error);
    return false;
  }
};

// Validate image for RDT analysis
export const validateRDTImage = async (buffer: Buffer): Promise<{ isValid: boolean; issues: string[] }> => {
  try {
    const metadata = await sharp(buffer).metadata();
    const issues: string[] = [];
    
    // Check minimum dimensions
    if (metadata.width && metadata.width < 200) {
      issues.push('Image width is too small (minimum 200px)');
    }
    
    if (metadata.height && metadata.height < 200) {
      issues.push('Image height is too small (minimum 200px)');
    }
    
    // Check if image is too dark or too bright
    const stats = await sharp(buffer).stats();
    const channels = stats.channels;
    
    if (channels && channels.length > 0) {
      const averageBrightness = channels.reduce((sum, channel) => sum + channel.mean, 0) / channels.length;
      
      if (averageBrightness < 30) {
        issues.push('Image appears too dark');
      } else if (averageBrightness > 225) {
        issues.push('Image appears too bright');
      }
    }
    
    // Check for blur (basic check using edge detection)
    const edges = await sharp(buffer)
      .grayscale()
      .convolve({
        width: 3,
        height: 3,
        kernel: [-1, -1, -1, -1, 8, -1, -1, -1, -1]
      })
      .raw()
      .toBuffer();
    
    // Calculate edge strength
    let edgeSum = 0;
    for (let i = 0; i < edges.length; i++) {
      edgeSum += edges[i];
    }
    const edgeStrength = edgeSum / edges.length;
    
    if (edgeStrength < 10) {
      issues.push('Image appears blurry');
    }
    
    return {
      isValid: issues.length === 0,
      issues
    };
  } catch (error) {
    console.error('Image validation error:', error);
    return {
      isValid: false,
      issues: ['Failed to validate image']
    };
  }
};

export { upload };