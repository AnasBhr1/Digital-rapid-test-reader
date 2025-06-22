import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { ApiResponse, ValidationError } from '../types';

// Generic validation middleware
export const validate = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { error } = schema.validate(req.body, { 
      abortEarly: false,
      allowUnknown: false,
      stripUnknown: true
    });

    if (error) {
      const errors: ValidationError[] = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      } as ApiResponse);
      return;
    }

    next();
  };
};

// Validation schemas
export const schemas = {
  // User Registration
  register: Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .min(8)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        'any.required': 'Password is required'
      }),
    name: Joi.string()
      .min(2)
      .max(100)
      .required()
      .messages({
        'string.min': 'Name must be at least 2 characters long',
        'string.max': 'Name cannot exceed 100 characters',
        'any.required': 'Name is required'
      }),
    gender: Joi.string()
      .valid('MALE', 'FEMALE', 'OTHER', 'PREFER_NOT_TO_SAY')
      .required()
      .messages({
        'any.only': 'Gender must be one of: MALE, FEMALE, OTHER, PREFER_NOT_TO_SAY',
        'any.required': 'Gender is required'
      }),
    age: Joi.number()
      .integer()
      .min(1)
      .max(150)
      .required()
      .messages({
        'number.base': 'Age must be a number',
        'number.integer': 'Age must be a whole number',
        'number.min': 'Age must be at least 1',
        'number.max': 'Age cannot exceed 150',
        'any.required': 'Age is required'
      }),
    phone: Joi.string()
      .pattern(/^\+?[1-9]\d{1,14}$/)
      .optional()
      .messages({
        'string.pattern.base': 'Please provide a valid phone number'
      }),
    nationality: Joi.string()
      .max(100)
      .optional()
      .messages({
        'string.max': 'Nationality cannot exceed 100 characters'
      })
  }),

  // User Login
  login: Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .required()
      .messages({
        'any.required': 'Password is required'
      })
  }),

  // Refresh Token
  refreshToken: Joi.object({
    refreshToken: Joi.string()
      .required()
      .messages({
        'any.required': 'Refresh token is required'
      })
  }),

  // Create Test
  createTest: Joi.object({
    testType: Joi.string()
      .valid('COVID_19', 'PREGNANCY', 'INFLUENZA_A', 'INFLUENZA_B', 'STREP_A', 'OTHER')
      .required()
      .messages({
        'any.only': 'Test type must be one of: COVID_19, PREGNANCY, INFLUENZA_A, INFLUENZA_B, STREP_A, OTHER',
        'any.required': 'Test type is required'
      }),
    result: Joi.string()
      .valid('POSITIVE', 'NEGATIVE', 'INVALID', 'INCONCLUSIVE')
      .required()
      .messages({
        'any.only': 'Result must be one of: POSITIVE, NEGATIVE, INVALID, INCONCLUSIVE',
        'any.required': 'Test result is required'
      }),
    confidence: Joi.number()
      .min(0)
      .max(1)
      .optional()
      .messages({
        'number.min': 'Confidence must be between 0 and 1',
        'number.max': 'Confidence must be between 0 and 1'
      }),
    latitude: Joi.number()
      .min(-90)
      .max(90)
      .optional()
      .messages({
        'number.min': 'Latitude must be between -90 and 90',
        'number.max': 'Latitude must be between -90 and 90'
      }),
    longitude: Joi.number()
      .min(-180)
      .max(180)
      .optional()
      .messages({
        'number.min': 'Longitude must be between -180 and 180',
        'number.max': 'Longitude must be between -180 and 180'
      }),
    location: Joi.string()
      .max(500)
      .optional()
      .messages({
        'string.max': 'Location cannot exceed 500 characters'
      }),
    isAnonymous: Joi.boolean()
      .optional()
      .default(false)
  }),

  // Update Profile
  updateProfile: Joi.object({
    name: Joi.string()
      .min(2)
      .max(100)
      .optional()
      .messages({
        'string.min': 'Name must be at least 2 characters long',
        'string.max': 'Name cannot exceed 100 characters'
      }),
    phone: Joi.string()
      .pattern(/^\+?[1-9]\d{1,14}$/)
      .optional()
      .allow('')
      .messages({
        'string.pattern.base': 'Please provide a valid phone number'
      }),
    nationality: Joi.string()
      .max(100)
      .optional()
      .allow('')
      .messages({
        'string.max': 'Nationality cannot exceed 100 characters'
      })
  }),

  // Change Password
  changePassword: Joi.object({
    currentPassword: Joi.string()
      .required()
      .messages({
        'any.required': 'Current password is required'
      }),
    newPassword: Joi.string()
      .min(8)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        'any.required': 'New password is required'
      })
  }),

  // Admin Login
  adminLogin: Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .required()
      .messages({
        'any.required': 'Password is required'
      })
  }),

  // Query Parameters Validation
  queryParams: Joi.object({
    page: Joi.number()
      .integer()
      .min(1)
      .optional()
      .default(1),
    limit: Joi.number()
      .integer()
      .min(1)
      .max(100)
      .optional()
      .default(10),
    sortBy: Joi.string()
      .optional(),
    sortOrder: Joi.string()
      .valid('asc', 'desc')
      .optional()
      .default('desc'),
    search: Joi.string()
      .max(100)
      .optional(),
    startDate: Joi.date()
      .iso()
      .optional(),
    endDate: Joi.date()
      .iso()
      .optional(),
    testType: Joi.string()
      .valid('COVID_19', 'PREGNANCY', 'INFLUENZA_A', 'INFLUENZA_B', 'STREP_A', 'OTHER')
      .optional(),
    result: Joi.string()
      .valid('POSITIVE', 'NEGATIVE', 'INVALID', 'INCONCLUSIVE')
      .optional(),
    location: Joi.string()
      .max(100)
      .optional()
  })
};

// Validate query parameters
export const validateQuery = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { error, value } = schema.validate(req.query, { 
      abortEarly: false,
      allowUnknown: false,
      stripUnknown: true
    });

    if (error) {
      const errors: ValidationError[] = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      res.status(400).json({
        success: false,
        message: 'Invalid query parameters',
        errors
      } as ApiResponse);
      return;
    }

    // Replace query with validated and sanitized values
    req.query = value;
    next();
  };
};