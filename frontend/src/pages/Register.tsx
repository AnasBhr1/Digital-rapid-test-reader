import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Mail, Lock, User, Eye, EyeOff, UserPlus, Phone, Globe } from 'lucide-react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import toast from 'react-hot-toast';

import { useAuth } from '../contexts/AuthContext';
import Button from '../components/UI/Button';
import Input from '../components/UI/Input';

const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Please enter a valid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
      'Password must contain uppercase, lowercase, number and special character'),
  confirmPassword: z.string(),
  gender: z.enum(['MALE', 'FEMALE', 'OTHER', 'PREFER_NOT_TO_SAY']),
  age: z.number().min(1, 'Age must be at least 1').max(150, 'Age must be less than 150'),
  phone: z.string().optional(),
  nationality: z.string().optional()
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

type RegisterFormData = z.infer<typeof registerSchema>;

const Register: React.FC = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const { register: registerUser } = useAuth();
  const navigate = useNavigate();

  const {
    register,
    handleSubmit,
    formState: { errors }
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema)
  });

  const onSubmit = async (data: RegisterFormData) => {
    try {
      setIsLoading(true);
      const { confirmPassword, ...registerData } = data;
      await registerUser(registerData);
      navigate('/dashboard');
    } catch (error) {
      console.error('Registration error:', error);
      toast.error('Registration failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
      <motion.div
        className="max-w-md w-full space-y-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        {/* Header */}
        <div className="text-center">
          <motion.div
            className="mx-auto h-12 w-12 bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl flex items-center justify-center"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <UserPlus className="h-6 w-6 text-white" />
          </motion.div>
          <h2 className="mt-6 text-3xl font-bold text-gray-900">
            Create your account
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            Join Digital RDT Reader and start analyzing tests today
          </p>
        </div>

        {/* Form */}
        <motion.form
          className="mt-8 space-y-6"
          onSubmit={handleSubmit(onSubmit)}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.3 }}
        >
          <div className="space-y-4">
            {/* Name */}
            <Input
              {...register('name')}
              type="text"
              placeholder="Enter your full name"
              label="Full Name"
              leftIcon={<User className="h-4 w-4" />}
              error={errors.name?.message}
              autoComplete="name"
            />

            {/* Email */}
            <Input
              {...register('email')}
              type="email"
              placeholder="Enter your email"
              label="Email Address"
              leftIcon={<Mail className="h-4 w-4" />}
              error={errors.email?.message}
              autoComplete="email"
            />

            {/* Gender and Age Row */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Gender
                </label>
                <select
                  {...register('gender')}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="PREFER_NOT_TO_SAY">Prefer not to say</option>
                  <option value="MALE">Male</option>
                  <option value="FEMALE">Female</option>
                  <option value="OTHER">Other</option>
                </select>
                {errors.gender && (
                  <p className="mt-1 text-xs text-red-600">{errors.gender.message}</p>
                )}
              </div>

              <Input
                {...register('age', { valueAsNumber: true })}
                type="number"
                placeholder="Age"
                label="Age"
                error={errors.age?.message}
                min="1"
                max="150"
              />
            </div>

            {/* Phone (Optional) */}
            <Input
              {...register('phone')}
              type="tel"
              placeholder="Phone number (optional)"
              label="Phone Number"
              leftIcon={<Phone className="h-4 w-4" />}
              error={errors.phone?.message}
              autoComplete="tel"
            />

            {/* Nationality (Optional) */}
            <Input
              {...register('nationality')}
              type="text"
              placeholder="Nationality (optional)"
              label="Nationality"
              leftIcon={<Globe className="h-4 w-4" />}
              error={errors.nationality?.message}
            />

            {/* Password */}
            <div className="relative">
              <Input
                {...register('password')}
                type={showPassword ? 'text' : 'password'}
                placeholder="Enter your password"
                label="Password"
                leftIcon={<Lock className="h-4 w-4" />}
                error={errors.password?.message}
                autoComplete="new-password"
              />
              <button
                type="button"
                className="absolute right-3 top-9 text-gray-400 hover:text-gray-600"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </button>
            </div>

            {/* Confirm Password */}
            <div className="relative">
              <Input
                {...register('confirmPassword')}
                type={showConfirmPassword ? 'text' : 'password'}
                placeholder="Confirm your password"
                label="Confirm Password"
                leftIcon={<Lock className="h-4 w-4" />}
                error={errors.confirmPassword?.message}
                autoComplete="new-password"
              />
              <button
                type="button"
                className="absolute right-3 top-9 text-gray-400 hover:text-gray-600"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                {showConfirmPassword ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>

          {/* Terms */}
          <div className="flex items-center">
            <input
              id="agree-terms"
              name="agree-terms"
              type="checkbox"
              required
              className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <label htmlFor="agree-terms" className="ml-2 block text-sm text-gray-900">
              I agree to the{' '}
              <Link to="/terms" className="text-blue-600 hover:text-blue-500 underline">
                Terms of Service
              </Link>{' '}
              and{' '}
              <Link to="/privacy" className="text-blue-600 hover:text-blue-500 underline">
                Privacy Policy
              </Link>
            </label>
          </div>

          <Button
            type="submit"
            fullWidth
            size="lg"
            isLoading={isLoading}
            loadingText="Creating account..."
          >
            Create Account
          </Button>

          <div className="text-center">
            <span className="text-sm text-gray-600">
              Already have an account?{' '}
              <Link
                to="/login"
                className="font-medium text-blue-600 hover:text-blue-500"
              >
                Sign in here
              </Link>
            </span>
          </div>
        </motion.form>

        {/* Footer */}
        <div className="text-center text-xs text-gray-500">
          <p>
            Your data is protected and encrypted. We comply with GDPR and healthcare privacy standards.
          </p>
        </div>
      </motion.div>
    </div>
  );
};

export default Register;