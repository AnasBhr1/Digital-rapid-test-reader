import React, { forwardRef } from 'react';
import { motion } from 'framer-motion';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  fullWidth?: boolean;
}

const Input = forwardRef<HTMLInputElement, InputProps>(({
  label,
  error,
  helperText,
  leftIcon,
  rightIcon,
  fullWidth = true,
  className = '',
  id,
  ...props
}, ref) => {
  const inputId = id || `input-${Math.random().toString(36).substr(2, 9)}`;
  
  const baseClasses = 'w-full rounded-lg border px-3 py-2 text-sm placeholder:text-secondary-400 focus:outline-none focus:ring-1 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200';
  
  const stateClasses = error
    ? 'border-error-300 focus:border-error-500 focus:ring-error-500'
    : 'border-secondary-300 focus:border-primary-500 focus:ring-primary-500';
  
  const paddingClasses = leftIcon && rightIcon
    ? 'pl-10 pr-10'
    : leftIcon
    ? 'pl-10'
    : rightIcon
    ? 'pr-10'
    : '';

  const inputClasses = `${baseClasses} ${stateClasses} ${paddingClasses} ${className}`;
  const containerClasses = fullWidth ? 'w-full' : '';

  return (
    <motion.div
      className={containerClasses}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      {label && (
        <label
          htmlFor={inputId}
          className="block text-sm font-medium text-secondary-700 mb-1"
        >
          {label}
        </label>
      )}
      
      <div className="relative">
        {leftIcon && (
          <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
            <span className="text-secondary-400 text-sm">
              {leftIcon}
            </span>
          </div>
        )}
        
        <input
          ref={ref}
          id={inputId}
          className={inputClasses}
          {...props}
        />
        
        {rightIcon && (
          <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
            <span className="text-secondary-400 text-sm">
              {rightIcon}
            </span>
          </div>
        )}
      </div>
      
      {(error || helperText) && (
        <motion.div
          className="mt-1"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          transition={{ duration: 0.2 }}
        >
          {error ? (
            <p className="text-xs text-error-600 font-medium">
              {error}
            </p>
          ) : helperText ? (
            <p className="text-xs text-secondary-500">
              {helperText}
            </p>
          ) : null}
        </motion.div>
      )}
    </motion.div>
  );
});

Input.displayName = 'Input';

export default Input;