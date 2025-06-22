import React from 'react';
import { motion } from 'framer-motion';
import { Camera, Upload } from 'lucide-react';

const ScanTest: React.FC = () => {
  return (
    <div className="max-w-4xl mx-auto">
      <motion.div
        className="text-center mb-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <h1 className="text-3xl font-bold text-gray-900 mb-4">
          Scan Your Test
        </h1>
        <p className="text-gray-600">
          Upload an image of your rapid diagnostic test for AI-powered analysis
        </p>
      </motion.div>

      <motion.div
        className="bg-white rounded-xl shadow-soft p-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
      >
        <div className="border-2 border-dashed border-gray-300 rounded-lg p-12 text-center">
          <Camera className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            Upload Test Image
          </h3>
          <p className="text-gray-600 mb-4">
            Take a photo or select an image from your device
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
              <Camera className="w-4 h-4 mr-2" />
              Take Photo
            </button>
            <button className="inline-flex items-center px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors">
              <Upload className="w-4 h-4 mr-2" />
              Choose File
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default ScanTest;