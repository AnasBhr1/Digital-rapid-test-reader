import React from 'react';
import { motion } from 'framer-motion';
import { User } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

const Profile: React.FC = () => {
  const { user } = useAuth();

  return (
    <motion.div
      className="max-w-4xl mx-auto"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
    >
      <h1 className="text-3xl font-bold text-gray-900 mb-8">Profile</h1>
      <div className="bg-white rounded-xl shadow-soft p-8">
        <div className="flex items-center mb-6">
          <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mr-4">
            <User className="w-8 h-8 text-blue-600" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-900">{user?.name}</h2>
            <p className="text-gray-600">{user?.email}</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Age</label>
            <p className="text-gray-900">{user?.age}</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Gender</label>
            <p className="text-gray-900">{user?.gender}</p>
          </div>
          {user?.phone && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Phone</label>
              <p className="text-gray-900">{user.phone}</p>
            </div>
          )}
          {user?.nationality && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Nationality</label>
              <p className="text-gray-900">{user.nationality}</p>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
};

export default Profile;