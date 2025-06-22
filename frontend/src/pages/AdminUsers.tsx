import React from 'react';
import { motion } from 'framer-motion';

const AdminUsers: React.FC = () => {
  return (
    <motion.div
      className="max-w-7xl mx-auto"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
    >
      <h1 className="text-3xl font-bold text-gray-900 mb-8">User Management</h1>
      <div className="bg-white rounded-xl shadow-soft p-8">
        <p className="text-gray-600">User management interface will be displayed here.</p>
      </div>
    </motion.div>
  );
};

export default AdminUsers;