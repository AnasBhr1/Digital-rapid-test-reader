import React from 'react';
import { motion } from 'framer-motion';
import { BarChart3, Users, TestTube, AlertTriangle } from 'lucide-react';

const AdminDashboard: React.FC = () => {
  const stats = [
    { title: 'Total Tests', value: '1,234', icon: TestTube, color: 'bg-blue-500' },
    { title: 'Active Users', value: '567', icon: Users, color: 'bg-green-500' },
    { title: 'Positive Rate', value: '12.3%', icon: BarChart3, color: 'bg-purple-500' },
    { title: 'Alerts', value: '3', icon: AlertTriangle, color: 'bg-red-500' }
  ];

  return (
    <div className="max-w-7xl mx-auto">
      <motion.div
        className="mb-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <h1 className="text-3xl font-bold text-gray-900 mb-4">Admin Dashboard</h1>
        <p className="text-gray-600">Monitor system performance and user activity</p>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {stats.map((stat, index) => (
          <motion.div
            key={stat.title}
            className="bg-white rounded-xl shadow-soft p-6"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: index * 0.1 }}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">{stat.title}</p>
                <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
              </div>
              <div className={`w-12 h-12 ${stat.color} rounded-lg flex items-center justify-center`}>
                <stat.icon className="w-6 h-6 text-white" />
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <motion.div
        className="bg-white rounded-xl shadow-soft p-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.4 }}
      >
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Recent Activity</h2>
        <p className="text-gray-600">Recent system activity and alerts will be displayed here.</p>
      </motion.div>
    </div>
  );
};

export default AdminDashboard;