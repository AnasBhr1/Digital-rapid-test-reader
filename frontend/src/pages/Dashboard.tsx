import React from 'react';
import { motion } from 'framer-motion';
import { Camera, History, BarChart3, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import Button from '../components/UI/Button';
import { useAuth } from '../contexts/AuthContext';

const Dashboard: React.FC = () => {
  const { user } = useAuth();

  const quickActions = [
    {
      title: 'Scan New Test',
      description: 'Upload and analyze a new rapid diagnostic test',
      icon: Camera,
      href: '/scan',
      color: 'bg-blue-500'
    },
    {
      title: 'Test History',
      description: 'View your previous test results and trends',
      icon: History,
      href: '/history',
      color: 'bg-green-500'
    },
    {
      title: 'Analytics',
      description: 'Detailed insights and health tracking',
      icon: BarChart3,
      href: '/analytics',
      color: 'bg-purple-500'
    },
    {
      title: 'Privacy Settings',
      description: 'Manage your data and privacy preferences',
      icon: Shield,
      href: '/privacy',
      color: 'bg-orange-500'
    }
  ];

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <motion.div
        className="mb-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Welcome back, {user?.name}!
        </h1>
        <p className="text-gray-600">
          Ready to scan a new test or review your health data?
        </p>
      </motion.div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {quickActions.map((action, index) => (
          <motion.div
            key={action.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: index * 0.1 }}
          >
            <Link
              to={action.href}
              className="block p-6 bg-white rounded-xl shadow-soft hover:shadow-soft-lg transition-all duration-300 hover:-translate-y-1"
            >
              <div className={`w-12 h-12 ${action.color} rounded-lg flex items-center justify-center mb-4`}>
                <action.icon className="w-6 h-6 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                {action.title}
              </h3>
              <p className="text-gray-600 text-sm">
                {action.description}
              </p>
            </Link>
          </motion.div>
        ))}
      </div>

      {/* Recent Activity */}
      <motion.div
        className="bg-white rounded-xl shadow-soft p-6 mb-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.4 }}
      >
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Recent Activity</h2>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center">
              <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center mr-3">
                <Camera className="w-5 h-5 text-green-600" />
              </div>
              <div>
                <p className="font-medium text-gray-900">COVID-19 Test Analyzed</p>
                <p className="text-sm text-gray-500">2 hours ago • Result: Negative</p>
              </div>
            </div>
            <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-medium">
              Negative
            </span>
          </div>
          
          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center">
              <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center mr-3">
                <History className="w-5 h-5 text-blue-600" />
              </div>
              <div>
                <p className="font-medium text-gray-900">Test History Updated</p>
                <p className="text-sm text-gray-500">1 day ago • 5 tests total</p>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Quick Scan */}
      <motion.div
        className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl p-8 text-center"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.5 }}
      >
        <h2 className="text-2xl font-bold text-white mb-4">
          Ready to scan a test?
        </h2>
        <p className="text-blue-100 mb-6">
          Upload your rapid diagnostic test image and get instant AI-powered results
        </p>
        <Link to="/scan">
          <Button size="lg" variant="secondary">
            <Camera className="w-5 h-5 mr-2" />
            Start Scanning
          </Button>
        </Link>
      </motion.div>
    </div>
  );
};

export default Dashboard;