import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Camera, Shield, BarChart3, Smartphone, CheckCircle, Users } from 'lucide-react';
import Button from '../components/UI/Button';

const Home: React.FC = () => {
  const features = [
    {
      icon: Camera,
      title: 'AI-Powered Scanning',
      description: 'Upload your rapid diagnostic test image and get instant AI-powered results with confidence scores.'
    },
    {
      icon: Shield,
      title: 'Privacy Protected',
      description: 'Your health data is encrypted and protected. Anonymous testing options available.'
    },
    {
      icon: BarChart3,
      title: 'Track Your Health',
      description: 'View your test history, trends, and get personalized health insights over time.'
    },
    {
      icon: Smartphone,
      title: 'Mobile Ready',
      description: 'Install as a mobile app for quick access. Works offline when you need it most.'
    }
  ];

  const stats = [
    { label: 'Tests Analyzed', value: '50,000+' },
    { label: 'Accuracy Rate', value: '95.2%' },
    { label: 'Countries Served', value: '25+' },
    { label: 'Healthcare Partners', value: '100+' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Hero Section */}
      <section className="relative overflow-hidden pt-16 pb-32">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <motion.h1
              className="text-4xl sm:text-5xl lg:text-6xl font-bold text-gray-900 mb-6"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
            >
              Digital{' '}
              <span className="text-gradient bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                RDT Reader
              </span>
            </motion.h1>
            
            <motion.p
              className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
            >
              Scan and analyze rapid diagnostic tests with AI-powered image recognition. 
              Get instant results, track your health, and contribute to global health monitoring.
            </motion.p>

            <motion.div
              className="flex flex-col sm:flex-row gap-4 justify-center"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
            >
              <Link to="/register">
                <Button size="lg" className="w-full sm:w-auto">
                  Get Started Free
                </Button>
              </Link>
              <Link to="/login">
                <Button variant="outline" size="lg" className="w-full sm:w-auto">
                  Sign In
                </Button>
              </Link>
            </motion.div>
          </div>
        </div>

        {/* Floating Elements */}
        <div className="absolute top-20 left-10 opacity-20">
          <motion.div
            animate={{ y: [0, -20, 0] }}
            transition={{ duration: 4, repeat: Infinity }}
            className="w-20 h-20 bg-blue-500 rounded-full"
          />
        </div>
        <div className="absolute top-32 right-10 opacity-20">
          <motion.div
            animate={{ y: [0, 20, 0] }}
            transition={{ duration: 3, repeat: Infinity }}
            className="w-16 h-16 bg-purple-500 rounded-full"
          />
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-gray-900 mb-4">
              Why Choose Digital RDT Reader?
            </h2>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Advanced AI technology meets healthcare accessibility to provide accurate, 
              fast, and private diagnostic test analysis.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                className="text-center p-6 rounded-xl bg-gray-50 hover:bg-gray-100 transition-colors"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
              >
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <feature.icon className="w-6 h-6 text-blue-600" />
                </div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  {feature.title}
                </h3>
                <p className="text-gray-600 text-sm">
                  {feature.description}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-20 bg-gradient-to-r from-blue-600 to-purple-600">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                className="text-center"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
              >
                <div className="text-3xl lg:text-4xl font-bold text-white mb-2">
                  {stat.value}
                </div>
                <div className="text-blue-100 text-sm lg:text-base">
                  {stat.label}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-bold text-gray-900 mb-4">
            Ready to Get Started?
          </h2>
          <p className="text-lg text-gray-600 mb-8">
            Join thousands of users who trust Digital RDT Reader for accurate diagnostic test analysis.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link to="/register">
              <Button size="lg" className="w-full sm:w-auto">
                <CheckCircle className="w-5 h-5 mr-2" />
                Start Free Trial
              </Button>
            </Link>
            <Link to="/login">
              <Button variant="outline" size="lg" className="w-full sm:w-auto">
                <Users className="w-5 h-5 mr-2" />
                Healthcare Provider Login
              </Button>
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Home;