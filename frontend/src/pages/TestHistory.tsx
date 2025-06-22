import React from 'react';
import { motion } from 'framer-motion';
import { History, Calendar, MapPin } from 'lucide-react';

const TestHistory: React.FC = () => {
  const mockTests = [
    {
      id: '1',
      type: 'COVID-19',
      result: 'Negative',
      date: '2024-01-15',
      location: 'Casablanca, Morocco',
      confidence: 95
    },
    {
      id: '2',
      type: 'Influenza A',
      result: 'Positive',
      date: '2024-01-10',
      location: 'Rabat, Morocco',
      confidence: 88
    }
  ];

  return (
    <div className="max-w-4xl mx-auto">
      <motion.div
        className="mb-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <h1 className="text-3xl font-bold text-gray-900 mb-4">
          Test History
        </h1>
        <p className="text-gray-600">
          View and manage your previous test results
        </p>
      </motion.div>

      <div className="space-y-4">
        {mockTests.map((test, index) => (
          <motion.div
            key={test.id}
            className="bg-white rounded-xl shadow-soft p-6"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: index * 0.1 }}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mr-4">
                  <History className="w-6 h-6 text-blue-600" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{test.type} Test</h3>
                  <div className="flex items-center text-sm text-gray-500 mt-1">
                    <Calendar className="w-4 h-4 mr-1" />
                    {test.date}
                    <MapPin className="w-4 h-4 ml-4 mr-1" />
                    {test.location}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                  test.result === 'Negative' 
                    ? 'bg-green-100 text-green-800' 
                    : 'bg-red-100 text-red-800'
                }`}>
                  {test.result}
                </span>
                <p className="text-sm text-gray-500 mt-1">
                  {test.confidence}% confidence
                </p>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

export default TestHistory;