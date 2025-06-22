import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('Starting database seed...');

  // Create admin user
  const adminPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'Admin123!@#', 12);
  
  const admin = await prisma.admin.upsert({
    where: { email: process.env.ADMIN_EMAIL || 'admin@rdtreader.com' },
    update: {},
    create: {
      email: process.env.ADMIN_EMAIL || 'admin@rdtreader.com',
      password: adminPassword,
      name: 'System Administrator',
      role: 'SUPER_ADMIN',
      permissions: [
        'users:read',
        'users:write',
        'users:delete',
        'tests:read',
        'tests:write',
        'tests:delete',
        'analytics:read',
        'system:read',
        'system:write'
      ]
    }
  });

  console.log('Created admin user:', admin.email);

  // Create sample regular users
  const sampleUsers = [
    {
      email: 'john.doe@example.com',
      password: await bcrypt.hash('Password123!', 12),
      name: 'John Doe',
      gender: 'MALE' as const,
      age: 30,
      phone: '+212600000001',
      nationality: 'Morocco'
    },
    {
      email: 'jane.smith@example.com',
      password: await bcrypt.hash('Password123!', 12),
      name: 'Jane Smith',
      gender: 'FEMALE' as const,
      age: 28,
      phone: '+212600000002',
      nationality: 'Morocco'
    },
    {
      email: 'ahmed.benali@example.com',
      password: await bcrypt.hash('Password123!', 12),
      name: 'Ahmed Ben Ali',
      gender: 'MALE' as const,
      age: 35,
      phone: '+212600000003',
      nationality: 'Morocco'
    }
  ];

  const createdUsers = [];
  for (const userData of sampleUsers) {
    const user = await prisma.user.upsert({
      where: { email: userData.email },
      update: {},
      create: {
        ...userData,
        isVerified: true
      }
    });
    createdUsers.push(user);
    console.log('Created user:', user.email);
  }

  // Create sample tests
  const testTypes = ['COVID_19', 'PREGNANCY', 'INFLUENZA_A', 'STREP_A'] as const;
  const testResults = ['POSITIVE', 'NEGATIVE', 'INVALID'] as const;
  const locations = [
    { name: 'Casablanca', lat: 33.5731, lng: -7.5898 },
    { name: 'Rabat', lat: 34.0209, lng: -6.8416 },
    { name: 'Marrakech', lat: 31.6295, lng: -7.9811 },
    { name: 'Fez', lat: 34.0181, lng: -5.0078 }
  ];

  for (let i = 0; i < 50; i++) {
    const randomUser = createdUsers[Math.floor(Math.random() * createdUsers.length)];
    const randomTestType = testTypes[Math.floor(Math.random() * testTypes.length)];
    const randomResult = testResults[Math.floor(Math.random() * testResults.length)];
    const randomLocation = locations[Math.floor(Math.random() * locations.length)];
    
    // Generate random date within last 30 days
    const randomDate = new Date();
    randomDate.setDate(randomDate.getDate() - Math.floor(Math.random() * 30));

    if (randomUser && randomTestType && randomResult && randomLocation) {
      const test = await prisma.test.create({
        data: {
          userId: randomUser.id,
          testType: randomTestType,
          result: randomResult,
          confidence: Math.random() * 0.3 + 0.7, // 0.7 to 1.0
          latitude: randomLocation.lat + (Math.random() - 0.5) * 0.1, // Add some variation
          longitude: randomLocation.lng + (Math.random() - 0.5) * 0.1,
          location: randomLocation.name,
          testDate: randomDate,
          isAnonymous: Math.random() > 0.8, // 20% anonymous
          isReported: randomResult === 'POSITIVE' ? Math.random() > 0.3 : false // 70% of positive tests reported
        }
      });

      if (i % 10 === 0) {
        console.log(`Created ${i + 1} sample tests...`);
      }
    }
  }

  console.log('Created 50 sample tests');

  // Create sample alerts
  const alerts = [
    {
      type: 'HIGH_POSITIVITY_RATE' as const,
      title: 'High Positivity Rate Alert',
      message: 'COVID-19 positivity rate has exceeded 15% in Casablanca region',
      severity: 'HIGH' as const,
      location: 'Casablanca',
      coordinates: JSON.stringify({ lat: 33.5731, lng: -7.5898 }),
      metadata: JSON.stringify({
        positivityRate: 18.5,
        testCount: 120,
        positiveCount: 22
      })
    },
    {
      type: 'OUTBREAK' as const,
      title: 'Potential Outbreak Detected',
      message: 'Unusual cluster of positive tests detected in Rabat',
      severity: 'CRITICAL' as const,
      location: 'Rabat',
      coordinates: JSON.stringify({ lat: 34.0209, lng: -6.8416 }),
      metadata: JSON.stringify({
        clusterSize: 8,
        timeframe: '48 hours',
        radius: '2km'
      })
    }
  ];

  for (const alertData of alerts) {
    const alert = await prisma.alert.create({
      data: alertData
    });
    console.log('Created alert:', alert.title);
  }

  console.log('Database seed completed successfully!');
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error('Error during seeding:', e);
    await prisma.$disconnect();
    process.exit(1);
  });