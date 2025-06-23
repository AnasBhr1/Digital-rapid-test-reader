# 🔬 Digital Rapid Diagnostic Test Reader

A modern web and mobile-friendly application that allows users to scan their rapid diagnostic tests (RDTs) using AI-powered image recognition, automatically detect results, and store/display data for both users and health authorities.

## 🚀 Features

### 👨‍👩‍👧‍👦 End Users
- **📱 Smart Test Scanning**: Use phone camera or webcam to scan RDTs
- **🤖 AI-Powered Detection**: Automatically detect test results (positive/negative/invalid)
- **📊 Result Display**: Clear result presentation with confidence scores
- **💡 Health Guidance**: Prevention tips and next steps based on results
- **🌍 Multi-language Support**: Arabic, French, and English
- **📈 Test History**: Track and view all previous tests
- **🔒 Privacy Controls**: Anonymous testing options

### 👩‍⚕️ Health Authorities & Admins
- **📊 Admin Dashboard**: Comprehensive analytics and insights
- **🗺️ Geographic Mapping**: Dynamic maps showing positive cases by location
- **📤 Data Export**: CSV export and API access for health data
- **🚨 Alert System**: Automated alerts for disease outbreaks or spikes
- **👥 User Management**: Manage users and their data
- **📈 Advanced Analytics**: Detailed statistics and trend analysis

### 🛡️ Security & Privacy
- **✅ GDPR Compliant**: Full compliance with data protection regulations
- **🔐 Data Encryption**: All sensitive data encrypted at rest and in transit
- **👤 User Consent**: Explicit consent for data collection and usage
- **🗑️ Data Control**: Users can delete or anonymize their data
- **🚫 No Discrimination**: Data cannot be used for law enforcement or discrimination

## 🏗️ Technology Stack

### Frontend
- **React 18** with TypeScript
- **Tailwind CSS** for styling
- **Framer Motion** for animations
- **React Query** for data fetching
- **React Hook Form** for form management
- **PWA Support** for mobile app-like experience

### Backend
- **Node.js** with Express and TypeScript
- **PostgreSQL** with Prisma ORM
- **JWT Authentication** with refresh tokens
- **File Upload** with image processing
- **Rate Limiting** and security middleware
- **Scheduled Tasks** for data cleanup

### Infrastructure
- **Docker** support for containerization
- **Vercel** deployment for frontend
- **Railway/Render** deployment for backend
- **Database** hosting on PlanetScale/Neon

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- PostgreSQL database
- Git

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd digital-rapid-test-reader
```

### 2. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env file with your configuration
# Set DATABASE_URL, JWT secrets, etc.

# Generate Prisma client
npx prisma generate

# Run database migrations
npx prisma migrate dev

# Seed the database (optional)
npx prisma db seed

# Start development server
npm run dev
```

The backend will be running at `http://localhost:3001`

### 3. Frontend Setup
```bash
# Navigate to frontend directory (from root)
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will be running at `http://localhost:5173`

### 4. Access the Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:3001/api
- **API Health Check**: http://localhost:3001/health

### 5. Default Admin Credentials
- **Email**: admin@rdtreader.com
- **Password**: Admin123!@# (change this in production!)

## 📱 PWA Installation

The app can be installed on mobile devices:

1. Open the app in your mobile browser
2. Look for the "Add to Home Screen" option
3. Follow the installation prompts
4. The app will be available like a native mobile app

## 🔧 Configuration

### Environment Variables

#### Backend (.env)
```bash
# Database
DATABASE_URL="postgresql://username:password@localhost:5432/rdt_reader"

# JWT Secrets (generate strong secrets!)
JWT_SECRET="your-super-secret-jwt-key"
JWT_REFRESH_SECRET="your-super-secret-refresh-key"

# Server
PORT=3001
NODE_ENV=development

# CORS
CORS_ORIGINS="http://localhost:5173,http://localhost:3000"

# Admin
ADMIN_EMAIL=admin@rdtreader.com
ADMIN_PASSWORD=change-this-secure-password
```

#### Frontend (.env)
```bash
VITE_API_URL=http://localhost:3001/api
```

## 🧪 Testing

### Backend Tests
```bash
cd backend
npm test
```

### Frontend Tests
```bash
cd frontend
npm test
```

### API Testing
Use the provided Postman collection or test manually:

```bash
# Health check
curl http://localhost:3001/health

# Register user
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Password123!","name":"Test User","gender":"MALE","age":25}'
```

## 🚀 Deployment

### Backend Deployment (Railway/Render)

1. **Create account** on Railway or Render
2. **Connect your GitHub** repository
3. **Configure environment variables**:
   - DATABASE_URL (from your database provider)
   - JWT_SECRET and JWT_REFRESH_SECRET (generate strong secrets)
   - NODE_ENV=production
   - All other production variables
4. **Deploy** the backend service

### Frontend Deployment (Vercel)

1. **Create account** on Vercel
2. **Connect your GitHub** repository
3. **Configure build settings**:
   - Framework: Vite
   - Root Directory: frontend
   - Build Command: npm run build
   - Output Directory: frontend/dist
4. **Set environment variables**:
   - VITE_API_URL (your deployed backend URL)
5. **Deploy** the frontend

### Database Deployment (PlanetScale/Neon)

1. **Create account** on PlanetScale or Neon
2. **Create a new database**
3. **Get the connection string**
4. **Update DATABASE_URL** in your backend environment
5. **Run migrations** in production:
   ```bash
   npx prisma migrate deploy
   ```

## 📊 Database Schema

The application uses the following main entities:

- **Users**: User accounts and profiles
- **Tests**: RDT test results and metadata
- **Admins**: Admin users with permissions
- **RefreshTokens**: JWT refresh token management
- **Alerts**: System alerts and notifications

See `backend/prisma/schema.prisma` for the complete schema.

## 🛡️ Security Features

- **JWT Authentication** with access and refresh tokens
- **Password Hashing** with bcrypt (12 rounds)
- **Rate Limiting** to prevent abuse
- **Input Validation** on all endpoints
- **CORS Protection** for cross-origin requests
- **Helmet.js** for security headers
- **File Upload Validation** for image processing
- **SQL Injection Prevention** via Prisma ORM

## 🌍 Multi-language Support

The app supports:
- **English** (default)
- **Arabic** (عربي)
- **French** (Français)

Language files are located in `frontend/src/locales/`

## 📱 Mobile Features

- **Responsive Design** optimized for mobile
- **Camera Integration** for test scanning
- **Offline Support** via PWA
- **Touch-friendly** UI components
- **Fast Loading** with optimized assets

## 🔄 API Documentation

### Authentication Endpoints
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh-token` - Refresh access token
- `POST /api/auth/logout` - User logout
- `GET /api/auth/profile` - Get user profile
- `PUT /api/auth/profile` - Update user profile

### Test Endpoints
- `POST /api/tests` - Create new test (with image upload)
- `GET /api/tests` - Get user's tests
- `GET /api/tests/:id` - Get specific test
- `PUT /api/tests/:id` - Update test
- `DELETE /api/tests/:id` - Delete test
- `GET /api/tests/stats` - Get user test statistics

### Admin Endpoints
- `POST /api/admin/login` - Admin login
- `GET /api/admin/dashboard/stats` - Dashboard statistics
- `GET /api/admin/users` - Get all users
- `GET /api/admin/tests` - Get all tests
- `GET /api/admin/export` - Export data

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 🆘 Support

For support and questions:
- 📧 Email: Anasbhr1@hotmail.com
- 🐛 Issues: [GitHub Issues]

## 🙏 Acknowledgments

- Healthcare workers and researchers fighting diseases worldwide
- Open source contributors and maintainers
- The React, Node.js, and TypeScript communities
- AI/ML researchers advancing medical image recognition

---

Made by Anas with ❤️ for global health and well-being