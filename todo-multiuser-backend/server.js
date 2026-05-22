require('dotenv').config();
const express = require('express');
const cors = require('cors');
const passport = require('./config/passport');
const { testConnection } = require('./config/database');
const { rateLimiters, securityHeaders, sanitizeInput, securityLogger } = require('./middleware/security');

const app = express();

// Trust proxy for Render
app.set('trust proxy', 1);

// Apply security middleware
app.use(securityHeaders);
app.use(securityLogger);

app.use(express.json({ limit: '10mb' }));
app.use(sanitizeInput);
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || 'http://localhost:5173',
    'https://stupendous-nougat-5e23b1.netlify.app',
    'https://dulcet-custard-82202d.netlify.app',
    'https://tubular-concha-16bda1.netlify.app',
    'https://multiuser-todo.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.disable('x-powered-by');

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Initialize Passport
app.use(passport.initialize());

// Test PostgreSQL connection
testConnection();

// Debug: Log environment variables
console.log('🔍 Environment check:');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? 'Set' : 'Missing');
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? 'Set' : 'Missing');
console.log('BACKEND_URL:', process.env.BACKEND_URL);
console.log('FRONTEND_URL:', process.env.FRONTEND_URL);
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'Set' : 'Missing');
console.log('SUPABASE_URL:', process.env.SUPABASE_URL ? 'Set' : 'Missing');

// Import and use superadmin routes
const superadminRoutes = require('./routes/superadmin.js');
app.use('/api/superadmin', superadminRoutes);

// Import and use auth routes
try {
  const authRoutes = require('./routes/auth.js');
  // Apply rate limiting to auth routes
  app.use('/api/auth/login', rateLimiters.auth);
  app.use('/api/auth/admin/login', rateLimiters.auth);
  app.use('/api/auth/register', rateLimiters.auth);
  app.use('/api/auth/admin/register', rateLimiters.auth);
  app.use('/api/auth/forgot-password', rateLimiters.passwordReset);
  app.use('/api/auth/reset-password', rateLimiters.passwordReset);
  
  app.use('/api/auth', authRoutes);
  console.log('✅ Auth routes loaded successfully');
} catch (error) {
  console.error('❌ Error loading auth routes:', error.message);
}

// Import and use task routes
const taskRoutes = require('./routes/task.js');
app.use('/api/tasks', taskRoutes);

// Import and use notification routes
const notificationRoutes = require('./routes/notification.js');
app.use('/api/notifications', notificationRoutes);

// 404 handler (should be after all real routes)
app.use((req, res, next) => {
  res.status(404).send("Sorry, can't find that!");
});

// Global error handler (should be last)
app.use((err, req, res, next) => {
  console.error('💥 Global error handler:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method
  });
  
  // Don't expose error details in production
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ message: 'Internal server error' });
  } else {
    res.status(500).json({ 
      message: err.message,
      stack: err.stack 
    });
  }
});

const PORT = process.env.PORT || 5500;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));

// Schedule daily cleanup of old completed tasks (runs at 2 AM daily)
const { cleanupApprovedTasks } = require('./utils/taskCleanup');

setInterval(async () => {
  const now = new Date();
  if (now.getHours() === 2 && now.getMinutes() === 0) {
    console.log('🕐 Running scheduled cleanup...');
    try {
      const result = await cleanupApprovedTasks();
      console.log(`✅ Cleanup completed: ${result.deletedCount} tasks deleted`);
    } catch (error) {
      console.error('❌ Scheduled cleanup failed:', error);
    }
  }
}, 60000);

console.log('⏰ Scheduled task cleanup enabled (runs daily at 2 AM)');
