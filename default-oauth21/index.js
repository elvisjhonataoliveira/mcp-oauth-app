const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { initializeDatabase, db } = require('./database');
const {
  sessionMiddleware,
  corsMiddleware,
  errorHandler,
  requestLogger
} = require('./middleware');
const oauthRoutes = require('./oauth-routes');
const authRoutes = require('./auth-routes');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(corsMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(sessionMiddleware);
app.use(requestLogger);

// Routes
app.use('/oauth', oauthRoutes);
app.use('/auth', authRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'OAuth2.1 Server'
  });
});

// Root endpoint with API information
app.get('/', (req, res) => {
  res.json({
    message: 'OAuth2.1 Server',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      authorization: '/oauth/authorize',
      token: '/oauth/token',
      userinfo: '/auth/userinfo',
      login: '/auth/login',
      logout: '/auth/logout',
      me: '/auth/me',
      status: '/auth/status',
      users: '/auth/users'
    },
    documentation: {
      oauth_flow: 'OAuth2.1 Authorization Code Flow with PKCE',
      supported_grant_types: ['authorization_code', 'refresh_token'],
      supported_response_types: ['code'],
      supported_scopes: ['read', 'profile', 'email'],
      pkce_required: true
    },
    example_client: {
      client_id: 'test-client',
      client_secret: 'test-secret',
      redirect_uris: ['http://localhost:3001/callback']
    },
    example_users: [
      { username: 'john.doe', password: 'password123' },
      { username: 'jane.smith', password: 'password123' },
      { username: 'bob.johnson', password: 'password123' }
    ]
  });
});

// Client demo endpoint (for testing purposes)
app.get('/demo', (req, res) => {
  res.json({
    message: 'OAuth2.1 Flow Demo',
    steps: [
      {
        step: 1,
        description: 'Generate PKCE challenge',
        action: 'Client generates code_verifier and code_challenge'
      },
      {
        step: 2,
        description: 'Redirect to authorization endpoint',
        url: '/oauth/authorize',
        required_params: [
          'response_type=code',
          'client_id=test-client',
          'redirect_uri=http://localhost:3001/callback',
          'scope=read profile email',
          'state=random-state-value',
          'code_challenge=PKCE_challenge',
          'code_challenge_method=S256'
        ]
      },
      {
        step: 3,
        description: 'User login',
        url: '/auth/login',
        method: 'POST',
        body: {
          username: 'john.doe',
          password: 'password123',
          session_id: 'session_id_from_step_2'
        }
      },
      {
        step: 4,
        description: 'User consent',
        url: '/oauth/consent',
        method: 'POST',
        body: {
          action: 'allow',
          session_id: 'session_id_from_step_2'
        }
      },
      {
        step: 5,
        description: 'Exchange code for tokens',
        url: '/oauth/token',
        method: 'POST',
        body: {
          grant_type: 'authorization_code',
          client_id: 'test-client',
          client_secret: 'test-secret',
          code: 'authorization_code_from_step_4',
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: 'PKCE_verifier_from_step_1'
        }
      },
      {
        step: 6,
        description: 'Access protected resource',
        url: '/auth/userinfo',
        method: 'GET',
        headers: {
          Authorization: 'Bearer access_token_from_step_5'
        }
      }
    ]
  });
});

// Protected resource example
app.get('/api/protected', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Bearer token required'
    });
  }

  const token = authHeader.slice(7);
  const tokenData = db.findAccessToken(token);

  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.status(401).json({
      error: 'invalid_token',
      message: 'Invalid or expired token'
    });
  }

  const user = db.findUserById(tokenData.userId);
  
  res.json({
    message: 'Access granted to protected resource',
    user: user ? {
      id: user.id,
      username: user.username,
      email: user.email
    } : null,
    scope: tokenData.scope,
    client_id: tokenData.clientId
  });
});

// Error handling middleware (must be last)
app.use(errorHandler);

// Start server
async function startServer() {
  try {
    console.log('Starting OAuth2.1 Server...');
    
    // Initialize database
    await initializeDatabase();
    
    // Clean expired tokens every 5 minutes
    setInterval(() => {
      db.cleanExpiredTokens();
      console.log('Cleaned expired tokens');
    }, 5 * 60 * 1000);

    app.listen(PORT, () => {
      console.log(`\n🚀 OAuth2.1 Server is running on port ${PORT}`);
      console.log(`📍 Server URL: http://localhost:${PORT}`);
      console.log(`📖 API Documentation: http://localhost:${PORT}/`);
      console.log(`🧪 Demo Guide: http://localhost:${PORT}/demo`);
      console.log(`💚 Health Check: http://localhost:${PORT}/health`);
      console.log('\n📋 Available Users:');
      console.log('   - john.doe / password123');
      console.log('   - jane.smith / password123');
      console.log('   - bob.johnson / password123');
      console.log('\n🔑 Test Client:');
      console.log('   - Client ID: test-client');
      console.log('   - Client Secret: test-secret');
      console.log('   - Redirect URI: http://localhost:3001/callback');
      console.log('\n🔒 OAuth2.1 Features:');
      console.log('   ✅ PKCE (Proof Key for Code Exchange)');
      console.log('   ✅ Authorization Code Flow');
      console.log('   ✅ Refresh Token Flow');
      console.log('   ✅ Token Introspection');
      console.log('   ✅ Secure Token Storage');
      console.log('   ✅ Scope-based Access Control');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\n🛑 Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

// Start the server
startServer();

module.exports = app; 