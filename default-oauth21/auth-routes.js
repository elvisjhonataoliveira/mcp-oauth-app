const express = require('express');
const { db } = require('./database');
const { requireAuth, requireBearerToken } = require('./middleware');

const router = express.Router();

// Login endpoint
router.post('/login', async (req, res) => {
  const { username, password, session_id } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Username and password are required'
    });
  }

  try {
    // Validate user credentials
    const user = await db.validateUser(username, password);
    
    if (!user) {
      return res.status(401).json({
        error: 'invalid_credentials',
        message: 'Invalid username or password'
      });
    }

    // Store user in session
    req.session.userId = user.id;
    req.session.username = user.username;
    const sessionId = req.saveSession();

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      },
      session_id: sessionId
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'server_error',
      message: 'Internal server error'
    });
  }
});

// Logout endpoint
router.post('/logout', (req, res) => {
  // Clear session
  req.session = {};
  
  res.json({
    message: 'Logout successful'
  });
});

// Get current user info (requires authentication)
router.get('/me', requireAuth, (req, res) => {
  const user = db.findUserById(req.session.userId);
  
  if (!user) {
    return res.status(404).json({
      error: 'user_not_found',
      message: 'User not found'
    });
  }

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName
  });
});

// Check authentication status
router.get('/status', (req, res) => {
  const isAuthenticated = !!req.session.userId;
  
  res.json({
    authenticated: isAuthenticated,
    user: isAuthenticated ? {
      id: req.session.userId,
      username: req.session.username
    } : null
  });
});

// Get user info using access token (OAuth2.1 resource endpoint)
router.get('/userinfo', requireBearerToken, (req, res) => {
  const user = db.findUserById(req.tokenData.userId);
  
  if (!user) {
    return res.status(404).json({
      error: 'user_not_found',
      error_description: 'User not found'
    });
  }

  // Return user info based on granted scopes
  const scopes = req.tokenData.scope ? req.tokenData.scope.split(' ') : [];
  const userInfo = {
    sub: user.id, // Standard OAuth2 claim
  };

  // Add claims based on scopes
  if (scopes.includes('profile') || scopes.includes('read')) {
    userInfo.username = user.username;
    userInfo.given_name = user.firstName;
    userInfo.family_name = user.lastName;
    userInfo.name = `${user.firstName} ${user.lastName}`;
  }

  if (scopes.includes('email')) {
    userInfo.email = user.email;
    userInfo.email_verified = true;
  }

  res.json(userInfo);
});

// List all users (for testing purposes)
router.get('/users', requireAuth, (req, res) => {
  const users = [];
  for (const user of db.users?.values() || []) {
    users.push({
      id: user.id,
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName
    });
  }

  res.json({
    users,
    total: users.length
  });
});

module.exports = router; 