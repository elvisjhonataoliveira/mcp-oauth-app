const { verifyAccessToken } = require('./oauth-utils');
const { db } = require('./database');

// Simple in-memory session store
const sessions = new Map();

// Session middleware
function sessionMiddleware(req, res, next) {
  const sessionId = req.headers['x-session-id'] || req.query.session_id;
  
  if (sessionId && sessions.has(sessionId)) {
    req.session = sessions.get(sessionId);
  } else {
    req.session = {};
  }
  
  // Helper to save session
  req.saveSession = () => {
    if (!req.session.id) {
      req.session.id = require('crypto').randomBytes(32).toString('hex');
    }
    sessions.set(req.session.id, req.session);
    return req.session.id;
  };
  
  next();
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Authentication required'
    });
  }
  next();
}

// OAuth2.1 Bearer token middleware
function requireBearerToken(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Bearer token required'
    });
  }
  
  const token = authHeader.slice(7); // Remove 'Bearer ' prefix
  const tokenData = db.findAccessToken(token);
  
  if (!tokenData) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired token'
    });
  }
  
  // Check if token is expired
  if (tokenData.expiresAt < Date.now()) {
    db.deleteAccessToken(token);
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Token expired'
    });
  }
  
  // Verify JWT token
  const decoded = verifyAccessToken(token);
  if (!decoded) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid token signature'
    });
  }
  
  req.tokenData = tokenData;
  req.decodedToken = decoded;
  next();
}

// CORS middleware
function corsMiddleware(req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Session-Id');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
}

// Error handling middleware
function errorHandler(err, req, res, next) {
  console.error('Error:', err);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: err.message
    });
  }
  
  return res.status(500).json({
    error: 'server_error',
    error_description: 'Internal server error'
  });
}

// Request logging middleware
function requestLogger(req, res, next) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - ${req.ip}`);
  next();
}

// Validate client middleware
function validateClient(req, res, next) {
  const clientId = req.body.client_id || req.query.client_id;
  const clientSecret = req.body.client_secret;
  
  if (!clientId) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'client_id is required'
    });
  }
  
  const client = db.findClient(clientId);
  if (!client) {
    return res.status(400).json({
      error: 'invalid_client',
      error_description: 'Invalid client_id'
    });
  }
  
  // For token endpoint, validate client secret
  if (req.path === '/oauth/token' && req.method === 'POST') {
    if (!clientSecret || client.clientSecret !== clientSecret) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }
  }
  
  req.client = client;
  next();
}

module.exports = {
  sessionMiddleware,
  requireAuth,
  requireBearerToken,
  corsMiddleware,
  errorHandler,
  requestLogger,
  validateClient
}; 