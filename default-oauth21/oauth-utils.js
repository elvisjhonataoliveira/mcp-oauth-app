const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production';

// Generate secure random string
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// Generate authorization code
function generateAuthorizationCode() {
  return generateRandomString(32);
}

// Generate access token (JWT)
function generateAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: '1h',
    issuer: 'oauth-server',
    audience: payload.clientId
  });
}

// Generate refresh token
function generateRefreshToken() {
  return generateRandomString(64);
}

// Verify access token
function verifyAccessToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Generate PKCE challenge
function generatePKCEChallenge() {
  const codeVerifier = generateRandomString(32);
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  
  return {
    codeVerifier,
    codeChallenge
  };
}

// Verify PKCE challenge
function verifyPKCEChallenge(codeVerifier, codeChallenge) {
  const computedChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  
  return computedChallenge === codeChallenge;
}

// Build authorization URL
function buildAuthorizationUrl(baseUrl, params) {
  const url = new URL('/oauth/authorize', baseUrl);
  Object.keys(params).forEach(key => {
    if (params[key]) {
      url.searchParams.set(key, params[key]);
    }
  });
  return url.toString();
}

// Parse scopes
function parseScopes(scopeString) {
  if (!scopeString) return [];
  return scopeString.split(' ').filter(scope => scope.length > 0);
}

// Validate redirect URI
function validateRedirectUri(uri, allowedUris) {
  return allowedUris.includes(uri);
}

// OAuth2.1 error responses
const OAuthErrors = {
  INVALID_REQUEST: 'invalid_request',
  UNAUTHORIZED_CLIENT: 'unauthorized_client',
  ACCESS_DENIED: 'access_denied',
  UNSUPPORTED_RESPONSE_TYPE: 'unsupported_response_type',
  INVALID_SCOPE: 'invalid_scope',
  SERVER_ERROR: 'server_error',
  TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',
  INVALID_CLIENT: 'invalid_client',
  INVALID_GRANT: 'invalid_grant',
  UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type'
};

// Create error response
function createErrorResponse(error, description, state = null) {
  const response = {
    error,
    error_description: description
  };
  
  if (state) {
    response.state = state;
  }
  
  return response;
}

// Create authorization response
function createAuthorizationResponse(code, state = null) {
  const response = { code };
  
  if (state) {
    response.state = state;
  }
  
  return response;
}

// Create token response
function createTokenResponse(accessToken, refreshToken, expiresIn = 3600, tokenType = 'Bearer', scope = null) {
  const response = {
    access_token: accessToken,
    token_type: tokenType,
    expires_in: expiresIn
  };
  
  if (refreshToken) {
    response.refresh_token = refreshToken;
  }
  
  if (scope) {
    response.scope = scope;
  }
  
  return response;
}

module.exports = {
  generateRandomString,
  generateAuthorizationCode,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  generatePKCEChallenge,
  verifyPKCEChallenge,
  buildAuthorizationUrl,
  parseScopes,
  validateRedirectUri,
  OAuthErrors,
  createErrorResponse,
  createAuthorizationResponse,
  createTokenResponse
}; 