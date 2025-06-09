const express = require('express');
const { db } = require('./database');
const {
  generateAuthorizationCode,
  generateAccessToken,
  generateRefreshToken,
  verifyPKCEChallenge,
  parseScopes,
  validateRedirectUri,
  OAuthErrors,
  createErrorResponse,
  createAuthorizationResponse,
  createTokenResponse
} = require('./oauth-utils');
const { validateClient, requireBearerToken } = require('./middleware');

const router = express.Router();

// OAuth2.1 Authorization endpoint
router.get('/authorize', validateClient, (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method
  } = req.query;

  try {
    // Validate response_type (OAuth2.1 only supports 'code')
    if (response_type !== 'code') {
      const error = createErrorResponse(
        OAuthErrors.UNSUPPORTED_RESPONSE_TYPE,
        'Only authorization code flow is supported',
        state
      );
      return res.status(400).json(error);
    }

    // Validate redirect_uri
    if (!redirect_uri || !validateRedirectUri(redirect_uri, req.client.redirectUris)) {
      const error = createErrorResponse(
        OAuthErrors.INVALID_REQUEST,
        'Invalid redirect_uri',
        state
      );
      return res.status(400).json(error);
    }

    // Validate PKCE (OAuth2.1 requirement)
    if (!code_challenge || !code_challenge_method) {
      const error = createErrorResponse(
        OAuthErrors.INVALID_REQUEST,
        'PKCE code_challenge and code_challenge_method are required',
        state
      );
      return res.status(400).json(error);
    }

    if (code_challenge_method !== 'S256') {
      const error = createErrorResponse(
        OAuthErrors.INVALID_REQUEST,
        'Only S256 code_challenge_method is supported',
        state
      );
      return res.status(400).json(error);
    }

    // Store authorization request in session
    const sessionId = req.saveSession();
    req.session.authRequest = {
      client_id,
      redirect_uri,
      scope: scope || 'read',
      state,
      code_challenge,
      code_challenge_method
    };
    req.saveSession();

    // Return login page info (in a real app, this would render a login page)
    res.json({
      message: 'Authorization required',
      login_url: `/auth/login?session_id=${sessionId}`,
      client: {
        name: req.client.name,
        description: req.client.description
      },
      scope: parseScopes(scope || 'read'),
      session_id: sessionId
    });

  } catch (error) {
    console.error('Authorization error:', error);
    const errorResponse = createErrorResponse(
      OAuthErrors.SERVER_ERROR,
      'Internal server error',
      state
    );
    return res.status(500).json(errorResponse);
  }
});

// Token endpoint
router.post('/token', validateClient, async (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    code_verifier,
    refresh_token
  } = req.body;

  try {
    if (grant_type === 'authorization_code') {
      // Authorization code grant
      if (!code || !redirect_uri || !code_verifier) {
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_REQUEST,
          'Missing required parameters'
        ));
      }

      // Find authorization code
      const authData = db.findAuthorizationCode(code);
      if (!authData) {
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_GRANT,
          'Invalid authorization code'
        ));
      }

      // Check if code is expired
      if (authData.expiresAt < Date.now()) {
        db.deleteAuthorizationCode(code);
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_GRANT,
          'Authorization code expired'
        ));
      }

      // Validate client and redirect URI
      if (authData.clientId !== req.client.clientId || 
          authData.redirectUri !== redirect_uri) {
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_GRANT,
          'Invalid client or redirect URI'
        ));
      }

      // Verify PKCE
      if (!verifyPKCEChallenge(code_verifier, authData.codeChallenge)) {
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_GRANT,
          'Invalid PKCE challenge'
        ));
      }

      // Generate tokens
      const tokenPayload = {
        userId: authData.userId,
        clientId: authData.clientId,
        scope: authData.scope
      };

      const accessToken = generateAccessToken(tokenPayload);
      const refreshTokenValue = generateRefreshToken();

      // Store tokens
      db.storeAccessToken(accessToken, tokenPayload);
      db.storeRefreshToken(refreshTokenValue, tokenPayload);

      // Delete used authorization code
      db.deleteAuthorizationCode(code);

      const tokenResponse = createTokenResponse(
        accessToken,
        refreshTokenValue,
        3600,
        'Bearer',
        authData.scope
      );

      return res.json(tokenResponse);

    } else if (grant_type === 'refresh_token') {
      // Refresh token grant
      if (!refresh_token) {
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_REQUEST,
          'refresh_token is required'
        ));
      }

      const refreshData = db.findRefreshToken(refresh_token);
      if (!refreshData) {
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_GRANT,
          'Invalid refresh token'
        ));
      }

      // Check if refresh token is expired
      if (refreshData.expiresAt < Date.now()) {
        db.deleteRefreshToken(refresh_token);
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_GRANT,
          'Refresh token expired'
        ));
      }

      // Validate client
      if (refreshData.clientId !== req.client.clientId) {
        return res.status(400).json(createErrorResponse(
          OAuthErrors.INVALID_GRANT,
          'Invalid client'
        ));
      }

      // Generate new access token
      const tokenPayload = {
        userId: refreshData.userId,
        clientId: refreshData.clientId,
        scope: refreshData.scope
      };

      const accessToken = generateAccessToken(tokenPayload);
      const newRefreshToken = generateRefreshToken();

      // Store new tokens and delete old refresh token
      db.storeAccessToken(accessToken, tokenPayload);
      db.storeRefreshToken(newRefreshToken, tokenPayload);
      db.deleteRefreshToken(refresh_token);

      const tokenResponse = createTokenResponse(
        accessToken,
        newRefreshToken,
        3600,
        'Bearer',
        refreshData.scope
      );

      return res.json(tokenResponse);

    } else {
      return res.status(400).json(createErrorResponse(
        OAuthErrors.UNSUPPORTED_GRANT_TYPE,
        'Unsupported grant type'
      ));
    }

  } catch (error) {
    console.error('Token error:', error);
    return res.status(500).json(createErrorResponse(
      OAuthErrors.SERVER_ERROR,
      'Internal server error'
    ));
  }
});

// Consent endpoint (handles user authorization)
router.post('/consent', (req, res) => {
  const { action, session_id } = req.body;

  if (!req.session.authRequest) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'No authorization request found'
    });
  }

  if (!req.session.userId) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'User not authenticated'
    });
  }

  const { authRequest } = req.session;

  if (action === 'deny') {
    // User denied authorization
    const redirectUrl = new URL(authRequest.redirect_uri);
    const error = createErrorResponse(
      OAuthErrors.ACCESS_DENIED,
      'User denied authorization',
      authRequest.state
    );
    
    Object.keys(error).forEach(key => {
      redirectUrl.searchParams.set(key, error[key]);
    });

    return res.json({
      redirect_url: redirectUrl.toString()
    });
  }

  if (action === 'allow') {
    // Generate authorization code
    const code = generateAuthorizationCode();
    
    // Store authorization code
    db.storeAuthorizationCode(code, {
      userId: req.session.userId,
      clientId: authRequest.client_id,
      redirectUri: authRequest.redirect_uri,
      scope: authRequest.scope,
      codeChallenge: authRequest.code_challenge
    });

    // Create authorization response
    const redirectUrl = new URL(authRequest.redirect_uri);
    const authResponse = createAuthorizationResponse(code, authRequest.state);
    
    Object.keys(authResponse).forEach(key => {
      redirectUrl.searchParams.set(key, authResponse[key]);
    });

    // Clear session
    delete req.session.authRequest;
    req.saveSession();

    return res.json({
      redirect_url: redirectUrl.toString()
    });
  }

  return res.status(400).json({
    error: 'invalid_request',
    message: 'Invalid action'
  });
});

// Token introspection endpoint
router.post('/introspect', requireBearerToken, (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'token parameter is required'
    });
  }

  const tokenData = db.findAccessToken(token);
  
  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.json({ active: false });
  }

  const user = db.findUserById(tokenData.userId);
  
  res.json({
    active: true,
    client_id: tokenData.clientId,
    username: user ? user.username : null,
    scope: tokenData.scope,
    exp: Math.floor(tokenData.expiresAt / 1000),
    iat: Math.floor(tokenData.createdAt / 1000)
  });
});

module.exports = router; 