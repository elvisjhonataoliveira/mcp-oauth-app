const express = require('express');
const crypto = require('crypto');
const database = require('../database');

const router = express.Router();

// Token endpoint (RFC 6749 Section 3.2)
router.post('/token', (req, res) => {
    const { grant_type } = req.body;

    switch (grant_type) {
        case 'authorization_code':
            return handleAuthorizationCodeGrant(req, res);
        case 'refresh_token':
            return handleRefreshTokenGrant(req, res);
        default:
            return res.status(400).json({
                error: 'unsupported_grant_type',
                error_description: `Grant type '${grant_type}' is not supported`
            });
    }
});

// Authorization Code Grant
function handleAuthorizationCodeGrant(req, res) {
    const {
        code,
        redirect_uri,
        client_id,
        code_verifier
    } = req.body;

    // Validate required parameters
    if (!code) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'code parameter is required'
        });
    }

    if (!redirect_uri) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'redirect_uri parameter is required'
        });
    }

    // Authenticate client
    const client = authenticateClient(req);
    if (!client) {
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Client authentication failed'
        });
    }

    // Validate authorization code
    const authCode = database.getAuthorizationCode(code);
    if (!authCode) {
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid authorization code'
        });
    }

    // Check if code is expired
    if (Date.now() > authCode.expires_at) {
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Authorization code has expired'
        });
    }

    // Check if code is already used
    if (authCode.used) {
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Authorization code has already been used'
        });
    }

    // Validate client_id matches
    if (authCode.client_id !== client.client_id) {
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Authorization code was not issued to this client'
        });
    }

    // Validate redirect_uri matches
    if (authCode.redirect_uri !== redirect_uri) {
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'redirect_uri does not match'
        });
    }

    // Validate PKCE if code_challenge was used
    if (authCode.code_challenge) {
        if (!code_verifier) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'code_verifier is required'
            });
        }

        const isValidChallenge = validatePKCE(
            code_verifier,
            authCode.code_challenge,
            authCode.code_challenge_method
        );

        if (!isValidChallenge) {
            return res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Invalid code_verifier'
            });
        }
    }

    // Mark authorization code as used
    database.useAuthorizationCode(code);

    // Generate tokens
    const accessToken = database.createAccessToken(
        authCode.user_id,
        authCode.client_id,
        authCode.scope
    );

    const refreshToken = database.createRefreshToken(
        authCode.user_id,
        authCode.client_id,
        authCode.scope
    );

    // Return token response
    res.json({
        access_token: accessToken.access_token,
        token_type: accessToken.token_type,
        expires_in: Math.floor((accessToken.expires_at - Date.now()) / 1000),
        refresh_token: refreshToken.refresh_token,
        scope: authCode.scope
    });
}

// Refresh Token Grant
function handleRefreshTokenGrant(req, res) {
    const { refresh_token, scope } = req.body;

    if (!refresh_token) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'refresh_token parameter is required'
        });
    }

    // Authenticate client
    const client = authenticateClient(req);
    if (!client) {
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Client authentication failed'
        });
    }

    // Validate refresh token
    const storedRefreshToken = database.getRefreshToken(refresh_token);
    if (!storedRefreshToken) {
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid refresh token'
        });
    }

    // Check if refresh token is expired
    if (Date.now() > storedRefreshToken.expires_at) {
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Refresh token has expired'
        });
    }

    // Validate client_id matches
    if (storedRefreshToken.client_id !== client.client_id) {
        return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Refresh token was not issued to this client'
        });
    }

    // Validate scope (if provided, must be subset of original scope)
    const requestedScope = scope || storedRefreshToken.scope;
    if (!isSubsetScope(requestedScope, storedRefreshToken.scope)) {
        return res.status(400).json({
            error: 'invalid_scope',
            error_description: 'Requested scope exceeds originally granted scope'
        });
    }

    // Generate new access token
    const accessToken = database.createAccessToken(
        storedRefreshToken.user_id,
        storedRefreshToken.client_id,
        requestedScope
    );

    // Return token response
    res.json({
        access_token: accessToken.access_token,
        token_type: accessToken.token_type,
        expires_in: Math.floor((accessToken.expires_at - Date.now()) / 1000),
        scope: requestedScope
    });
}

// Token introspection endpoint (RFC 7662)
router.post('/introspect', (req, res) => {
    const { token, token_type_hint } = req.body;

    if (!token) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'token parameter is required'
        });
    }

    // Authenticate client (required for introspection)
    const client = authenticateClient(req);
    if (!client) {
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Client authentication failed'
        });
    }

    // Introspect token
    const introspectionResult = database.introspectToken(token);
    res.json(introspectionResult);
});

// Token revocation endpoint (RFC 7009)
router.post('/revoke', (req, res) => {
    const { token, token_type_hint } = req.body;

    if (!token) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'token parameter is required'
        });
    }

    // Authenticate client (required for revocation)
    const client = authenticateClient(req);
    if (!client) {
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Client authentication failed'
        });
    }

    // Revoke token
    const revoked = database.revokeToken(token);
    
    // RFC 7009: Return 200 regardless of whether token was found
    res.status(200).end();
});

// Helper function to authenticate client
function authenticateClient(req) {
    const authHeader = req.headers.authorization;
    let clientId, clientSecret;

    if (authHeader && authHeader.startsWith('Basic ')) {
        // client_secret_basic authentication
        const credentials = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
        const [id, secret] = credentials.split(':');
        clientId = decodeURIComponent(id);
        clientSecret = decodeURIComponent(secret);
    } else {
        // client_secret_post authentication
        clientId = req.body.client_id;
        clientSecret = req.body.client_secret;
    }

    if (!clientId || !clientSecret) {
        return null;
    }

    return database.validateClientCredentials(clientId, clientSecret);
}

// Helper function to validate PKCE
function validatePKCE(codeVerifier, codeChallenge, method) {
    if (method === 'plain') {
        return codeVerifier === codeChallenge;
    } else if (method === 'S256') {
        const hash = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
        return hash === codeChallenge;
    }
    return false;
}

// Helper function to check if requested scope is subset of granted scope
function isSubsetScope(requestedScope, grantedScope) {
    const requestedScopes = requestedScope.split(' ');
    const grantedScopes = grantedScope.split(' ');
    
    return requestedScopes.every(scope => grantedScopes.includes(scope));
}

module.exports = router; 