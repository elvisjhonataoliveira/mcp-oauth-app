const express = require('express');
const crypto = require('crypto');
const database = require('../database');

const router = express.Router();

// Authorization endpoint (RFC 6749 Section 3.1)
router.get('/authorize', (req, res) => {
    const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method
    } = req.query;

    // Validate response_type
    if (response_type !== 'code') {
        return res.status(400).json({
            error: 'unsupported_response_type',
            error_description: 'Only response_type=code is supported'
        });
    }

    // Validate client_id
    if (!client_id) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'client_id parameter is required'
        });
    }

    const client = database.getClientById(client_id);
    if (!client) {
        return res.status(400).json({
            error: 'invalid_client',
            error_description: 'Invalid client_id'
        });
    }

    // Validate redirect_uri
    if (!redirect_uri) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'redirect_uri parameter is required'
        });
    }

    if (!client.redirect_uris.includes(redirect_uri)) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid redirect_uri'
        });
    }

    // OAuth 2.1 requires PKCE for public clients
    if (!code_challenge && client.token_endpoint_auth_method === 'none') {
        const errorParams = new URLSearchParams({
            error: 'invalid_request',
            error_description: 'code_challenge required for public clients',
            state: state || ''
        });
        return res.redirect(`${redirect_uri}?${errorParams}`);
    }

    // Validate PKCE if provided
    if (code_challenge) {
        if (!code_challenge_method) {
            const errorParams = new URLSearchParams({
                error: 'invalid_request',
                error_description: 'code_challenge_method is required when code_challenge is present',
                state: state || ''
            });
            return res.redirect(`${redirect_uri}?${errorParams}`);
        }

        if (!['S256', 'plain'].includes(code_challenge_method)) {
            const errorParams = new URLSearchParams({
                error: 'invalid_request',
                error_description: 'Unsupported code_challenge_method',
                state: state || ''
            });
            return res.redirect(`${redirect_uri}?${errorParams}`);
        }
    }

    // Store authorization request for later processing
    const authRequest = {
        response_type,
        client_id,
        redirect_uri,
        scope: scope || 'read',
        state,
        code_challenge,
        code_challenge_method
    };

    // For this demo, render a simple login form
    res.render('login', {
        authRequest: JSON.stringify(authRequest),
        client: client
    });
});

// Handle login form submission
router.post('/login', (req, res) => {
    const { username, password, authRequest } = req.body;
    
    let parsedAuthRequest;
    try {
        parsedAuthRequest = JSON.parse(authRequest);
    } catch (error) {
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid authorization request'
        });
    }

    // Validate user credentials
    const user = database.validateUserCredentials(username, password);
    if (!user) {
        return res.render('login', {
            authRequest: authRequest,
            client: database.getClientById(parsedAuthRequest.client_id),
            error: 'Invalid username or password'
        });
    }

    // For this demo, automatically grant consent
    // In a real implementation, you would show a consent screen
    const authCode = database.createAuthorizationCode(
        user.id,
        parsedAuthRequest.client_id,
        parsedAuthRequest.redirect_uri,
        parsedAuthRequest.scope,
        parsedAuthRequest.code_challenge,
        parsedAuthRequest.code_challenge_method
    );

    // Redirect back to client with authorization code
    const responseParams = new URLSearchParams({
        code: authCode.code
    });

    if (parsedAuthRequest.state) {
        responseParams.append('state', parsedAuthRequest.state);
    }

    res.redirect(`${parsedAuthRequest.redirect_uri}?${responseParams}`);
});

// Consent endpoint (for explicit consent flow)
router.get('/consent', (req, res) => {
    // This would typically be reached after login
    // For this demo, we'll redirect to login
    res.redirect('/auth/authorize?' + req.url.split('?')[1]);
});

// Logout endpoint
router.post('/logout', (req, res) => {
    // In a real implementation, you would clear session
    res.json({ message: 'Logged out successfully' });
});

module.exports = router; 