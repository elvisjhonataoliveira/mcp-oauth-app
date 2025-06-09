const express = require('express');
const { v4: uuidv4 } = require('uuid');
const database = require('../database');

const router = express.Router();

// Dynamic Client Registration Protocol (RFC 7591)
router.post('/register', (req, res) => {
    try {
        const {
            redirect_uris,
            client_name,
            client_uri,
            logo_uri,
            scope,
            contacts,
            tos_uri,
            policy_uri,
            jwks_uri,
            jwks,
            software_id,
            software_version,
            token_endpoint_auth_method,
            grant_types,
            response_types,
            client_secret
        } = req.body;

        // Validate required fields
        if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
            return res.status(400).json({
                error: 'invalid_redirect_uri',
                error_description: 'redirect_uris is required and must be a non-empty array'
            });
        }

        // Validate redirect URIs
        for (const uri of redirect_uris) {
            try {
                const url = new URL(uri);
                // OAuth 2.1 security: reject localhost and non-HTTPS URIs in production
                if (process.env.NODE_ENV === 'production') {
                    if (url.protocol !== 'https:' && url.hostname !== 'localhost') {
                        return res.status(400).json({
                            error: 'invalid_redirect_uri',
                            error_description: 'Only HTTPS redirect URIs are allowed in production'
                        });
                    }
                }
            } catch (error) {
                return res.status(400).json({
                    error: 'invalid_redirect_uri',
                    error_description: `Invalid redirect URI: ${uri}`
                });
            }
        }

        // Validate grant types
        const supportedGrantTypes = ['authorization_code', 'refresh_token'];
        const clientGrantTypes = grant_types || ['authorization_code'];
        
        for (const grantType of clientGrantTypes) {
            if (!supportedGrantTypes.includes(grantType)) {
                return res.status(400).json({
                    error: 'invalid_grant_type',
                    error_description: `Unsupported grant type: ${grantType}`
                });
            }
        }

        // Validate response types
        const supportedResponseTypes = ['code'];
        const clientResponseTypes = response_types || ['code'];
        
        for (const responseType of clientResponseTypes) {
            if (!supportedResponseTypes.includes(responseType)) {
                return res.status(400).json({
                    error: 'invalid_response_type',
                    error_description: `Unsupported response type: ${responseType}`
                });
            }
        }

        // Generate client credentials
        const clientId = uuidv4();
        const clientSecret = client_secret || uuidv4();

        // Create client
        const client = database.createClient({
            client_name: client_name || 'Unnamed Client',
            client_secret: clientSecret,
            redirect_uris: redirect_uris,
            client_uri: client_uri,
            logo_uri: logo_uri,
            scope: scope || 'read',
            contacts: contacts,
            tos_uri: tos_uri,
            policy_uri: policy_uri,
            jwks_uri: jwks_uri,
            jwks: jwks,
            software_id: software_id,
            software_version: software_version,
            token_endpoint_auth_method: token_endpoint_auth_method || 'client_secret_basic',
            grant_types: clientGrantTypes,
            response_types: clientResponseTypes
        });

        // Prepare response (RFC 7591 Section 3.2.1)
        const response = {
            client_id: client.client_id,
            client_secret: clientSecret, // Return plaintext secret only once
            client_id_issued_at: client.created_at,
            client_secret_expires_at: 0, // 0 means never expires
            redirect_uris: client.redirect_uris,
            token_endpoint_auth_method: client.token_endpoint_auth_method,
            grant_types: client.grant_types,
            response_types: client.response_types,
            client_name: client.client_name,
            scope: client.scope
        };

        // Include optional fields if provided
        if (client.client_uri) response.client_uri = client.client_uri;
        if (client.logo_uri) response.logo_uri = client.logo_uri;
        if (client.contacts) response.contacts = client.contacts;
        if (client.tos_uri) response.tos_uri = client.tos_uri;
        if (client.policy_uri) response.policy_uri = client.policy_uri;
        if (client.jwks_uri) response.jwks_uri = client.jwks_uri;
        if (client.jwks) response.jwks = client.jwks;
        if (client.software_id) response.software_id = client.software_id;
        if (client.software_version) response.software_version = client.software_version;

        res.status(201).json(response);

    } catch (error) {
        console.error('Client registration error:', error);
        res.status(500).json({
            error: 'server_error',
            error_description: 'An internal server error occurred during client registration'
        });
    }
});

// Client Configuration Endpoint (RFC 7592)
router.get('/:client_id', authenticateClient, (req, res) => {
    const client = req.client;
    
    const response = {
        client_id: client.client_id,
        client_id_issued_at: client.created_at,
        client_secret_expires_at: 0,
        redirect_uris: client.redirect_uris,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        grant_types: client.grant_types,
        response_types: client.response_types,
        client_name: client.client_name,
        scope: client.scope
    };

    // Include optional fields if present
    if (client.client_uri) response.client_uri = client.client_uri;
    if (client.logo_uri) response.logo_uri = client.logo_uri;
    if (client.contacts) response.contacts = client.contacts;
    if (client.tos_uri) response.tos_uri = client.tos_uri;
    if (client.policy_uri) response.policy_uri = client.policy_uri;
    if (client.jwks_uri) response.jwks_uri = client.jwks_uri;
    if (client.software_id) response.software_id = client.software_id;
    if (client.software_version) response.software_version = client.software_version;

    res.json(response);
});

// Update client configuration (RFC 7592)
router.put('/:client_id', authenticateClient, (req, res) => {
    // In a real implementation, you would update the client configuration
    // For this demo, we'll return the current configuration
    res.status(501).json({
        error: 'unsupported_operation',
        error_description: 'Client configuration updates are not supported in this implementation'
    });
});

// Delete client (RFC 7592)
router.delete('/:client_id', authenticateClient, (req, res) => {
    // In a real implementation, you would delete the client
    res.status(501).json({
        error: 'unsupported_operation',
        error_description: 'Client deletion is not supported in this implementation'
    });
});

// Middleware to authenticate client for configuration endpoints
function authenticateClient(req, res, next) {
    const clientId = req.params.client_id;
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Bearer token required for client authentication'
        });
    }

    // In a real implementation, you would validate the registration access token
    // For this demo, we'll just check if the client exists
    const client = database.getClientById(clientId);
    if (!client) {
        return res.status(404).json({
            error: 'invalid_client',
            error_description: 'Client not found'
        });
    }

    req.client = client;
    next();
}

module.exports = router; 