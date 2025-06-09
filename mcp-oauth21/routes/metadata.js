const express = require('express');
const router = express.Router();

// Authorization Server Metadata (RFC 8414)
router.get('/oauth-authorization-server', (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const metadata = {
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/auth/authorize`,
        token_endpoint: `${baseUrl}/oauth/token`,
        token_endpoint_auth_methods_supported: [
            'client_secret_basic',
            'client_secret_post'
        ],
        token_endpoint_auth_signing_alg_values_supported: ['RS256'],
        userinfo_endpoint: `${baseUrl}/api/userinfo`,
        registration_endpoint: `${baseUrl}/clients/register`,
        scopes_supported: ['read', 'write', 'profile', 'email'],
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: [
            'authorization_code',
            'refresh_token'
        ],
        code_challenge_methods_supported: ['S256', 'plain'],
        introspection_endpoint: `${baseUrl}/oauth/introspect`,
        introspection_endpoint_auth_methods_supported: [
            'client_secret_basic',
            'client_secret_post'
        ],
        revocation_endpoint: `${baseUrl}/oauth/revoke`,
        revocation_endpoint_auth_methods_supported: [
            'client_secret_basic',
            'client_secret_post'
        ],
        // OAuth 2.1 specific features
        require_request_uri_registration: false,
        require_signed_request_object: false,
        request_object_signing_alg_values_supported: ['RS256'],
        request_object_encryption_alg_values_supported: ['RSA-OAEP'],
        request_object_encryption_enc_values_supported: ['A256GCM'],
        request_parameter_supported: true,
        request_uri_parameter_supported: false,
        // Security best practices
        tls_client_certificate_bound_access_tokens: false,
        dpop_signing_alg_values_supported: ['RS256', 'ES256'],
        authorization_response_iss_parameter_supported: true
    };

    res.json(metadata);
});

// Protected Resource Metadata (RFC 8414 Section 3.2)
router.get('/oauth-protected-resource', (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const metadata = {
        resource: baseUrl,
        authorization_servers: [baseUrl],
        scopes_supported: ['read', 'write', 'profile', 'email'],
        bearer_methods_supported: ['header', 'body', 'query'],
        resource_documentation: `${baseUrl}/docs`,
        introspection_endpoint: `${baseUrl}/oauth/introspect`,
        introspection_endpoint_auth_methods_supported: [
            'client_secret_basic',
            'client_secret_post'
        ],
        revocation_endpoint: `${baseUrl}/oauth/revoke`,
        revocation_endpoint_auth_methods_supported: [
            'client_secret_basic',
            'client_secret_post'
        ],
        // OAuth 2.1 specific features
        tls_client_certificate_bound_access_tokens: false,
        dpop_signing_alg_values_supported: ['RS256', 'ES256']
    };

    res.json(metadata);
});

// Additional endpoint for discovery
router.get('/openid_configuration', (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const metadata = {
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/auth/authorize`,
        token_endpoint: `${baseUrl}/oauth/token`,
        userinfo_endpoint: `${baseUrl}/api/userinfo`,
        registration_endpoint: `${baseUrl}/clients/register`,
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        scopes_supported: ['openid', 'profile', 'email', 'read', 'write'],
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: [
            'authorization_code',
            'refresh_token'
        ],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: [
            'client_secret_basic',
            'client_secret_post'
        ],
        claims_supported: [
            'sub',
            'iss',
            'aud',
            'exp',
            'iat',
            'name',
            'given_name',
            'family_name',
            'email',
            'email_verified'
        ]
    };

    res.json(metadata);
});

// JWKS endpoint (placeholder for JWT key sets)
router.get('/jwks.json', (req, res) => {
    // In a real implementation, you would return actual JWK sets
    const jwks = {
        keys: [
            {
                kty: 'RSA',
                use: 'sig',
                kid: 'sample-key-id',
                n: 'sample-modulus-placeholder',
                e: 'AQAB'
            }
        ]
    };

    res.json(jwks);
});

module.exports = router; 