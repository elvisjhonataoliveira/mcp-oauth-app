const express = require('express');
const database = require('../database');

const router = express.Router();

// Middleware to authenticate bearer tokens
function authenticateBearer(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Bearer token required'
        });
    }

    const token = authHeader.slice(7); // Remove 'Bearer ' prefix
    const accessToken = database.getAccessToken(token);

    if (!accessToken) {
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Invalid or expired access token'
        });
    }

    // Check if token is expired
    if (Date.now() > accessToken.expires_at) {
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Access token has expired'
        });
    }

    // Get user information
    const user = database.getUserById(accessToken.user_id);
    if (!user) {
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'User associated with token not found'
        });
    }

    // Attach token and user to request
    req.accessToken = accessToken;
    req.user = user;
    next();
}

// Middleware to check scope
function requireScope(requiredScope) {
    return (req, res, next) => {
        const tokenScopes = req.accessToken.scope.split(' ');
        
        if (!tokenScopes.includes(requiredScope)) {
            return res.status(403).json({
                error: 'insufficient_scope',
                error_description: `Access token does not have required scope: ${requiredScope}`
            });
        }
        
        next();
    };
}

// UserInfo endpoint (OpenID Connect Core 1.0 Section 5.3)
router.get('/userinfo', authenticateBearer, requireScope('profile'), (req, res) => {
    const user = req.user;
    const tokenScopes = req.accessToken.scope.split(' ');

    const userInfo = {
        sub: user.id, // Subject identifier
    };

    // Include profile information if scope allows
    if (tokenScopes.includes('profile')) {
        userInfo.name = `${user.firstName} ${user.lastName}`;
        userInfo.given_name = user.firstName;
        userInfo.family_name = user.lastName;
        userInfo.preferred_username = user.username;
    }

    // Include email information if scope allows
    if (tokenScopes.includes('email')) {
        userInfo.email = user.email;
        userInfo.email_verified = true; // In a real app, this would be actual verification status
    }

    res.json(userInfo);
});

// Protected resource: User profile
router.get('/profile', authenticateBearer, requireScope('profile'), (req, res) => {
    const user = req.user;
    
    res.json({
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt
    });
});

// Protected resource: User data (read scope)
router.get('/user/data', authenticateBearer, requireScope('read'), (req, res) => {
    const user = req.user;
    
    res.json({
        message: 'This is protected user data',
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        },
        accessedAt: new Date().toISOString()
    });
});

// Protected resource: Update user data (write scope)
router.put('/user/data', authenticateBearer, requireScope('write'), (req, res) => {
    const user = req.user;
    const { firstName, lastName } = req.body;
    
    // In a real implementation, you would update the user in the database
    res.json({
        message: 'User data updated successfully',
        user: {
            id: user.id,
            username: user.username,
            firstName: firstName || user.firstName,
            lastName: lastName || user.lastName
        },
        updatedAt: new Date().toISOString()
    });
});

// Protected resource: Admin endpoint (requires admin role)
router.get('/admin/users', authenticateBearer, requireScope('read'), (req, res) => {
    const user = req.user;
    
    if (user.role !== 'admin') {
        return res.status(403).json({
            error: 'access_denied',
            error_description: 'Admin role required'
        });
    }
    
    // Return all users (without passwords)
    const users = Array.from(database.database.users.values()).map(u => ({
        id: u.id,
        username: u.username,
        email: u.email,
        firstName: u.firstName,
        lastName: u.lastName,
        role: u.role,
        createdAt: u.createdAt
    }));
    
    res.json({
        users: users,
        total: users.length
    });
});

// Protected resource: Health check
router.get('/health', authenticateBearer, (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        user: req.user.username,
        scopes: req.accessToken.scope.split(' ')
    });
});

// Test endpoint to verify token without specific scope requirements
router.get('/test', authenticateBearer, (req, res) => {
    res.json({
        message: 'Token is valid',
        user: {
            id: req.user.id,
            username: req.user.username
        },
        token: {
            client_id: req.accessToken.client_id,
            scope: req.accessToken.scope,
            expires_at: new Date(req.accessToken.expires_at).toISOString()
        }
    });
});

module.exports = router; 