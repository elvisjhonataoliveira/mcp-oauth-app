const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

// In-memory database
const database = {
    users: new Map(),
    clients: new Map(),
    authorizationCodes: new Map(),
    accessTokens: new Map(),
    refreshTokens: new Map()
};

// Mock initializer
function initialize() {
    console.log('Initializing in-memory database with mock data...');
    
    // Create mock users
    const users = [
        {
            id: uuidv4(),
            username: 'alice',
            email: 'alice@example.com',
            password: 'password123',
            firstName: 'Alice',
            lastName: 'Johnson',
            role: 'user'
        },
        {
            id: uuidv4(),
            username: 'bob',
            email: 'bob@example.com',
            password: 'password456',
            firstName: 'Bob',
            lastName: 'Smith',
            role: 'admin'
        },
        {
            id: uuidv4(),
            username: 'charlie',
            email: 'charlie@example.com',
            password: 'password789',
            firstName: 'Charlie',
            lastName: 'Brown',
            role: 'user'
        }
    ];

    // Hash passwords and store users
    users.forEach(user => {
        const hashedPassword = bcrypt.hashSync(user.password, 10);
        database.users.set(user.id, {
            ...user,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        });
        console.log(`Created user: ${user.username} (${user.email})`);
    });

    // Create a sample client for testing
    const sampleClient = {
        client_id: 'sample-client-id',
        client_secret: bcrypt.hashSync('sample-client-secret', 10),
        client_name: 'Sample OAuth2.1 Client',
        redirect_uris: ['http://localhost:3001/callback', 'http://localhost:8080/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: 'read write profile',
        token_endpoint_auth_method: 'client_secret_basic',
        created_at: Math.floor(Date.now() / 1000)
    };

    database.clients.set(sampleClient.client_id, sampleClient);
    console.log(`Created sample client: ${sampleClient.client_name}`);
    console.log('Database initialization complete.');
}

// User operations
function getUserById(id) {
    return database.users.get(id);
}

function getUserByUsername(username) {
    for (let user of database.users.values()) {
        if (user.username === username) {
            return user;
        }
    }
    return null;
}

function getUserByEmail(email) {
    for (let user of database.users.values()) {
        if (user.email === email) {
            return user;
        }
    }
    return null;
}

function validateUserCredentials(username, password) {
    const user = getUserByUsername(username);
    if (user && bcrypt.compareSync(password, user.password)) {
        return user;
    }
    return null;
}

// Client operations
function getClientById(clientId) {
    return database.clients.get(clientId);
}

function validateClientCredentials(clientId, clientSecret) {
    const client = getClientById(clientId);
    if (client && bcrypt.compareSync(clientSecret, client.client_secret)) {
        return client;
    }
    return null;
}

function createClient(clientData) {
    const clientId = uuidv4();
    const hashedSecret = bcrypt.hashSync(clientData.client_secret, 10);
    
    const client = {
        client_id: clientId,
        client_secret: hashedSecret,
        client_name: clientData.client_name,
        redirect_uris: clientData.redirect_uris,
        grant_types: clientData.grant_types || ['authorization_code'],
        response_types: clientData.response_types || ['code'],
        scope: clientData.scope || 'read',
        token_endpoint_auth_method: clientData.token_endpoint_auth_method || 'client_secret_basic',
        created_at: Math.floor(Date.now() / 1000)
    };

    database.clients.set(clientId, client);
    return client;
}

// Authorization code operations
function createAuthorizationCode(userId, clientId, redirectUri, scope, codeChallenge, codeChallengeMethod) {
    const code = {
        code: uuidv4(),
        user_id: userId,
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: scope,
        code_challenge: codeChallenge,
        code_challenge_method: codeChallengeMethod,
        expires_at: Date.now() + (10 * 60 * 1000), // 10 minutes
        used: false
    };

    database.authorizationCodes.set(code.code, code);
    return code;
}

function getAuthorizationCode(code) {
    return database.authorizationCodes.get(code);
}

function useAuthorizationCode(code) {
    const authCode = database.authorizationCodes.get(code);
    if (authCode) {
        authCode.used = true;
        return authCode;
    }
    return null;
}

// Token operations
function createAccessToken(userId, clientId, scope) {
    const token = {
        access_token: uuidv4(),
        token_type: 'Bearer',
        user_id: userId,
        client_id: clientId,
        scope: scope,
        expires_at: Date.now() + (3600 * 1000), // 1 hour
        created_at: Date.now()
    };

    database.accessTokens.set(token.access_token, token);
    return token;
}

function createRefreshToken(userId, clientId, scope) {
    const token = {
        refresh_token: uuidv4(),
        user_id: userId,
        client_id: clientId,
        scope: scope,
        expires_at: Date.now() + (30 * 24 * 3600 * 1000), // 30 days
        created_at: Date.now()
    };

    database.refreshTokens.set(token.refresh_token, token);
    return token;
}

function getAccessToken(token) {
    return database.accessTokens.get(token);
}

function getRefreshToken(token) {
    return database.refreshTokens.get(token);
}

function revokeToken(token) {
    const accessToken = database.accessTokens.get(token);
    const refreshToken = database.refreshTokens.get(token);
    
    if (accessToken) {
        database.accessTokens.delete(token);
        return true;
    }
    
    if (refreshToken) {
        database.refreshTokens.delete(token);
        return true;
    }
    
    return false;
}

function introspectToken(token) {
    const accessToken = database.accessTokens.get(token);
    if (accessToken) {
        return {
            active: Date.now() < accessToken.expires_at,
            client_id: accessToken.client_id,
            username: getUserById(accessToken.user_id)?.username,
            scope: accessToken.scope,
            exp: Math.floor(accessToken.expires_at / 1000),
            iat: Math.floor(accessToken.created_at / 1000),
            token_type: 'access_token'
        };
    }

    const refreshToken = database.refreshTokens.get(token);
    if (refreshToken) {
        return {
            active: Date.now() < refreshToken.expires_at,
            client_id: refreshToken.client_id,
            username: getUserById(refreshToken.user_id)?.username,
            scope: refreshToken.scope,
            exp: Math.floor(refreshToken.expires_at / 1000),
            iat: Math.floor(refreshToken.created_at / 1000),
            token_type: 'refresh_token'
        };
    }

    return { active: false };
}

module.exports = {
    initialize,
    getUserById,
    getUserByUsername,
    getUserByEmail,
    validateUserCredentials,
    getClientById,
    validateClientCredentials,
    createClient,
    createAuthorizationCode,
    getAuthorizationCode,
    useAuthorizationCode,
    createAccessToken,
    createRefreshToken,
    getAccessToken,
    getRefreshToken,
    revokeToken,
    introspectToken,
    database
}; 