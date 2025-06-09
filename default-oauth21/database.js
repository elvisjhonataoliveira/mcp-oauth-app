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

// Initialize with mock users
async function initializeDatabase() {
  console.log('Initializing database with mock data...');
  
  // Create mock users
  const users = [
    {
      id: uuidv4(),
      username: 'john.doe',
      email: 'john.doe@example.com',
      password: 'password123',
      firstName: 'John',
      lastName: 'Doe'
    },
    {
      id: uuidv4(),
      username: 'jane.smith',
      email: 'jane.smith@example.com',
      password: 'password123',
      firstName: 'Jane',
      lastName: 'Smith'
    },
    {
      id: uuidv4(),
      username: 'bob.johnson',
      email: 'bob.johnson@example.com',
      password: 'password123',
      firstName: 'Bob',
      lastName: 'Johnson'
    }
  ];

  // Hash passwords and store users
  for (const user of users) {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    database.users.set(user.username, {
      ...user,
      password: hashedPassword
    });
  }

  // Create a test client application
  database.clients.set('test-client', {
    clientId: 'test-client',
    clientSecret: 'test-secret',
    redirectUris: ['http://localhost:3001/callback'],
    name: 'Test Application',
    description: 'A test OAuth2.1 client application'
  });

  console.log('Database initialized successfully!');
  console.log(`Users: ${database.users.size}`);
  console.log(`Clients: ${database.clients.size}`);
}

// Database operations
const db = {
  // User operations
  findUserByUsername: (username) => database.users.get(username),
  findUserById: (id) => {
    for (const user of database.users.values()) {
      if (user.id === id) return user;
    }
    return null;
  },
  validateUser: async (username, password) => {
    const user = database.users.get(username);
    if (!user) return null;
    
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? user : null;
  },

  // Client operations
  findClient: (clientId) => database.clients.get(clientId),
  validateClient: (clientId, clientSecret) => {
    const client = database.clients.get(clientId);
    return client && client.clientSecret === clientSecret ? client : null;
  },

  // Authorization code operations
  storeAuthorizationCode: (code, data) => {
    database.authorizationCodes.set(code, {
      ...data,
      createdAt: Date.now(),
      expiresAt: Date.now() + (10 * 60 * 1000) // 10 minutes
    });
  },
  findAuthorizationCode: (code) => database.authorizationCodes.get(code),
  deleteAuthorizationCode: (code) => database.authorizationCodes.delete(code),

  // Token operations
  storeAccessToken: (token, data) => {
    database.accessTokens.set(token, {
      ...data,
      createdAt: Date.now(),
      expiresAt: Date.now() + (60 * 60 * 1000) // 1 hour
    });
  },
  findAccessToken: (token) => database.accessTokens.get(token),
  deleteAccessToken: (token) => database.accessTokens.delete(token),

  storeRefreshToken: (token, data) => {
    database.refreshTokens.set(token, {
      ...data,
      createdAt: Date.now(),
      expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000) // 30 days
    });
  },
  findRefreshToken: (token) => database.refreshTokens.get(token),
  deleteRefreshToken: (token) => database.refreshTokens.delete(token),

  // Helper function to clean expired tokens
  cleanExpiredTokens: () => {
    const now = Date.now();
    
    // Clean authorization codes
    for (const [code, data] of database.authorizationCodes.entries()) {
      if (data.expiresAt < now) {
        database.authorizationCodes.delete(code);
      }
    }
    
    // Clean access tokens
    for (const [token, data] of database.accessTokens.entries()) {
      if (data.expiresAt < now) {
        database.accessTokens.delete(token);
      }
    }
    
    // Clean refresh tokens
    for (const [token, data] of database.refreshTokens.entries()) {
      if (data.expiresAt < now) {
        database.refreshTokens.delete(token);
      }
    }
  }
};

module.exports = {
  initializeDatabase,
  db
}; 