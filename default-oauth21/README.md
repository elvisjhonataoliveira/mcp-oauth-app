# OAuth2.1 Server

A complete OAuth2.1 implementation built with Node.js and Express, featuring PKCE (Proof Key for Code Exchange) and secure token management.

## Features

- ✅ **OAuth2.1 Compliance**: Full implementation of OAuth2.1 specification
- ✅ **PKCE Support**: Required for all authorization flows
- ✅ **Authorization Code Flow**: Secure authorization with PKCE
- ✅ **Refresh Token Flow**: Token renewal without re-authentication
- ✅ **Token Introspection**: Token validation and metadata
- ✅ **Scope-based Access Control**: Granular permissions
- ✅ **In-memory Database**: No external dependencies
- ✅ **Session Management**: Secure session handling
- ✅ **Mock Users**: Pre-configured test users

## Quick Start

### Installation

```bash
# Install dependencies
npm install

# Start the server
npm start
```

The server will start on `http://localhost:3000`

### Test the OAuth2.1 Flow

Run the included test script to see the complete OAuth2.1 flow in action:

```bash
# In a new terminal (server must be running)
node test-oauth-flow.js
```

## API Endpoints

### OAuth2.1 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Authorization endpoint |
| `/oauth/token` | POST | Token endpoint |
| `/oauth/consent` | POST | User consent handling |
| `/oauth/introspect` | POST | Token introspection |

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | User login |
| `/auth/logout` | POST | User logout |
| `/auth/me` | GET | Current user info |
| `/auth/status` | GET | Authentication status |
| `/auth/userinfo` | GET | OAuth2.1 userinfo endpoint |
| `/auth/users` | GET | List all users (admin) |

### Utility Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API documentation |
| `/demo` | GET | OAuth2.1 flow guide |
| `/health` | GET | Health check |
| `/api/protected` | GET | Protected resource example |

## OAuth2.1 Flow

### 1. Authorization Request

```http
GET /oauth/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3001/callback&scope=read profile email&state=random-state&code_challenge=CHALLENGE&code_challenge_method=S256
```

### 2. User Login

```http
POST /auth/login
Content-Type: application/json
X-Session-Id: SESSION_ID

{
  "username": "john.doe",
  "password": "password123",
  "session_id": "SESSION_ID"
}
```

### 3. User Consent

```http
POST /oauth/consent
Content-Type: application/json
X-Session-Id: SESSION_ID

{
  "action": "allow",
  "session_id": "SESSION_ID"
}
```

### 4. Token Exchange

```http
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "test-client",
  "client_secret": "test-secret",
  "code": "AUTHORIZATION_CODE",
  "redirect_uri": "http://localhost:3001/callback",
  "code_verifier": "CODE_VERIFIER"
}
```

### 5. Access Protected Resources

```http
GET /auth/userinfo
Authorization: Bearer ACCESS_TOKEN
```

## Configuration

### Default Client

- **Client ID**: `test-client`
- **Client Secret**: `test-secret`
- **Redirect URI**: `http://localhost:3001/callback`

### Default Users

| Username | Password | Email |
|----------|----------|-------|
| john.doe | password123 | john.doe@example.com |
| jane.smith | password123 | jane.smith@example.com |
| bob.johnson | password123 | bob.johnson@example.com |

### Supported Scopes

- `read`: Basic read access
- `profile`: User profile information
- `email`: User email address

### Token Lifetimes

- **Authorization Code**: 10 minutes
- **Access Token**: 1 hour
- **Refresh Token**: 30 days

## PKCE Implementation

This server requires PKCE for all authorization flows, implementing OAuth2.1 security best practices:

- **Code Challenge Method**: `S256` (SHA256)
- **Code Verifier**: 32-byte random string, base64url encoded
- **Code Challenge**: SHA256 hash of code verifier, base64url encoded

### Generating PKCE Challenge (Example)

```javascript
const crypto = require('crypto');

function generatePKCEChallenge() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  
  return { codeVerifier, codeChallenge };
}
```

## Security Features

- **Secure Token Storage**: JWT with HMAC-SHA256 signing
- **PKCE Required**: Prevents authorization code interception
- **State Parameter**: CSRF protection
- **Token Expiration**: Automatic cleanup of expired tokens
- **Scope Validation**: Granular access control
- **Client Authentication**: Secret-based client validation

## Error Handling

The server returns standard OAuth2.1 error responses:

```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter",
  "state": "optional-state-value"
}
```

### Common Error Codes

- `invalid_request`: Malformed request
- `unauthorized_client`: Invalid client credentials
- `access_denied`: User denied authorization
- `unsupported_response_type`: Only 'code' is supported
- `invalid_scope`: Invalid or unknown scope
- `invalid_grant`: Invalid authorization code or refresh token
- `unsupported_grant_type`: Unsupported grant type

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│     Client      │────▶│  OAuth Server   │────▶│ Resource Server │
│                 │     │                 │     │                 │
│ - Generates     │     │ - Authorization │     │ - Protected     │
│   PKCE          │     │ - Token Mgmt    │     │   Resources     │
│ - Handles       │     │ - User Auth     │     │ - Token         │
│   Redirects     │     │ - Session Mgmt  │     │   Validation    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Components

- **Database Module** (`database.js`): In-memory storage with mock data
- **OAuth Utils** (`oauth-utils.js`): Token generation and PKCE handling
- **Middleware** (`middleware.js`): Authentication and validation
- **OAuth Routes** (`oauth-routes.js`): OAuth2.1 endpoints
- **Auth Routes** (`auth-routes.js`): User authentication endpoints
- **Main App** (`index.js`): Express server setup

## Development

### Project Structure

```
oauth-app/
├── database.js           # In-memory database
├── oauth-utils.js        # OAuth2.1 utilities
├── middleware.js         # Express middleware
├── oauth-routes.js       # OAuth2.1 endpoints
├── auth-routes.js        # Authentication endpoints
├── index.js              # Main application
├── test-oauth-flow.js    # Test script
├── package.json          # Dependencies
└── README.md             # Documentation
```

### Adding New Users

Modify the `initializeDatabase()` function in `database.js`:

```javascript
const users = [
  {
    id: uuidv4(),
    username: 'new.user',
    email: 'new.user@example.com',
    password: 'password123',
    firstName: 'New',
    lastName: 'User'
  }
  // ... existing users
];
```

### Adding New Clients

Add clients in the `initializeDatabase()` function:

```javascript
database.clients.set('new-client', {
  clientId: 'new-client',
  clientSecret: 'new-secret',
  redirectUris: ['http://localhost:3002/callback'],
  name: 'New Application',
  description: 'Description of new client'
});
```

## Testing

The included test script (`test-oauth-flow.js`) demonstrates a complete OAuth2.1 flow:

1. **PKCE Generation**: Creates code verifier and challenge
2. **Authorization Request**: Initiates OAuth2.1 flow
3. **User Authentication**: Logs in with test credentials
4. **User Consent**: Grants authorization
5. **Token Exchange**: Exchanges code for tokens
6. **Resource Access**: Uses access token for API calls

## Production Considerations

⚠️ **This is a demo implementation. For production use:**

- Replace in-memory storage with persistent database
- Use environment variables for secrets
- Implement proper logging and monitoring
- Add rate limiting and DDoS protection
- Use HTTPS for all communications
- Implement proper session storage (Redis, etc.)
- Add input validation and sanitization
- Implement proper error handling and logging
- Use production-grade JWT signing keys

## License

MIT License - See LICENSE file for details

## Support

For questions and support, please check the `/demo` endpoint for detailed flow examples. 