# OAuth2.1 Authorization Server Implementation

This is a complete OAuth2.1 Authorization Server implementation built with Node.js and Express, featuring all the core OAuth2.1 specifications and best practices.

## Features

### Core OAuth2.1 Implementation
- ✅ **Authorization Code Flow** with PKCE support
- ✅ **Refresh Token Grant**
- ✅ **Token Introspection** (RFC 7662)
- ✅ **Token Revocation** (RFC 7009)
- ✅ **Authorization Server Metadata** (RFC 8414)
- ✅ **Protected Resource Metadata** (RFC 8414)
- ✅ **Dynamic Client Registration Protocol** (RFC 7591)

### Security Features
- ✅ PKCE (Proof Key for Code Exchange) support
- ✅ Secure client authentication (Basic and POST methods)
- ✅ Scope-based access control
- ✅ Token expiration and validation
- ✅ Authorization code replay protection

### Technical Implementation
- ✅ Node.js with CommonJS modules
- ✅ Express.js for routing
- ✅ In-memory database for all storage
- ✅ Mock user initialization with 3 test users
- ✅ EJS templating for login interface
- ✅ Comprehensive error handling

## Quick Start

### Installation and Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start the OAuth2.1 server:**
   ```bash
   npm run start-mcp
   # or for development
   npm run dev-mcp
   ```

3. **Server will be running on:**
   ```
   http://localhost:3000
   ```

### Test Users

The application comes with 3 pre-configured test users:

| Username | Password    | Role  |
|----------|-------------|-------|
| alice    | password123 | user  |
| bob      | password456 | admin |
| charlie  | password789 | user  |

### Pre-configured Test Client

A sample client is automatically created for testing:

- **Client ID:** `sample-client-id`
- **Client Secret:** `sample-client-secret`
- **Redirect URIs:** 
  - `http://localhost:3001/callback`
  - `http://localhost:8080/callback`

## API Endpoints

### Discovery and Metadata

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/oauth-authorization-server` | Authorization Server Metadata |
| `GET /.well-known/oauth-protected-resource` | Protected Resource Metadata |
| `GET /.well-known/openid_configuration` | OpenID Connect Discovery |
| `GET /.well-known/jwks.json` | JSON Web Key Set |

### OAuth2.1 Flow

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/authorize` | GET | Authorization endpoint |
| `/auth/login` | POST | Handle user login |
| `/oauth/token` | POST | Token endpoint |
| `/oauth/introspect` | POST | Token introspection |
| `/oauth/revoke` | POST | Token revocation |

### Dynamic Client Registration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/clients/register` | POST | Register new client |
| `/clients/:client_id` | GET | Get client configuration |

### Protected Resources

| Endpoint | Method | Scope Required | Description |
|----------|--------|----------------|-------------|
| `/api/userinfo` | GET | profile | OpenID Connect UserInfo |
| `/api/profile` | GET | profile | User profile data |
| `/api/user/data` | GET | read | Protected user data |
| `/api/user/data` | PUT | write | Update user data |
| `/api/admin/users` | GET | read + admin role | Admin: List all users |
| `/api/health` | GET | any | Health check |
| `/api/test` | GET | any | Token validation test |

## Testing the Implementation

### 1. Test Authorization Server Metadata

```bash
curl http://localhost:3000/.well-known/oauth-authorization-server
```

### 2. Test Dynamic Client Registration

```bash
curl -X POST http://localhost:3000/clients/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:8080/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "read write profile"
  }'
```

### 3. Test OAuth2.1 Authorization Code Flow

#### Step 1: Authorization Request
Visit in browser:
```
http://localhost:3000/auth/authorize?response_type=code&client_id=sample-client-id&redirect_uri=http://localhost:3001/callback&scope=read%20profile&state=xyz123
```

#### Step 2: Login
Use any of the test users (e.g., alice/password123)

#### Step 3: Exchange Authorization Code for Tokens
```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'sample-client-id:sample-client-secret' | base64)" \
  -d "grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=http://localhost:3001/callback"
```

### 4. Test Protected Resources

```bash
# Test UserInfo endpoint
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  http://localhost:3000/api/userinfo

# Test protected user data
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  http://localhost:3000/api/user/data
```

### 5. Test Token Introspection

```bash
curl -X POST http://localhost:3000/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'sample-client-id:sample-client-secret' | base64)" \
  -d "token=ACCESS_TOKEN"
```

### 6. Test Token Revocation

```bash
curl -X POST http://localhost:3000/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'sample-client-id:sample-client-secret' | base64)" \
  -d "token=ACCESS_TOKEN"
```

## PKCE Flow Testing

For testing with PKCE (recommended for all clients):

1. **Generate code verifier and challenge:**
   ```javascript
   const crypto = require('crypto');
   const codeVerifier = crypto.randomBytes(32).toString('base64url');
   const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
   ```

2. **Authorization request with PKCE:**
   ```
   http://localhost:3000/auth/authorize?response_type=code&client_id=sample-client-id&redirect_uri=http://localhost:3001/callback&scope=read%20profile&state=xyz123&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
   ```

3. **Token request with code verifier:**
   ```bash
   curl -X POST http://localhost:3000/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Authorization: Basic $(echo -n 'sample-client-id:sample-client-secret' | base64)" \
     -d "grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=http://localhost:3001/callback&code_verifier=CODE_VERIFIER"
   ```

## Architecture

### File Structure
```
mcp-oauth21/
├── index.js              # Main application entry point
├── database.js           # In-memory database and mock data
├── routes/
│   ├── auth.js           # Authorization endpoints
│   ├── token.js          # Token endpoints
│   ├── client.js         # Client registration
│   ├── metadata.js       # Server metadata
│   └── resource.js       # Protected resources
├── views/
│   └── login.ejs         # Login page template
└── README.md             # This file
```

### In-Memory Database Schema

The application uses JavaScript Maps to store:

- **Users**: User accounts with hashed passwords
- **Clients**: OAuth2.1 client applications
- **Authorization Codes**: Temporary codes for authorization flow
- **Access Tokens**: Bearer tokens for resource access
- **Refresh Tokens**: Long-lived tokens for token refresh

## OAuth2.1 Compliance

This implementation follows OAuth2.1 specifications including:

- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7636**: PKCE (Proof Key for Code Exchange)
- **RFC 7662**: Token Introspection
- **RFC 7009**: Token Revocation
- **RFC 8414**: Authorization Server Metadata
- **RFC 7591**: Dynamic Client Registration Protocol

### Security Considerations

- Authorization codes expire in 10 minutes
- Access tokens expire in 1 hour
- Refresh tokens expire in 30 days
- PKCE support for enhanced security
- Scope-based access control
- Secure client credential handling

## Development Notes

This is a demonstration implementation for learning and testing OAuth2.1 flows. For production use, consider:

- Persistent database storage
- Proper session management
- HTTPS enforcement
- Rate limiting
- Audit logging
- JWT token implementation
- Proper key management for signing

## Contributing

This implementation serves as a reference for OAuth2.1 flows. Feel free to extend it with additional features or use it as a starting point for your own OAuth2.1 server implementation. 