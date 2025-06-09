sequenceDiagram
    participant Client as Client Application
    participant Browser as User Browser
    participant AuthServer as Authorization Server
    participant ResourceServer as Resource Server
    participant User as Resource Owner

    Note over Client,ResourceServer: Phase 1: Discovery & Registration

    Note over Client,AuthServer: 1. Authorization Server Metadata Discovery
    Client->>AuthServer: GET /.well-known/oauth-authorization-server
    AuthServer->>Client: Return server metadata<br/>{<br/>  "issuer": "http://localhost:3000",<br/>  "authorization_endpoint": "/oauth/authorize",<br/>  "token_endpoint": "/oauth/token",<br/>  "registration_endpoint": "/register",<br/>  "introspection_endpoint": "/oauth/introspect",<br/>  "code_challenge_methods_supported": ["S256"],<br/>  "grant_types_supported": ["authorization_code", "refresh_token"],<br/>  "response_types_supported": ["code"],<br/>  "scopes_supported": ["read", "profile", "email"]<br/>}

    Note over Client,ResourceServer: 2. Protected Resource Metadata Discovery
    Client->>ResourceServer: GET /.well-known/oauth-protected-resource
    ResourceServer->>Client: Return resource metadata<br/>{<br/>  "resource": "http://localhost:3000",<br/>  "authorization_servers": ["http://localhost:3000"],<br/>  "scopes_supported": ["read", "profile", "email"],<br/>  "bearer_methods_supported": ["header"],<br/>  "resource_documentation": "/docs"<br/>}

    Note over Client,AuthServer: 3. Dynamic Client Registration
    Client->>AuthServer: POST /register<br/>{<br/>  "redirect_uris": ["https://client.app/callback"],<br/>  "client_name": "My Dynamic App",<br/>  "client_uri": "https://client.app",<br/>  "logo_uri": "https://client.app/logo.png",<br/>  "scope": "read profile email",<br/>  "grant_types": ["authorization_code", "refresh_token"],<br/>  "response_types": ["code"],<br/>  "token_endpoint_auth_method": "client_secret_post"<br/>}

    AuthServer->>AuthServer: Generate client_id<br/>Generate client_secret<br/>Generate registration_access_token
    AuthServer->>Client: Return client credentials<br/>{<br/>  "client_id": "dynamic_12345",<br/>  "client_secret": "secret_abc123",<br/>  "client_id_issued_at": 1609459200,<br/>  "client_secret_expires_at": 0,<br/>  "registration_access_token": "reg_token_xyz",<br/>  "registration_client_uri": "/register/dynamic_12345"<br/>}

    Note over Client,ResourceServer: Phase 2: OAuth2.1 Authorization Flow

    Note over Client: 4. Generate PKCE Challenge
    Client->>Client: Generate code_verifier<br/>Generate code_challenge = SHA256(code_verifier)

    Note over Client,AuthServer: 5. Authorization Request
    Client->>Browser: Redirect to authorization endpoint
    Browser->>AuthServer: GET /oauth/authorize<br/>?response_type=code<br/>&client_id=dynamic_12345<br/>&redirect_uri=https://client.app/callback<br/>&scope=read profile email<br/>&state=secure_random_state<br/>&code_challenge=PKCE_CHALLENGE<br/>&code_challenge_method=S256

    AuthServer->>AuthServer: Validate client_id<br/>Validate redirect_uri<br/>Validate PKCE parameters
    AuthServer->>Browser: Return authorization form<br/>(session_id provided)

    Note over AuthServer,User: 6. User Authentication & Consent
    Browser->>User: Display login form
    User->>Browser: Enter credentials
    Browser->>AuthServer: POST /auth/login<br/>{username, password, session_id}
    AuthServer->>AuthServer: Validate user credentials
    
    Browser->>User: Display consent screen<br/>(show requested scopes)
    User->>Browser: Grant permission
    Browser->>AuthServer: POST /oauth/consent<br/>{action: "allow", session_id}

    Note over AuthServer,Client: 7. Authorization Response
    AuthServer->>AuthServer: Generate authorization_code<br/>Store code + PKCE challenge<br/>Set expiration (10 minutes)
    AuthServer->>Browser: HTTP 302 Redirect<br/>Location: https://client.app/callback<br/>?code=AUTH_CODE_12345<br/>&state=secure_random_state
    Browser->>Client: Authorization code received

    Note over Client,AuthServer: 8. Token Exchange
    Client->>Client: Validate state parameter<br/>(CSRF protection)
    Client->>AuthServer: POST /oauth/token<br/>{<br/>  "grant_type": "authorization_code",<br/>  "client_id": "dynamic_12345",<br/>  "client_secret": "secret_abc123",<br/>  "code": "AUTH_CODE_12345",<br/>  "redirect_uri": "https://client.app/callback",<br/>  "code_verifier": "PKCE_VERIFIER"<br/>}

    AuthServer->>AuthServer: Verify client credentials<br/>Verify PKCE: SHA256(code_verifier) === code_challenge<br/>Verify redirect_uri matches<br/>Check code expiration
    AuthServer->>AuthServer: Generate access_token (JWT)<br/>Generate refresh_token<br/>Delete authorization_code
    AuthServer->>Client: Return token response<br/>{<br/>  "access_token": "...",<br/>  "token_type": "Bearer",<br/>  "expires_in": 3600,<br/>  "refresh_token": "refresh_token_xyz789",<br/>  "scope": "read profile email"<br/>}

    Note over Client,ResourceServer: Phase 3: Protected Resource Access

    Note over Client,ResourceServer: 9. Access Protected Resources
    Client->>ResourceServer: GET /api/userinfo<br/>Authorization: Bearer ...
    
    ResourceServer->>AuthServer: POST /oauth/introspect<br/>{<br/>  "token": "...",<br/>  "token_type_hint": "access_token"<br/>}
    AuthServer->>AuthServer: Validate JWT signature<br/>Check token expiration<br/>Verify token scopes
    AuthServer->>ResourceServer: Return introspection response<br/>{<br/>  "active": true,<br/>  "client_id": "dynamic_12345",<br/>  "username": "john.doe",<br/>  "scope": "read profile email",<br/>  "exp": 1609462800,<br/>  "iat": 1609459200<br/>}

    ResourceServer->>ResourceServer: Check required scopes<br/>Load user data
    ResourceServer->>Client: Return protected resource<br/>{<br/>  "sub": "user_123",<br/>  "username": "john.doe",<br/>  "given_name": "John",<br/>  "family_name": "Doe",<br/>  "email": "john.doe@example.com",<br/>  "email_verified": true,<br/>  "profile": "https://example.com/john.doe"<br/>}

    Note over Client,AuthServer: 10. Token Refresh (When Needed)
    Client->>AuthServer: POST /oauth/token<br/>{<br/>  "grant_type": "refresh_token",<br/>  "client_id": "dynamic_12345",<br/>  "client_secret": "secret_abc123",<br/>  "refresh_token": "refresh_token_xyz789"<br/>}
    AuthServer->>AuthServer: Validate refresh token<br/>Generate new tokens<br/>Optionally rotate refresh token
    AuthServer->>Client: Return new tokens<br/>{<br/>  "access_token": "...",<br/>  "refresh_token": "new_refresh_token_abc456",<br/>  "expires_in": 3600<br/>}

    Note over Client,AuthServer: Phase 4: Client Management (Optional)

    Note over Client,AuthServer: 11. Client Configuration Update
    Client->>AuthServer: PUT /register/dynamic_12345<br/>Authorization: Bearer reg_token_xyz<br/>{<br/>  "client_name": "Updated App Name",<br/>  "client_uri": "https://newclient.app",<br/>  "redirect_uris": ["https://newclient.app/callback"]<br/>}
    AuthServer->>AuthServer: Validate registration token<br/>Update client metadata
    AuthServer->>Client: Return updated client info<br/>{<br/>  "client_id": "dynamic_12345",<br/>  "client_name": "Updated App Name",<br/>  "client_uri": "https://newclient.app"<br/>}