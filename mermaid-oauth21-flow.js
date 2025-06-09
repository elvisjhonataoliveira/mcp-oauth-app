sequenceDiagram
    participant Client as Client Application
    participant Browser as User Browser
    participant AuthServer as OAuth2.1 Server
    participant User as Resource Owner
    participant ResourceServer as Resource Server

    Note over Client: 1. Generate PKCE Challenge
    Client->>Client: Generate code_verifier<br/>Generate code_challenge = SHA256(code_verifier)

    Note over Client,AuthServer: 2. Authorization Request
    Client->>Browser: Redirect to authorization endpoint
    Browser->>AuthServer: GET /oauth/authorize<br/>?response_type=code<br/>&client_id=test-client<br/>&redirect_uri=callback<br/>&scope=read profile email<br/>&state=random-state<br/>&code_challenge=CHALLENGE<br/>&code_challenge_method=S256

    Note over AuthServer,User: 3. User Authentication
    AuthServer->>Browser: Return login form<br/>(session_id provided)
    Browser->>User: Display login form
    User->>Browser: Enter credentials
    Browser->>AuthServer: POST /auth/login<br/>{username, password, session_id}
    AuthServer->>AuthServer: Validate credentials
    AuthServer->>Browser: Login successful

    Note over AuthServer,User: 4. User Consent
    Browser->>User: Display consent form<br/>(requested scopes)
    User->>Browser: Grant/Deny permission
    Browser->>AuthServer: POST /oauth/consent<br/>{action: "allow", session_id}

    Note over AuthServer,Client: 5. Authorization Response
    AuthServer->>AuthServer: Generate authorization_code<br/>Store with code_challenge
    AuthServer->>Browser: Redirect to callback URI<br/>?code=AUTH_CODE&state=STATE
    Browser->>Client: Authorization code received

    Note over Client,AuthServer: 6. Token Exchange
    Client->>AuthServer: POST /oauth/token<br/>{<br/>  grant_type: "authorization_code",<br/>  client_id: "test-client",<br/>  client_secret: "test-secret",<br/>  code: "AUTH_CODE",<br/>  redirect_uri: "callback",<br/>  code_verifier: "VERIFIER"<br/>}
    
    AuthServer->>AuthServer: Verify PKCE:<br/>SHA256(code_verifier) === code_challenge
    AuthServer->>AuthServer: Generate access_token (JWT)<br/>Generate refresh_token
    AuthServer->>Client: Return tokens<br/>{<br/>  access_token: "JWT_TOKEN",<br/>  token_type: "Bearer",<br/>  expires_in: 3600,<br/>  refresh_token: "REFRESH_TOKEN",<br/>  scope: "read profile email"<br/>}

    Note over Client,ResourceServer: 7. Access Protected Resources
    Client->>ResourceServer: GET /auth/userinfo<br/>Authorization: Bearer JWT_TOKEN
    ResourceServer->>AuthServer: Validate token (introspection)
    AuthServer->>ResourceServer: Token valid + user info
    ResourceServer->>Client: Return protected resource<br/>{<br/>  sub: "user_id",<br/>  username: "john.doe",<br/>  email: "john.doe@example.com",<br/>  name: "John Doe"<br/>}

    Note over Client,AuthServer: 8. Token Refresh (Optional)
    Client->>AuthServer: POST /oauth/token<br/>{<br/>  grant_type: "refresh_token",<br/>  client_id: "test-client",<br/>  client_secret: "test-secret",<br/>  refresh_token: "REFRESH_TOKEN"<br/>}
    AuthServer->>AuthServer: Validate refresh token
    AuthServer->>Client: Return new tokens<br/>{<br/>  access_token: "NEW_JWT_TOKEN",<br/>  refresh_token: "NEW_REFRESH_TOKEN"<br/>}