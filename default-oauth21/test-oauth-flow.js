const crypto = require('crypto');
const http = require('http');

// Test configuration
const SERVER_URL = 'http://localhost:3000';
const CLIENT_ID = 'test-client';
const CLIENT_SECRET = 'test-secret';
const REDIRECT_URI = 'http://localhost:3001/callback';
const USERNAME = 'john.doe';
const PASSWORD = 'password123';

// PKCE functions
function generatePKCEChallenge() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  
  return { codeVerifier, codeChallenge };
}

// HTTP helper
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || 80,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    };

    const req = http.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          resolve({ status: res.statusCode, data: jsonData });
        } catch (e) {
          resolve({ status: res.statusCode, data });
        }
      });
    });

    req.on('error', reject);
    if (options.body) req.write(JSON.stringify(options.body));
    req.end();
  });
}

async function testOAuth2Flow() {
  console.log('🚀 Starting OAuth2.1 Flow Test\n');

  try {
    // Step 1: PKCE
    const { codeVerifier, codeChallenge } = generatePKCEChallenge();
    console.log('✅ Step 1: PKCE challenge generated\n');

    // Step 2: Authorization
    const state = crypto.randomBytes(16).toString('hex');
    const authUrl = new URL('/oauth/authorize', SERVER_URL);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('scope', 'read profile email');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authResponse = await makeRequest(authUrl.toString());
    console.log('✅ Step 2: Authorization started');
    console.log(`   Status: ${authResponse.status}`);
    
    if (authResponse.status !== 200) {
      throw new Error(`Authorization failed: ${authResponse.data.error_description}`);
    }

    const sessionId = authResponse.data.session_id;
    console.log(`   Session ID: ${sessionId}\n`);

    // Step 3: Login
    const loginResponse = await makeRequest(`${SERVER_URL}/auth/login`, {
      method: 'POST',
      headers: { 'X-Session-Id': sessionId },
      body: { username: USERNAME, password: PASSWORD, session_id: sessionId }
    });

    console.log('✅ Step 3: User login');
    console.log(`   Status: ${loginResponse.status}`);
    
    if (loginResponse.status !== 200) {
      throw new Error(`Login failed: ${loginResponse.data.message}`);
    }
    console.log(`   User: ${loginResponse.data.user.username}\n`);

    // Step 4: Consent
    const consentResponse = await makeRequest(`${SERVER_URL}/oauth/consent`, {
      method: 'POST',
      headers: { 'X-Session-Id': sessionId },
      body: { action: 'allow', session_id: sessionId }
    });

    console.log('✅ Step 4: User consent');
    console.log(`   Status: ${consentResponse.status}`);
    
    if (consentResponse.status !== 200) {
      throw new Error(`Consent failed: ${consentResponse.data.message}`);
    }

    const redirectUrl = new URL(consentResponse.data.redirect_url);
    const authCode = redirectUrl.searchParams.get('code');
    console.log(`   Authorization Code: ${authCode.substring(0, 20)}...\n`);

    // Step 5: Token exchange
    const tokenResponse = await makeRequest(`${SERVER_URL}/oauth/token`, {
      method: 'POST',
      body: {
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code: authCode,
        redirect_uri: REDIRECT_URI,
        code_verifier: codeVerifier
      }
    });

    console.log('✅ Step 5: Token exchange');
    console.log(`   Status: ${tokenResponse.status}`);
    
    if (tokenResponse.status !== 200) {
      throw new Error(`Token exchange failed: ${tokenResponse.data.error_description}`);
    }

    const { access_token, refresh_token } = tokenResponse.data;
    console.log(`   Access Token: ${access_token.substring(0, 50)}...\n`);

    // Step 6: Protected resource
    const userinfoResponse = await makeRequest(`${SERVER_URL}/auth/userinfo`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${access_token}` }
    });

    console.log('✅ Step 6: Protected resource access');
    console.log(`   Status: ${userinfoResponse.status}`);
    
    if (userinfoResponse.status === 200) {
      console.log('   User Info:', JSON.stringify(userinfoResponse.data, null, 2));
    }

    console.log('\n🎉 OAuth2.1 Flow Test Completed Successfully!');

  } catch (error) {
    console.error('\n❌ Test Failed:', error.message);
    console.error('Make sure the server is running on http://localhost:3000');
  }
}

console.log('OAuth2.1 Flow Test Script');
console.log('========================\n');
setTimeout(testOAuth2Flow, 1000); 