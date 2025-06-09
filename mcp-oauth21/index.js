const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Import our modules
const database = require('./database');
const authRoutes = require('./routes/auth');
const clientRoutes = require('./routes/client');
const tokenRoutes = require('./routes/token');
const metadataRoutes = require('./routes/metadata');
const resourceRoutes = require('./routes/resource');

// Initialize database with mock data
database.initialize();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

app.use((req, res, next)=>{
    console.log(`[${new Date().toISOString()}] Calling ${req.method} \t${req.url}`);
    next();
});

// Middleware to log response status codes
app.use((req, res, next) => {
    const originalEnd = res.end;

    // Override end method
    res.end = function(chunk, encoding) {
        console.log(`[${new Date().toISOString()}] Response ${res.statusCode} - ${req.method} ${req.url}`);
        return originalEnd.call(this, chunk, encoding);
    };

    next();
});


// Routes
app.use('/.well-known', metadataRoutes);
app.use('/auth', authRoutes);
app.use('/oauth', tokenRoutes);
app.use('/clients', clientRoutes);
app.use('/api', resourceRoutes);

// Home route
app.get('/', (req, res) => {
    res.json({
        message: 'OAuth2.1 Authorization Server',
        endpoints: {
            metadata: '/.well-known/oauth-authorization-server',
            authorize: '/auth/authorize',
            token: '/oauth/token',
            introspect: '/oauth/introspect',
            revoke: '/oauth/revoke',
            register: '/clients/register',
            userinfo: '/api/userinfo'
        }
    });
});

app.all('/mcp', (req, res) => {
    if(!req?.headers?.authorization?.startsWith('Bearer ')){
        return res.status(401).json({
            error: 'unauthorized',
            error_description: 'Missing or invalid authorization header'
        });
    }

    return res.json({
        message: 'OAuth2.1 Authorization Server',
        endpoints: {
            metadata: '/.well-known/oauth-authorization-server',
            authorize: '/auth/authorize',
            token: '/oauth/token',
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'internal_server_error',
        error_description: 'An internal server error occurred'
    });
});

app.listen(PORT, () => {
    console.log(`OAuth2.1 Authorization Server running on port ${PORT}`);
    console.log(`Authorization Server Metadata: http://localhost:${PORT}/.well-known/oauth-authorization-server`);
    console.log(`Protected Resource Metadata: http://localhost:${PORT}/.well-known/oauth-protected-resource`);
});

module.exports = app; 