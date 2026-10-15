"""
Aegis OWASP Defensive Hardening Playbooks
Provides ready-to-deploy, copy-paste hardening configurations for major web servers and frameworks.
"""

PLAYBOOKS = {
    "nginx": {
        "title": "Nginx Security Hardening (nginx.conf / sites-available)",
        "description": "Enforces OWASP recommended security headers, blocks access to hidden dotfiles (.env, .git), disables server version tokens, and mitigates basic flood attacks.",
        "snippet": """# 1. Hide Nginx Version Token
server_tokens off;

# 2. OWASP Recommended Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none';" always;

# Enable HSTS only if serving HTTPS (Uncomment below in production)
# add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# 3. Block Hidden Files (.env, .git, etc.)
location ~ /\\. {
    deny all;
    access_log off;
    log_not_found off;
}

# 4. Block Sensitive Backup/Config Extensions
location ~* \\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$ {
    deny all;
}
"""
    },
    "apache": {
        "title": "Apache HTTP Server Hardening (.htaccess / httpd.conf)",
        "description": "Applies Apache mod_headers rules, protects hidden files, and disables directory indexing.",
        "snippet": """# 1. Disable Server Signature
ServerSignature Off
ServerTokens Prod

# 2. Disable Directory Browsing
Options -Indexes

# 3. Block Access to Dotfiles (.env, .git)
<FilesMatch "^\\.">
    Require all denied
</FilesMatch>

# 4. Inject OWASP Security Headers (Requires mod_headers)
<IfModule mod_headers.c>
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-Content-Type-Options "nosniff"
    Header set Referrer-Policy "strict-origin-when-cross-origin"
    Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    # Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>
"""
    },
    "express": {
        "title": "Express.js / Node.js Security Hardening",
        "description": "Hardens Express using Helmet, disables 'x-powered-by', and sets secure session cookie flags.",
        "snippet": """const express = require('express');
const helmet = require('helmet');
const session = require('express-session');

const app = express();

// 1. Disable Express Signature
app.disable('x-powered-by');

// 2. Enforce Helmet Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            objectSrc: ["'none'"]
        }
    },
    frameguard: { action: 'sameorigin' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// 3. Secure Cookie Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'strong-random-dev-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Defends against XSS cookie theft
        secure: process.env.NODE_ENV === 'production', // Requires HTTPS in prod
        sameSite: 'lax', // Defends against CSRF
        maxAge: 3600000 // 1 hour expiration
    }
}));
"""
    },
    "caddy": {
        "title": "Caddy Web Server Hardening (Caddyfile)",
        "description": "Modern Caddyfile directives for TLS, header hardening, and blocking sensitive routes.",
        "snippet": """localhost:8080 {
    # 1. Reverse proxy to backend
    reverse_proxy 127.0.0.1:3000

    # 2. Inject Security Headers
    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        Content-Security-Policy "default-src 'self'; script-src 'self';"
        -Server # Remove server banner
    }

    # 3. Block Sensitive Files
    @blocked path_regexp (^|/)\\.
    respond @blocked 403
}
"""
    },
    "python_fastapi": {
        "title": "Python FastAPI / Starlette Security Middleware",
        "description": "Security headers and CORS defensive restrictions for FastAPI applications.",
        "snippet": """from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

# 1. Restrict CORS to explicitly trusted origins (Never use '*' with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# 2. Custom Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self';"
        # Strip or mask server banner if present
        if "server" in response.headers:
            del response.headers["server"]
        return response

app.add_middleware(SecurityHeadersMiddleware)
"""
    }
}
