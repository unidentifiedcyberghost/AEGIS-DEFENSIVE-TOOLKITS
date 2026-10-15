"""
Aegis Comprehensive Cyber Attack Defense Matrix
Catalogs all major web attack vectors with detailed symptom indicators,
immediate containment steps, root-cause remediation guides, and multi-framework code fixes.
"""

from typing import Dict, List, Any

ATTACK_MATRIX: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "id": "sqli",
        "name": "SQL Injection (SQLi)",
        "icon": "💥",
        "severity": "CRITICAL",
        "category": "Data Injection",
        "owasp_cwe": "OWASP A03:2021 / CWE-89",
        "description": "Attacker injects malicious SQL statements via form inputs, URL parameters, or HTTP headers (e.g., `' OR '1'='1`, `UNION SELECT`, `SLEEP(5)`). This allows unauthorized reading of databases, bypassing authentication, modifying database records, and in severe cases, executing operating system commands (via xp_cmdshell or INTO OUTFILE).",
        "symptoms": [
            "Log entries showing SQL keywords in query strings: `' UNION SELECT`, `1=1--`, `admin'--`, `BENCHMARK()`",
            "Database syntax errors visible in HTTP responses (e.g. 'You have an error in your SQL syntax', 'ORA-00933')",
            "Abnormal delays in HTTP response times (indicating Time-based Blind SQLi using SLEEP or pg_sleep)",
            "Spike in database query volume or sudden unauthorized admin accounts created"
        ],
        "immediate_actions": [
            "1. Identify the targeted endpoint and parameter from the IDS logs or web access logs.",
            "2. Immediately apply a web server or WAF filter (Nginx/ModSecurity) to reject requests containing SQL injection metacharacters (quotes, semicolons, comments '--', 'UNION').",
            "3. Temporarily restrict database user privileges: revoke DROP, ALTER, and SUPERUSER/DBA privileges from the web application DB account.",
            "4. Drop or firewall-block the attacking IP address using Aegis One-Click Firewall scripts."
        ],
        "permanent_fix": [
            "1. NEVER concatenate user input directly into SQL strings. Always use Parameterized Queries (Prepared Statements).",
            "2. If using an ORM (SQLAlchemy, Prisma, Hibernate, Entity Framework), ensure raw SQL queries (.raw(), .query()) are parameterized.",
            "3. Enforce strict input validation using allow-lists (e.g. ensure IDs are integers, usernames are alphanumeric).",
            "4. Follow the Principle of Least Privilege for the database user account used by your application."
        ],
        "code_fixes": {
            "python": """# Python (Flask / FastAPI / SQLite / PostgreSQL / MySQL)
# ❌ VULNERABLE:
# cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")

# ✅ SECURE FIX (Parameterized Query):
cursor.execute("SELECT id, username, email FROM users WHERE username = %s AND status = %s", (user_input, 'active'))
user = cursor.fetchone()

# OR Using SQLAlchemy ORM:
user = session.query(User).filter(User.username == user_input, User.status == 'active').first()
""",
            "nodejs": """// Node.js (Express with pg / mysql2 / Prisma)
// ❌ VULNERABLE:
// db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);

// ✅ SECURE FIX (Parameterized Query):
const query = 'SELECT id, email, role FROM users WHERE email = $1';
const result = await db.query(query, [req.body.email]);

// OR Using Prisma ORM (Auto-parameterized):
const user = await prisma.user.findUnique({
    where: { email: req.body.email }
});
""",
            "php": """<?php
// PHP (PDO)
// ❌ VULNERABLE:
// $conn->query("SELECT * FROM users WHERE email = '" . $_POST['email'] . "'");

// ✅ SECURE FIX (PDO Prepared Statements):
$stmt = $pdo->prepare('SELECT id, email, password_hash FROM users WHERE email = :email LIMIT 1');
$stmt->execute(['email' => filter_var($_POST['email'], FILTER_SANITIZE_EMAIL)]);
$user = $stmt->fetch();
?>
""",
            "nginx": """# Nginx WAF Filter against Common SQLi in Query Strings
location / {
    if ($query_string ~* "(union.*select|select.*from|insert.*into|drop.*table|xp_cmdshell|benchmark|sleep\\()|(--|#)") {
        return 403 "Blocked by Aegis Defensive WAF: Potential SQL Injection Detected";
    }
    try_files $uri $uri/ /index.html;
}
"""
        }
    },

    "xss": {
        "id": "xss",
        "name": "Cross-Site Scripting (XSS)",
        "icon": "💉",
        "severity": "CRITICAL",
        "category": "Script Injection",
        "owasp_cwe": "OWASP A03:2021 / CWE-79",
        "description": "Attacker injects client-side executable JavaScript into web pages viewed by other users. Classified into Reflected XSS (payload delivered via link), Stored XSS (payload stored in database, e.g. comments/profiles), and DOM-based XSS (payload executed entirely in browser DOM via innerHTML or eval). Exploitation allows session hijacking, cookie theft, keystroke logging, and website defacement.",
        "symptoms": [
            "HTTP request parameters containing `<script>`, `onerror=`, `onload=`, `javascript:`, or base64 data URIs",
            "Popups or unexpected alerts (`alert(1)`, `document.cookie`) appearing for users",
            "Users reporting unexpected redirects to external phishing domains",
            "Stolen session tokens being used from unexpected geographic regions or IP addresses"
        ],
        "immediate_actions": [
            "1. Deploy a strict Content-Security-Policy (CSP) HTTP header immediately to disable inline script execution (`'unsafe-inline'`).",
            "2. Audit database text fields (comments, profile names, bios) for stored `<script>` tags and sanitize/delete infected records.",
            "3. Enforce `HttpOnly` and `SameSite=Lax` on all session and authentication cookies so JavaScript cannot read `document.cookie`.",
            "4. Verify WAF rules block payloads containing `<script>`, `svg/onload`, and `img/onerror`."
        ],
        "permanent_fix": [
            "1. Context-Aware Output Encoding: Encode dynamic data before rendering in HTML body (`&lt;`), HTML attributes (`&quot;`), JavaScript variables, and URLs.",
            "2. Avoid dangerous DOM sinks: Never use `element.innerHTML`, `document.write()`, or `eval()`. Use `element.textContent` or framework text interpolation (`{{ }}`).",
            "3. If rich text or HTML is required, sanitize it using an established sanitizer library (DOMPurify on frontend, Bleach on Python, Sanitize-HTML on Node.js).",
            "4. Maintain a robust Content-Security-Policy with cryptographic nonces or hashes for authorized scripts."
        ],
        "code_fixes": {
            "python": """# Python (Flask / Jinja2 / Bleach)
import bleach
from markupsafe import escape

# Safe plain-text rendering (Auto-escapes < > & "):
safe_text = escape(user_input)

# If allowing safe rich-text HTML (e.g. <b>, <i>, <a>):
ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br']
ALLOWED_ATTRS = {'a': ['href', 'title', 'rel']}
clean_html = bleach.clean(user_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
""",
            "nodejs": """// Node.js (DOMPurify with JSDOM or sanitize-html)
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Sanitize untrusted user input before storing or rendering:
const cleanHtml = DOMPurify.sanitize(req.body.content);

// For React / Angular / Vue:
// Use standard JSX escaping: <div>{userInput}</div>
// NEVER use dangerouslySetInnerHTML without DOMPurify!
""",
            "php": """<?php
// PHP Output Encoding
// Always encode HTML output before printing to browser:
echo htmlspecialchars($user_input, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// For JavaScript context inside <script>:
echo json_encode($user_data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
""",
            "nginx": """# Nginx Anti-XSS Security Headers Injection
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
"""
        }
    },

    "webshell": {
        "id": "webshell",
        "name": "Web Shell & Malicious File Upload (VIRUS / Backdoor)",
        "icon": "🦠",
        "severity": "CRITICAL",
        "category": "Malware & Backdoors",
        "owasp_cwe": "OWASP A04:2021 / CWE-434",
        "description": "Attacker uploads a malicious script (e.g., PHP shell, JSP backdoor, ASPX webshell, or JavaScript cryptominer) via file upload forms, CMS plugins, or unauthenticated file upload endpoints. Once uploaded, the attacker navigates to the file path to execute arbitrary operating system commands, install persistent backdoors, deface the website, or encrypt server files (Ransomware).",
        "symptoms": [
            "New, unexpected `.php`, `.phtml`, `.jsp`, `.aspx`, or `.cgi` files appearing in `/uploads`, `/static`, or `/images` directories",
            "Files with obfuscated execution primitives: `eval(base64_decode())`, `passthru()`, `assert()`, `gzinflate()`",
            "Unusual outbound network connections originating from the web server process (reverse shells on ports 4444, 1337)",
            "Web access logs showing POST requests to obscure files with parameters like `?pass=`, `?cmd=`, `?c=`"
        ],
        "immediate_actions": [
            "1. Run Aegis Category 3 Malware Scanner immediately to detect and quarantine infected files.",
            "2. Disable script execution in all public upload directories immediately via web server config (Nginx/Apache).",
            "3. Revoke write permissions for the web server user on source code and web root directories (`chmod -R 555` or read-only mount).",
            "4. Inspect current network connections (`netstat -ano` or `lsof -i`) to kill any active reverse shell processes."
        ],
        "permanent_fix": [
            "1. Store uploaded files completely OUTSIDE the web root (or in private S3/GCS buckets with presigned URLs).",
            "2. Rename all uploaded files upon receipt using random UUIDs (e.g., `uuid4() + '.jpg'`) rather than trusting user filenames.",
            "3. Validate file contents via binary magic numbers/MIME sniffing (e.g., `python-magic`), NOT just client-supplied extensions.",
            "4. Re-encode uploaded images using an image library (Pillow / ImageMagick) to strip embedded PHP/polyglot payloads."
        ],
        "code_fixes": {
            "python": """# Python Secure File Upload Handler
import os
import uuid
import magic  # pip install python-magic-bin
from werkzeug.utils import secure_filename

ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/webp', 'application/pdf'}
UPLOAD_DIR = '/var/app/private_uploads'  # OUTSIDE web root!

def handle_upload(file_storage):
    # 1. Read first 2048 bytes for magic number verification
    header = file_storage.read(2048)
    file_storage.seek(0)
    mime = magic.from_buffer(header, mime=True)
    if mime not in ALLOWED_MIME_TYPES:
        raise ValueError("Malicious or unsupported file type detected!")

    # 2. Generate random UUID filename with safe extension
    ext = mime.split('/')[-1].replace('jpeg', 'jpg')
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    dest_path = os.path.join(UPLOAD_DIR, safe_name)
    file_storage.save(dest_path)
    return safe_name
""",
            "nodejs": """// Node.js (Multer with fileFilter & random filenames)
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const storage = multer.diskStorage({
    destination: '/var/private_uploads', // OUTSIDE web root
    filename: (req, file, cb) => {
        const randomName = crypto.randomBytes(16).toString('hex');
        const safeExt = path.extname(file.originalname).toLowerCase();
        if (!['.jpg', '.jpeg', '.png', '.pdf'].includes(safeExt)) {
            return cb(new Error('Disallowed file extension!'));
        }
        cb(null, `${randomName}${safeExt}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});
""",
            "nginx": """# Nginx: Disable script execution in all upload directories
location /uploads/ {
    # Prohibit execution of any script engine
    location ~ \\.(php|phtml|php5|pl|py|jsp|asp|sh|cgi)$ {
        deny all;
        return 403 "Script execution prohibited in upload directories";
    }
    # Serve only static files
    try_files $uri =404;
}
""",
            "apache": """# Apache .htaccess inside /uploads directory:
# Disable PHP and script execution completely
<FilesMatch "\\.(php|phtml|php3|php4|php5|phps|pl|py|jsp|asp|sh|cgi)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>

RemoveHandler .php .phtml .php3
RemoveType .php .phtml .php3
php_flag engine off
"""
        }
    },

    "rce": {
        "id": "rce",
        "name": "Command Injection / Remote Code Execution (RCE)",
        "icon": "⚡",
        "severity": "CRITICAL",
        "category": "Code Execution",
        "owasp_cwe": "OWASP A03:2021 / CWE-78",
        "description": "Attacker injects operating system commands through vulnerable inputs that are passed to system shells (e.g., `os.system()`, `exec()`, `passthru()`, `child_process.exec()`). Using command separators like `;`, `&&`, `|`, or backticks, attackers execute shell commands with the privileges of the web application server, taking total control of the host.",
        "symptoms": [
            "Requests containing shell characters: `; whoami`, `| cat /etc/passwd`, `&& ping`, `` `id` ``",
            "New unfamiliar listening ports or outbound traffic to unknown foreign IPs",
            "Sudden creation of new system users or modified `/etc/passwd` / Windows SAM registries",
            "High CPU usage from rogue background mining processes (`xmrig`, `kdevtmpfsi`)"
        ],
        "immediate_actions": [
            "1. Disconnect the server from the public internet or place it behind an emergency WAF filter.",
            "2. Kill any suspicious child processes spawned by the web server (look for `sh`, `bash`, `cmd.exe`, `powershell.exe`).",
            "3. Search source code for dangerous system call functions (`system`, `popen`, `exec`, `eval`) and comment them out.",
            "4. Freeze application logs and create a forensic snapshot before any evidence is overwritten."
        ],
        "permanent_fix": [
            "1. AVOID invoking OS shell commands from web applications whenever possible. Use native language APIs or libraries instead.",
            "2. If external commands MUST be run, use API signatures that pass arguments as structured arrays without invoking a shell (e.g., `subprocess.run(['ping', '-c', '1', ip], shell=False)`).",
            "3. Run web servers inside unprivileged Docker containers or chroot jails with read-only root filesystems.",
            "4. Restrict web server user permissions (deny sudo, deny shell access with `/sbin/nologin`)."
        ],
        "code_fixes": {
            "python": """# Python Safe Subprocess Execution
# ❌ DANGEROUS:
# os.system("ping -c 1 " + user_input)
# subprocess.Popen(f"convert {file} output.png", shell=True)

# ✅ SECURE FIX (shell=False with argument list):
import subprocess
import ipaddress

# Validate input strictly:
try:
    clean_ip = str(ipaddress.ip_address(user_input.strip()))
except ValueError:
    raise ValueError("Invalid IP address format")

# Execute safely without shell interpolation:
result = subprocess.run(
    ["ping", "-c", "1", clean_ip],
    capture_output=True,
    text=True,
    shell=False,  # CRITICAL: Prevents command chaining (; | &&)
    timeout=5
)
""",
            "nodejs": """// Node.js (child_process.execFile instead of exec)
// ❌ DANGEROUS:
// const { exec } = require('child_process');
// exec(`cat ${req.query.file}`, callback);

// ✅ SECURE FIX (execFile with arguments array):
const { execFile } = require('child_process');
const path = require('path');

// Pass arguments as a discrete array, NO shell is spawned:
execFile('/usr/bin/git', ['log', '-n', '5', '--oneline'], (error, stdout) => {
    if (error) throw error;
    console.log(stdout);
});
""",
            "nginx": """# Nginx WAF Filter against Command Injection Probes
location / {
    if ($query_string ~* "(;|\\|\\||&&|\\||`|>|<|\\b(nc|ncat|bash|sh|cmd|powershell|curl|wget)\\b)") {
        return 403 "Blocked by Aegis Defensive WAF: Potential Command Injection Detected";
    }
    try_files $uri $uri/ /index.html;
}
"""
        }
    },

    "path_traversal": {
        "id": "path_traversal",
        "name": "Path Traversal & Local File Inclusion (LFI)",
        "icon": "📂",
        "severity": "HIGH",
        "category": "File Access",
        "owasp_cwe": "OWASP A01:2021 / CWE-22",
        "description": "Attacker manipulates file path parameters using dot-dot-slash (`../`, `..\\`, `%2e%2e%2f`) sequences to access files and directories located outside the web root folder. This permits unauthorized reading of configuration files (`.env`, `wp-config.php`), operating system files (`/etc/passwd`, `C:\\Windows\\win.ini`), and sensitive source code.",
        "symptoms": [
            "Requests with `../`, `..\\`, `%2e%2e%2f`, `..%2f`, or null bytes `%00` in URL query parameters",
            "Attempts to read `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, or `boot.ini`",
            "Log entries showing 200 OK responses on requests with `file=../../../../`"
        ],
        "immediate_actions": [
            "1. Block requests containing `..` or `%2e%2e` at the reverse proxy/web server layer.",
            "2. Audit all endpoints that take a `filename`, `path`, `page`, `doc`, or `template` query parameter.",
            "3. Ensure the web server process user cannot read files outside its designated document root."
        ],
        "permanent_fix": [
            "1. Use an allow-list of known, permitted file identifiers (e.g. map `id=1` -> `page1.html`).",
            "2. Resolve the absolute canonical path using `os.path.realpath` / `path.resolve` and verify that the target path begins with the base directory.",
            "3. Strip all directory separator characters (`/`, `\\`) from user-supplied filename inputs."
        ],
        "code_fixes": {
            "python": """# Python Safe Path Resolution
import os

BASE_DIR = os.path.abspath("/var/www/static_docs")

def safe_read_file(user_filename):
    # 1. Strip directories, keep only the basename
    safe_name = os.path.basename(user_filename)
    
    # 2. Build full path and canonicalize
    target_path = os.path.abspath(os.path.join(BASE_DIR, safe_name))
    
    # 3. CRITICAL: Verify path does not escape BASE_DIR
    if os.path.commonpath([BASE_DIR, target_path]) != BASE_DIR:
        raise PermissionError("Path traversal attempt detected!")
        
    with open(target_path, 'r', encoding='utf-8') as f:
        return f.read()
""",
            "nodejs": """// Node.js Safe Path Resolution
const path = require('path');
const fs = require('fs');

const SAFE_BASE = path.resolve('/var/www/static_docs');

function safeReadFile(userFilename) {
    const safeName = path.basename(userFilename);
    const targetPath = path.resolve(SAFE_BASE, safeName);

    // Verify target starts with SAFE_BASE
    if (!targetPath.startsWith(SAFE_BASE)) {
        throw new Error('Path traversal attempt detected!');
    }

    return fs.readFileSync(targetPath, 'utf8');
}
""",
            "nginx": """# Nginx Traversal Deny Rule
location ~ (\\.\\./|\\.\\.\\\\|%2e%2e) {
    deny all;
    return 403 "Blocked: Directory traversal disallowed";
}
"""
        }
    },

    "ddos_flood": {
        "id": "ddos_flood",
        "name": "DDoS & HTTP Layer 7 Flood / Rapid Request Flooding",
        "icon": "🌊",
        "severity": "HIGH",
        "category": "Denial of Service",
        "owasp_cwe": "OWASP A04:2021 / CWE-400",
        "description": "Attacker floods the web application with high volumes of HTTP GET/POST requests, Slowloris partial connections, or resource-heavy database queries (e.g., unpaginated search queries). This saturates web server worker threads, CPU, and network bandwidth, resulting in legitimate users receiving 502 Bad Gateway or 504 Gateway Timeout errors.",
        "symptoms": [
            "Sudden spike in HTTP requests per second (RPS) from a single IP or distributed botnet",
            "Server CPU spikes to 100%, RAM exhaustion, or worker thread pool saturation",
            "Legitimate users experiencing timeouts or 502/503/504 HTTP status codes",
            "High concentration of requests to expensive computation endpoints (`/search`, `/export`, `/login`)"
        ],
        "immediate_actions": [
            "1. Activate Cloudflare 'Under Attack Mode' or reverse proxy DDoS mitigation shield.",
            "2. Apply rate-limiting at the Nginx/Caddy reverse proxy layer (e.g. max 10 requests/second per IP).",
            "3. Identify top attacking IP addresses from access logs and drop them with Aegis One-Click Firewall script.",
            "4. Temporarily disable heavy unindexed search or resource-intensive report export endpoints."
        ],
        "permanent_fix": [
            "1. Implement rate limiting and request throttling per IP / API key (using Redis token bucket algorithm).",
            "2. Enforce strict timeouts on idle TCP connections (keepalive_timeout 15s) to defend against Slowloris.",
            "3. Cache static assets and frequent database query responses using Redis / Varnish / Cloud CDN.",
            "4. Enforce mandatory pagination (`limit` & `offset`) on all database query endpoints."
        ],
        "code_fixes": {
            "nginx": """# Nginx Rate Limiting & Connection Throttling
# In http {} block:
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

# In server {} or location {} block:
location / {
    limit_req zone=one burst=20 nodelay;
    limit_conn addr 10;
    
    # Slowloris Defense Timeouts:
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 15s;
    send_timeout 10s;
}
""",
            "python": """# Python (Flask-Limiter / SlowAPI for FastAPI)
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"
)

@app.route("/api/search")
@limiter.limit("5 per minute")  # Strict limit on resource-heavy route
def heavy_search():
    return {"status": "ok"}
"""
        }
    },

    "bruteforce": {
        "id": "bruteforce",
        "name": "Brute Force & Credential Stuffing",
        "icon": "🔐",
        "severity": "HIGH",
        "category": "Authentication",
        "owasp_cwe": "OWASP A07:2021 / CWE-307",
        "description": "Attacker uses automated tools (Hydra, Burp Suite, Python scripts) to guess passwords or test millions of leaked credential combinations against login endpoints (`/login`, `/wp-login.php`, `/admin`). Successful attacks compromise user accounts and administrative dashboards.",
        "symptoms": [
            "Hundreds of POST requests per minute targeting authentication endpoints (`/login`, `/api/auth`)",
            "High ratio of 401 Unauthorized or 403 Forbidden responses compared to normal traffic",
            "Multiple failed login attempts across different usernames from the same IP address (or single username from multiple IPs)",
            "User complaints of unexpected account lockout notifications"
        ],
        "immediate_actions": [
            "1. Impose immediate IP-based rate limiting on the `/login` endpoint (max 5 attempts per 15 minutes).",
            "2. Temporarily enable CAPTCHA (Cloudflare Turnstile or reCAPTCHA v3) on all authentication forms.",
            "3. Enforce an account lockout policy (lock account for 15 minutes after 5 consecutive failed attempts).",
            "4. Require Multi-Factor Authentication (MFA / 2FA) for all administrative accounts."
        ],
        "permanent_fix": [
            "1. Implement Multi-Factor Authentication (TOTP via Authenticator apps or FIDO2/WebAuthn).",
            "2. Use modern, slow, memory-hard password hashing algorithms (Argon2id or bcrypt with cost factor >= 12).",
            "3. Check user passwords against known breached password lists (e.g. HaveIBeenPwned API) during registration/change.",
            "4. Deploy automated account lockout with exponential backoff delays on consecutive failed logins."
        ],
        "code_fixes": {
            "python": """# Python (bcrypt with exponential backoff & lockout)
import bcrypt
import time

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Uses bcrypt's built-in constant-time comparison to prevent timing attacks
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Example lockout check using Redis:
def check_login_attempts(username, ip_address, redis_client):
    key = f"login_attempts:{username}:{ip_address}"
    attempts = redis_client.get(key)
    if attempts and int(attempts) >= 5:
        raise PermissionError("Account temporarily locked due to too many failed attempts. Try again in 15 minutes.")
""",
            "nginx": """# Nginx Fail2Ban style limit for Login route
limit_req_zone $binary_remote_addr zone=login_zone:10m rate=1r/s;

location /login {
    limit_req zone=login_zone burst=5 nodelay;
    proxy_pass http://backend;
}
"""
        }
    },

    "env_leak": {
        "id": "env_leak",
        "name": "Sensitive File Exposure (.env, .git, Private Keys, DB Backups)",
        "icon": "🔑",
        "severity": "CRITICAL",
        "category": "Information Disclosure",
        "owasp_cwe": "OWASP A01:2021 / CWE-552",
        "description": "Sensitive application configuration files (such as `.env`, `.git/`, `.aws/credentials`, `id_rsa`, `backup.sql`, `config.php.bak`) are inadvertently left inside the web server's public document root. Attackers download these files to harvest database passwords, API keys, encryption secrets, and private source code, resulting in total server compromise.",
        "symptoms": [
            "HTTP access logs showing scans for `/.env`, `/.git/HEAD`, `/wp-config.php.bak`, `/backup.sql`, `/.aws/credentials`",
            "Secret credentials being used from unauthorized IPs to access cloud providers (AWS, GCP, GitHub)",
            "Web auditor (Aegis Cat 1) reporting 200 OK on requests to `/.env`"
        ],
        "immediate_actions": [
            "1. Configure web server (Nginx/Apache) to return 403 Forbidden or 404 Not Found for any file starting with `.` or ending in `.sql`, `.bak`, `.env`.",
            "2. IMMEDIATELY ROTATE all credentials, passwords, and API keys present in the exposed `.env` file (treat them as fully compromised).",
            "3. Move the `.env` file and private repositories completely outside the web server public document root.",
            "4. Check git commit history to ensure `.env` was never committed into public GitHub repositories."
        ],
        "permanent_fix": [
            "1. Set DocumentRoot strictly to a dedicated public folder (e.g. `/var/www/myproject/public` or `dist/`), NEVER the project root directory.",
            "2. Add `.env`, `*.pem`, `*.key`, `*.sql`, `*.bak` to your root `.gitignore` file.",
            "3. Use environment variables directly (injected via Docker / systemd / Kubernetes secrets) instead of static `.env` files in production.",
            "4. Run Aegis Automated Vulnerability Audits before every production deployment."
        ],
        "code_fixes": {
            "nginx": """# Nginx: Block all dotfiles (.env, .git) and backup extensions
location ~ /\\. {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}

location ~* \\.(bak|config|sql|ini|log|sh|inc|swp|dist|pem|key|env)$ {
    deny all;
    return 404;
}
""",
            "apache": """# Apache .htaccess: Deny access to sensitive files
<FilesMatch "^\\.">
    Require all denied
</FilesMatch>

<FilesMatch "\\.(env|sql|bak|key|pem|log|ini|sh)$">
    Require all denied
</FilesMatch>
"""
        }
    },

    "csrf": {
        "id": "csrf",
        "name": "Cross-Site Request Forgery (CSRF)",
        "icon": "🎭",
        "severity": "MEDIUM",
        "category": "Session Integrity",
        "owasp_cwe": "OWASP A01:2021 / CWE-352",
        "description": "Attacker tricks an authenticated user into clicking a link or loading a malicious third-party webpage that silently submits state-changing HTTP requests (such as transferring funds, updating email addresses, or changing passwords) using the victim's valid browser session cookies.",
        "symptoms": [
            "State-changing actions (password changes, profile updates) occurring without matching user activity",
            "Absence of anti-CSRF tokens in POST/PUT/DELETE forms and AJAX requests",
            "Session cookies lacking the `SameSite` attribute"
        ],
        "immediate_actions": [
            "1. Enforce `SameSite=Lax` or `SameSite=Strict` on all authentication and session cookies.",
            "2. Require current password re-authentication for critical operations (email change, password reset).",
            "3. Enable CSRF middleware in your web framework (e.g., Flask-WTF, csurf, Django CSRF)."
        ],
        "permanent_fix": [
            "1. Use cryptographically strong, unique Anti-CSRF Synchronizer Tokens (validated on every state-changing request).",
            "2. Set session cookie attributes: `Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax`.",
            "3. Verify the `Origin` and `Referer` headers on all incoming POST requests to ensure they match your domain."
        ],
        "code_fixes": {
            "python": """# Python (Flask-WTF / CSRFProtect)
from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'strong-production-random-secret-key'
csrf = CSRFProtect(app)

# In Jinja2 forms, include the token:
# <form method="post">
#     <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
#     ...
# </form>
""",
            "nodejs": """// Node.js (Cookie SameSite enforcement)
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        httpOnly: true,
        secure: true,      // HTTPS required
        sameSite: 'lax'    // Blocks cross-site unauthorized requests
    }
}));
"""
        }
    },

    "ssrf": {
        "id": "ssrf",
        "name": "Server-Side Request Forgery (SSRF)",
        "icon": "🌐",
        "severity": "HIGH",
        "category": "Network Pivoting",
        "owasp_cwe": "OWASP A10:2021 / CWE-918",
        "description": "Attacker abuses features that fetch remote URLs (such as webhook integrations, image importers, PDF generators) to induce the web server into making HTTP requests to internal, private network addresses. This allows attackers to access cloud metadata instances (`http://169.254.169.254`), internal microservices, and localhost admin interfaces (`http://127.0.0.1:8000`).",
        "symptoms": [
            "Requests to fetch endpoints containing `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254`, or private IPs (`10.0.0.0/8`, `192.168.0.0/16`)",
            "Attacker attempting to read AWS/GCP cloud IAM credentials via the instance metadata service",
            "Unexpected internal port scanning originating from the web server itself"
        ],
        "immediate_actions": [
            "1. Block outbound egress traffic from web servers to link-local address `169.254.169.254` (cloud metadata service).",
            "2. Implement an egress firewall rule preventing web servers from connecting to private internal subnets (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).",
            "3. Restrict URL-fetching features to an explicit whitelist of trusted external domains."
        ],
        "permanent_fix": [
            "1. Validate and resolve user-supplied hostnames via DNS BEFORE making requests, and verify the resolved IP is not private or loopback.",
            "2. Disable HTTP redirects (or validate the redirect target IP against the private subnet blacklist).",
            "3. Use IMDSv2 (Session Token required) on AWS EC2 to prevent SSRF from reading instance metadata.",
            "4. Run URL-fetching services in an isolated DMZ network with no route to internal infrastructure."
        ],
        "code_fixes": {
            "python": """# Python Safe URL Fetcher (Anti-SSRF Validator)
import ipaddress
import socket
import urllib.parse
import requests

FORBIDDEN_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),       # Localhost
    ipaddress.ip_network('10.0.0.0/8'),        # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),     # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),    # Private Class C
    ipaddress.ip_network('169.254.0.0/16'),    # Link-local / Cloud Metadata
    ipaddress.ip_network('::1/128'),           # IPv6 Localhost
]

def safe_fetch(url: str, timeout: int = 5):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Only HTTP/HTTPS allowed")

    # Resolve IP address to prevent DNS rebinding:
    host = parsed.hostname
    ip_str = socket.gethostbyname(host)
    ip_obj = ipaddress.ip_address(ip_str)

    # Verify IP is not private or link-local:
    for forbidden in FORBIDDEN_NETWORKS:
        if ip_obj in forbidden:
            raise PermissionError(f"Access to private/internal network ({ip_str}) is prohibited!")

    # Fetch with redirects disabled:
    return requests.get(url, allow_redirects=False, timeout=timeout)
"""
        }
    }
}
