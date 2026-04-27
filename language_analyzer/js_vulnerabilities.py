VULN_RULES = {
    "eval_usage": {
        "name": "Use of eval()",
        "severity": "critical",
        "patterns": [
            r"\beval\s*\(",
            r"\beval\s*\(\s*['\"`]",
            r"\beval\s*\(\s*\$\{",
            r"\bFunction\s*\(\s*['\"`]",
            r"\bsetTimeout\s*\(\s*['\"`]",
            r"\bsetInterval\s*\(\s*['\"`]",
            r"\bsetImmediate\s*\(\s*['\"`]",
            r"new\s+Function\s*\(",
            r"vm\.runInThisContext\s*\(",
            r"vm\.runInNewContext\s*\(",
        ],
        "description": "eval() and similar functions execute arbitrary code and enable code injection",
        "recommendations": [
            "Never use eval() with user input",
            "Use JSON.parse() instead of eval() to parse JSON",
            "Implement a secure parser or an interpreted DSL",
            "Consider using Web Workers for isolated code",
            "Use libraries like jexl or expr-eval for safe expressions"
        ]
    },
    
    "hardcoded_secrets": {
        "name": "Hardcoded Secrets",
        "severity": "critical",
        "patterns": [
            r"(?:password|passwd|pwd)\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"(?:api_key|apiKey|API_KEY)\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"(?:secret|SECRET|secret_key|secretKey)\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"(?:token|TOKEN|access_token|accessToken)\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"(?:authorization|auth|AUTHORIZATION)\s*[=:]\s*['\"](?:Bearer|Bearer\s+)[^'\"]+['\"]",
            r"(?:db_password|dbPassword|DB_PASSWORD)\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"(?:private_key|privateKey|PRIVATE_KEY)\s*[=:]\s*['\"][\s\S]*?['\"]",
            r"(?:aws_secret|AWS_SECRET|aws_access_key|AWS_ACCESS_KEY)\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"(?:stripe_key|stripeKey|STRIPE_KEY)\s*[=:]\s*['\"]sk_(?:test|live)_[^'\"]+['\"]",
            r"(?:mongodb_uri|MONGODB_URI|mongodb_password)\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]*(?:mongodb|password).*['\"]",
        ],
        "description": "Credentials, API keys, tokens, and secrets exposed in source code",
        "recommendations": [
            "Use environment variables (.env) to store secrets",
            "Use secret managers such as AWS Secrets Manager or HashiCorp Vault",
            "Never commit .env files to the repository",
            "Use .gitignore to exclude credential files",
            "Rotate all discovered credentials immediately",
            "Use libraries like dotenv to load environment variables"
        ]
    },
    
    "sql_injection": {
        "name": "SQL Injection",
        "severity": "critical",
        "patterns": [
            r"(?:query|execute|run|db\.(?:query|execute|run))\s*\(\s*['\"`].*(?:\+|\.concat|\.replace|\$\{|\`.*\$\{).*['\"`]",
            r"SELECT\s+.*\+\s*(?:req\.|params\.|query\.)",
            r"INSERT\s+INTO\s+.*\+\s*(?:req\.|params\.|query\.)",
            r"UPDATE\s+.*\+\s*(?:req\.|params\.|query\.)",
            r"DELETE\s+FROM\s+.*\+\s*(?:req\.|params\.|query\.)",
            r"db\.raw\s*\(\s*['\"`].*\+.*['\"`]",
            r"(?:sequelize|knex|typeorm)\.query\s*\(\s*['\"`].*(?:\+|\.concat|\`.*\$\{).*['\"`]",
            r"connection\.query\s*\(\s*['\"`].*(?:\+|\.concat|\$\{|\`.*\$\{).*['\"`]",
            r"mysql\.query\s*\(\s*['\"`].*(?:\+|\.concat|\$\{|\`.*\$\{).*['\"`]",
            r"pool\.query\s*\(\s*['\"`].*(?:\+|\.concat|\$\{|\`.*\$\{).*['\"`]",
        ],
        "description": "Variable concatenation in SQL queries without sanitization is vulnerable to SQL injection",
        "recommendations": [
            "Use prepared statements or parameterized queries",
            "Use ORMs like Sequelize, TypeORM, or Knex.js",
            "Validate and sanitize all user input",
            "Use a whitelist of allowed values",
            "Use stored procedures in the database",
            "Apply least-privilege principles to DB connections"
        ]
    },
    
    "command_injection": {
        "name": "Command Injection",
        "severity": "critical",
        "patterns": [
            r"(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(\s*['\"`].*(?:\+|\.concat|\$\{|\`.*\$\{).*['\"`]",
            r"(?:exec|execSync|execFile)\s*\(\s*`.*\$\{.*\}`",
            r"child_process\.(?:exec|execSync|execFile|spawn)\s*\(\s*(?:cmd|command|args).*(?:\+|\$\{)",
            r"shell\s*:\s*true[\s\S]*?(?:exec|spawn|execFile)\s*\(",
            r"bash\s*-c\s*['\"`].*(?:\+|\$\{).*['\"`]",
            r"/bin/sh\s*-c\s*['\"`].*(?:\+|\$\{).*['\"`]",
            r"(?:require|require\(['\"]child_process['\"])\s*(?:exec|spawn).*\+.*(?:user|input|query|param)",
            r"cp\.execSync\s*\(\s*`.*\$\{",
            r"require\(['\"]child_process['\"]\).*(?:exec|spawn).*\+\s*(?:req\.|params\.|query\.)",
            r"\.exec\s*\(\s*['\"`]\s*.*(?:\+|\.concat|\$\{)",
        ],
        "description": "Executing system commands with unvalidated variables enables command injection",
        "recommendations": [
            "Avoid exec(), execSync(), and spawn() with user input",
            "Use spawn() with an argument array instead of raw strings",
            "Never set shell: true unless absolutely necessary",
            "Validate and sanitize all user input",
            "Use a whitelist of allowed commands",
            "Apply least privilege to executed processes"
        ]
    },
    
    "xss_vulnerable": {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "patterns": [
            r"\.innerHTML\s*[+=]\s*(?!.*(?:sanitize|escape|DOMPurify))",
            r"\.innerHTML\s*=\s*(?:req\.|query\.|params\.|\.get\(\))",
            r"document\.write\s*\(\s*(?:req\.|query\.|params\.)",
            r"\.insertAdjacentHTML\s*\(\s*['\"]",
            r"dangerouslySetInnerHTML\s*=\s*\{",
            r"v-html\s*=",
            r"ng-bind-html\s*=",
            r"\[\s*innerHTML\s*\]\s*=",
            r"\.html\s*\(\s*(?:req\.|query\.|params\.|\.get\(\))",
            r"\.append\s*\(\s*['\"`].*<.*(?:script|img|svg).*['\"`]",
            r"response\.write\s*\(\s*(?:req\.|query\.|params\.)",
            r"res\.send\s*\(\s*['\"`].*<.*\+\s*(?:req\.|query\.|params\.)",
            r"\.html\s*\(\s*\$\{.*\}\s*\)",
            r"jQuery.*\.html\s*\(\s*(?!.*(?:sanitize|escape))",
        ],
        "description": "Direct assignment of unsanitized HTML content enables XSS",
        "recommendations": [
            "Use textContent instead of innerHTML whenever possible",
            "Sanitize all user input with DOMPurify",
            "Use Content Security Policy (CSP) headers",
            "Escape special characters (<, >, &, \", ')",
            "Use templates with auto-escaping (template literals with libraries)",
            "Set X-XSS-Protection headers"
        ]
    },
    
    "insecure_crypto": {
        "name": "Insecure Cryptography",
        "severity": "high",
        "patterns": [
            r"(?:crypto\.createHash|createHash)\s*\(\s*['\"](?:md5|sha1)['\"]",
            r"(?:crypto\.createCipher|createCipher)\s*\(",
            r"(?:crypto\.createDecipher|createDecipher)\s*\(",
            r"require\(['\"]md5['\"]\)",
            r"require\(['\"]sha1['\"]\)",
            r"bcrypt\.hash\s*\(\s*[^,]*,\s*[0-9]\s*\)",
            r"crypto\.scrypt\s*\(\s*[^,]*,\s*['\"][a-zA-Z0-9]{1,8}['\"]",
            r"\.hashSync\s*\(\s*[^,]*,\s*[0-9]\s*\)",
            r"crypto\.randomBytes\s*\(\s*(?:1|2|3|4|5)\s*\)",
            r"Math\.random\s*\(\)",
            r"jwt\.sign\s*\(\s*[^,]*,\s*['\"].*['\"]",
            r"jsonwebtoken.*sign.*(?:md5|sha1|['\"]secret['\"])",
        ],
        "description": "Weak cryptographic algorithms (MD5, SHA1) or insecure parameters",
        "recommendations": [
            "Use SHA-256 or stronger instead of MD5/SHA1",
            "Use bcrypt or scrypt for password hashing (rounds >= 10)",
            "Use crypto.createCipheriv instead of createCipher",
            "Generate random values with crypto.randomBytes()",
            "Use dedicated JWT libraries (jsonwebtoken with strong secrets)",
            "Implement key derivation functions (PBKDF2, Argon2)"
        ]
    },
    
    "path_traversal": {
        "name": "Path Traversal",
        "severity": "high",
        "patterns": [
            r"require\s*\(\s*(?:path\.join|__dirname)\s*\+\s*(?:req\.|query\.|params\.)",
            r"fs\.readFile\s*\(\s*(?:path\.|__dirname|\./).*\+\s*(?:req\.|query\.|params\.)",
            r"fs\.readFileSync\s*\(\s*(?:path\.|__dirname|\./).*\+\s*(?:req\.|query\.|params\.)",
            r"fs\.open\s*\(\s*(?:path\.|__dirname|\./).*\+\s*(?:req\.|query\.|params\.)",
            r"fs\.stat\s*\(\s*(?:path\.|__dirname|\./).*\+\s*(?:req\.|query\.|params\.)",
            r"path\.join\s*\(\s*['\"].*['\"],\s*(?:req\.|query\.|params\.)",
            r"require\s*\(\s*['\"].*\.\./",
            r"require\s*\(\s*\`.*\.\./",
            r"import\s+.*from\s+['\"].*\.\./",
            r"sendFile\s*\(\s*(?:req\.|query\.|params\.)",
            r"fs\.readdirSync\s*\(\s*(?:path\.|__dirname)\s*\+\s*(?:req\.|query\.|params\.)",
        ],
        "description": "File access with relative or unvalidated paths enables path traversal",
        "recommendations": [
            "Validate requested paths against a whitelist",
            "Use path.resolve() and verify the path stays inside the allowed directory",
            "Never allow '..' in user paths",
            "Implement base-directory sandboxing",
            "Use fs.access() before reading files",
            "Keep sensitive files outside the web root"
        ]
    },
    
    "insecure_dependencies": {
        "name": "Insecure Dependencies",
        "severity": "medium",
        "patterns": [
            r"(?:\"lodash\":|\"lodash\":|'lodash':)\s*['\"][\s\S]*?(?:[0-9]\.){2}[0-9](?:\.[0-9])?['\"]",
            r"(?:\"moment\":|'moment':)\s*['\"](?:2\.1[0-8]|2\.[0-9]\.[0-9])['\"]",
            r"(?:\"jquery\":|'jquery':)\s*['\"](?:1\.|2\.1|3\.[0-2])['\"]",
            r"(?:\"express\":|'express':)\s*['\"](?:[0-3]\.|4\.[0-9]\.[0-9])['\"]",
            r"(?:\"request\":|'request':)",
            r"(?:\"node-uuid\":|'node-uuid':)",
            r"(?:\"ejs\":|'ejs':)\s*['\"](?:[0-2]\.)['\"]",
            r"(?:\"jade\":|'jade':)",
            r"(?:\"npm\":|'npm':)\s*['\"](?:[0-5]\.)['\"]",
            r"(?:\"fs-extra\":|'fs-extra':)\s*['\"](?:[0-2]\.)['\"]",
            r"\"vulnerabilities\"\s*:\s*\[",
        ],
        "description": "Use of known library versions with documented vulnerabilities",
        "recommendations": [
            "Update all dependencies to secure versions",
            "Use npm audit to identify vulnerabilities",
            "Run npm audit fix regularly",
            "Use Dependabot or similar tools for automated updates",
            "Review the changelog before upgrading",
            "Maintain a dependency inventory in package.json"
        ]
    },
    
    "no_input_validation": {
        "name": "Missing Input Validation",
        "severity": "medium",
        "patterns": [
            r"(?:req\.body|req\.query|req\.params)\.[a-zA-Z_]\w*\s*(?:==|===|\+|-|\/|\*|>|<|\||&|&&)",
            r"\.get\s*\(\s*['\"].*['\"],\s*(?:req\.body|req\.query|req\.params)",
            r"(?:req\.body|req\.query|req\.params)\.[a-zA-Z_]\w*\s*(?:as\s+(?:string|number|int))?(?:\s*[;=+\-*/\|&]|\.)",
            r"if\s*\(\s*(?:req\.body|req\.query|req\.params)\.[a-zA-Z_]\w*\s*\)",
            r"switch\s*\(\s*(?:req\.body|req\.query|req\.params)",
            r"\.find\s*\(\s*(?:req\.body|req\.query|req\.params)\s*\)",
            r"\.filter\s*\(\s*.*(?:req\.body|req\.query|req\.params)",
            r"\.map\s*\(\s*(?:req\.body|req\.query|req\.params)",
            r"\.forEach\s*\(\s*(?:req\.body|req\.query|req\.params)",
            r"const\s+[a-zA-Z_]\w*\s*=\s*(?:req\.body|req\.query|req\.params)\.[a-zA-Z_]\w*(?:;|\s)",
        ],
        "description": "Direct access to input parameters without validation or sanitization",
        "recommendations": [
            "Use validation libraries such as joi, yup, or express-validator",
            "Implement validation middleware on routes",
            "Sanitize all user input",
            "Use specific data types (parseInt, parseFloat, etc.)",
            "Use a whitelist of allowed values",
            "Reject unexpected or out-of-range values"
        ]
    },
    
    "insecure_cors": {
        "name": "Insecure CORS",
        "severity": "medium",
        "patterns": [
            r"(?:Access-Control-Allow-Origin|origin)\s*[=:]\s*['\"]?\*['\"]?",
            r"cors\s*\(\s*\{\s*origin\s*:\s*\*\s*\}\s*\)",
            r"cors\s*\(\s*\{\s*origin\s*:\s*true\s*\}\s*\)",
            r"cors\s*\(\s*\)\s*(?=;|,|$)",
            r"allowedHeaders\s*[=:]\s*\[?\s*['\"]?\*['\"]?\s*\]?",
            r"exposedHeaders\s*[=:]\s*\[?\s*['\"]?\*['\"]?\s*\]?",
            r"credentials\s*[=:]\s*true[\s\S]*?origin\s*[=:]\s*\*",
            r"\.header\s*\(\s*['\"]Access-Control-Allow-Origin['\"],\s*['\"]?\*['\"]?\s*\)",
            r"res\.header\s*\(\s*['\"]Access-Control-Allow-Origin['\"],\s*['\"]?\*['\"]?\s*\)",
            r"setHeader\s*\(\s*['\"]Access-Control-Allow-Origin['\"],\s*['\"]?\*['\"]?\s*\)",
        ],
        "description": "CORS configured to allow any origin (*) enables unauthorized access",
        "recommendations": [
            "Explicitly specify allowed origins",
            "Use a whitelist of authorized domains",
            "Never use wildcard (*) with credentials: true",
            "Validate origin on every request",
            "Implement preflight requests for complex methods",
            "Enable CORS only for endpoints that require it"
        ]
    },
    
    "prototype_pollution": {
        "name": "Prototype Pollution",
        "severity": "high",
        "patterns": [
            r"\.constructor\s*\[.*\]\s*=",
            r"Object\.assign\s*\(\s*\{\}[\s\S]*?(?:req\.body|query|params)",
            r"\.prototype\s*\[.*\]\s*=.*(?:req\.|user\.|input)",
            r"lodash\.merge\s*\(\s*\{\}[\s\S]*?(?:req\.|query\.|params\.)",
            r"JSON\.parse\s*\(\s*.*\)[\s\S]*?\.constructor",
            r"Object\.create\s*\(\s*(?:req\.body|query|params)",
            r"spread operator.*\.\.\.\s*(?:req\.body|query|params)",
            r"\{\s*\.\.\.\s*(?:req\.body|query|params)\s*\}",
            r"for\s*\(\s*.*\s+in\s+(?:req\.body|query|params|obj)\s*\)",
            r"Object\.keys.*\.forEach\s*\([\s\S]*?obj\[.*\]\s*=",
        ],
        "description": "Assignment to properties without validation enables object prototype pollution",
        "recommendations": [
            "Use Object.hasOwnProperty() to verify properties",
            "Use Map instead of plain objects when possible",
            "Validate property names against a whitelist",
            "Use Object.freeze() to lock critical prototypes",
            "Avoid Object.assign() and spread operators with untrusted data",
            "Use libraries like lodash with security options enabled"
        ]
    },

    "idor_insecure_direct_object_reference": {
        "name": "IDOR (Insecure Direct Object Reference)",
        "severity": "high",
        "patterns": [
            r"router\.(?:get|put|patch|delete)\s*\(\s*['\"]/.*:id",
            r"(?:req\.params|req\.query)\.(?:id|userId|accountId|orderId)",
            r"(?:findByPk|findById|findOne)\s*\(\s*(?:req\.params|req\.query)\.(?:id|userId|accountId|orderId)",
            r"where\s*:\s*\{\s*id\s*:\s*(?:req\.params|req\.query)\.(?:id|userId)",
            r"\.destroy\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*(?:req\.params|req\.query)",
            r"\.update\s*\(\s*.*\{\s*where\s*:\s*\{\s*id\s*:\s*(?:req\.params|req\.query)",
            r"db\.(?:users|accounts|orders)\.(?:find|get|delete|update)\s*\(\s*(?:req\.params|req\.query)",
            r"/api/(?:users|accounts|orders)/\$\{.*(?:id|userId)",
            r"req\.user\.(?:id|sub)\s*\|\|\s*(?:req\.params|req\.query)\.(?:id|userId)",
            r"authorize\s*\(\s*\)\s*;\s*(?:.*)\.(?:findById|findByPk)\s*\(\s*req\.params\.id"
        ],
        "description": "Direct access to resources by user-controlled ID without ownership/authorization checks (IDOR)",
        "recommendations": [
            "Verify resource ownership before returning or modifying data",
            "Do not trust IDs received from params/query/body",
            "Apply object-level authorization controls (ABAC/RBAC per resource)",
            "Use indirect or opaque IDs when possible",
            "Log and monitor access to sensitive objects",
            "Add negative tests for cross-user access"
        ]
    },

    "debug_endpoint_exposure": {
        "name": "Sensitive Information Exposure (Debug Endpoint)",
        "severity": "medium",
        "patterns": [
            r"app\.get\s*\(\s*['\"]/debug",
            r"router\.get\s*\(\s*['\"]/debug",
            r"app\.get\s*\(\s*['\"]/__debug__",
            r"app\.get\s*\(\s*['\"]/internal",
            r"res\.json\s*\(\s*\{\s*(?:stack|trace|config|env|process\.env)",
            r"console\.log\s*\(\s*(?:process\.env|req\.headers|req\.cookies)",
            r"errorHandler\s*\(\s*\{\s*showStack\s*:\s*true",
            r"NODE_ENV\s*!==\s*['\"]production['\"]",
            r"app\.use\s*\(\s*require\(['\"]morgan['\"]\)\s*\(\s*['\"]dev['\"]\)",
            r"res\.send\s*\(\s*err\.stack"
        ],
        "description": "Debug endpoints or responses may expose stack traces, environment variables, and sensitive configuration",
        "recommendations": [
            "Disable debug endpoints in production",
            "Do not return stack traces to clients",
            "Filter secrets in logs and error responses",
            "Protect internal routes with strong authentication",
            "Use generic error handling for clients",
            "Set NODE_ENV=production in deployments"
        ]
    },

    "jwt_auth_mismanagement": {
        "name": "JWT Authentication Mismanagement",
        "severity": "high",
        "patterns": [
            r"jwt\.sign\s*\(\s*.*,\s*['\"][^'\"]+['\"]",
            r"jwt\.verify\s*\(\s*token\s*,\s*['\"][^'\"]+['\"]",
            r"ignoreExpiration\s*:\s*true",
            r"options\s*:\s*\{\s*ignoreExpiration\s*:\s*true",
            r"expiresIn\s*:\s*['\"](?:365d|10y|9999)",
            r"algorithm\s*:\s*['\"]none['\"]",
            r"jwt\.decode\s*\(\s*token\s*\)",
            r"Authorization\s*[:=]\s*['\"]Bearer\s+",
            r"SECRET(?:_KEY)?\s*[:=]\s*['\"][^'\"]+['\"]",
            r"allowInvalidAsymmetricKeyTypes\s*:\s*true"
        ],
        "description": "Insecure JWT configurations (hardcoded secret, weak expiration, or incomplete validation)",
        "recommendations": [
            "Store JWT secrets outside source code",
            "Validate signature, issuer, audience, and expiration",
            "Avoid insecure algorithms such as none",
            "Use short expirations and key rotation",
            "Do not use decode() for authorization decisions",
            "Implement revocation/blacklists for compromised tokens"
        ]
    },

    "jwt_forgery_token_manipulation": {
        "name": "JWT Forgery (Token Manipulation)",
        "severity": "critical",
        "patterns": [
            r"token\.split\(['\"]\\.['\"]\)\[1\]",
            r"JSON\.parse\s*\(\s*atob\s*\(\s*token\.split",
            r"Buffer\.from\s*\(\s*token\.split\(['\"]\\.['\"]\)\[1\]",
            r"payload\[['\"](?:role|admin|isAdmin)['\"]\]\s*=",
            r"jwt\.decode\s*\(\s*token\s*,\s*\{\s*complete\s*:\s*true",
            r"verify_signature\s*:\s*false",
            r"algorithms\s*:\s*\[\s*['\"]\*['\"]\s*\]",
            r"none\s*algorithm",
            r"token\s*=\s*header\s*\+\s*['\"]\\.['\"]\s*\+\s*payload\s*\+\s*['\"]\\.['\"]",
            r"res\.locals\.(?:user|claims)\s*=\s*jwt\.decode"
        ],
        "description": "JWT payload manipulation without robust signature verification enables privilege escalation",
        "recommendations": [
            "Use jwt.verify() with an explicit list of allowed algorithms",
            "Reject tokens with alg=none",
            "Never trust decoded claims without signature verification",
            "Validate aud/iss/sub and expiration skew settings",
            "Sign with strong keys and rotate them periodically",
            "Log attempts involving invalid or manipulated tokens"
        ]
    }
}
