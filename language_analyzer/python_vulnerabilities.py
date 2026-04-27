PYTHON_VULN_RULES = {
    "eval_exec_usage": {
        "name": "eval() and exec() Usage",
        "severity": "critical",
        "patterns": [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
            r"__import__\s*\(",
            r"exec\s*\(",
            r"eval\s*\(\s*input\s*\(",
            r"exec\s*\(\s*input\s*\(",
            r"compile\s*\(\s*.*\bexec\b",
            r"ast\.literal_eval\s*\(\s*(?![\s]*\[|[\s]*\{)",
            r"pickle\.loads\s*\(",
        ],
        "description": "eval() and exec() execute arbitrary Python code, allowing malicious code injection",
        "recommendations": [
            "Never use eval() or exec() with user input",
            "To evaluate expressions, use ast.literal_eval() only with literals",
            "For JSON, use json.loads() instead of eval()",
            "For configuration, use libraries like configparser",
            "Consider using sandboxes like RestrictedPython",
            "Implement whitelisting of allowed functions"
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
            r"(?:db_password|dbPassword|DB_PASSWORD)\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"(?:django\.db\.backends\.postgresql|mysql|oracle).*password.*['\"][^'\"]+['\"]",
            r"os\.environ\[[\s]*['\"](?:SECRET|PASSWORD|API|TOKEN)",
            r"settings\.\w*\s*=\s*['\"](?:sk_|pk_|ghp_)[^'\"]*['\"]",
            r"DATABASE_URL\s*=\s*['\"].*:.*@",
            r"(?:aws_access_key|AWS_ACCESS_KEY|aws_secret|AWS_SECRET)\s*[=:]\s*['\"]",
        ],
        "description": "Credentials, API keys, tokens, and secrets exposed in source code",
        "recommendations": [
            "Use environment variables (.env) to store secrets",
            "Use python-dotenv to load environment variables",
            "Implement secret managers like AWS Secrets Manager",
            "Never commit files .env to the repository",
            "Use .gitignore to exclude credential files",
            "Rotate all discovered credentials immediately"
        ]
    },
    
    "sql_injection": {
        "name": "SQL Injection",
        "severity": "critical",
        "patterns": [
            r"(?:query|execute|executemany)\s*\(\s*['\"].*(?:\+|\.format|\%|f[\s]*['\"]|\$\{).*['\"]",
            r"f[\s]*['\"]SELECT.*\{.*\}",
            r"(?:cursor|conn)\.execute\s*\(\s*['\"].*(?:\+|\.format|\%|f[\s]*[\'\"])",
            r"db\.query\s*\(\s*['\"].*(?:\+|\.format).*['\"]",
            r"SELECT\s+.*\+\s*str\(",
            r"INSERT\s+INTO\s+.*\+\s*(?:str|format)",
            r"UPDATE\s+.*\+\s*(?:str|format)",
            r"DELETE\s+FROM\s+.*\+\s*(?:str|format)",
            r"\.execute\s*\(\s*['\"].*\%.*['\"],\s*(?:.*user|.*input)",
            r"sqlalchemy\.text\s*\(\s*['\"].*\{.*\}['\"]",
        ],
        "description": "Variable concatenation in SQL queries without prepared statements, vulnerable to SQL injection",
        "recommendations": [
            "Use prepared statements with parameterization",
            "Use ORMs like SQLAlchemy, Django ORM or Tortoise",
            "Use ? for placeholders instead of concatenation",
            "Validate and sanitize all user inputs",
            "Use a whitelist of allowed values",
            "Apply the principle of least privilege to DB connections"
        ]
    },
    
    "command_injection": {
        "name": "Command Injection",
        "severity": "critical",
        "patterns": [
            r"(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen)\s*\(\s*['\"].*(?:\+|\.format|f[\s]*[\'\"]|\.split\(\))",
            r"subprocess\.(?:call|run|Popen)\s*\(\s*['\"].*\+",
            r"os\.system\s*\(\s*f[\s]*['\"].*\{",
            r"shell\s*=\s*True[\s\S]*?subprocess\.(?:call|run|Popen)",
            r"subprocess\.shell\s*\([\s\S]*?True",
            r"os\.popen\s*\(\s*(?:cmd|command|args)\s*\+",
            r"exec\s*\(\s*f[\s]*['\"].*\{.*\}",
            r"__import__\s*\(\s*['\"]subprocess['\"][\s\S]*?os\.system",
            r"paramiko\.exec_command\s*\(\s*['\"].*\+",
            r"fabric\.run\s*\(\s*['\"].*\+",
        ],
        "description": "System command execution with unvalidated variables allows command injection",
        "recommendations": [
            "Avoid os.system(); use subprocess with an argument list",
            "Never pass shell=True when using user input",
            "Use subprocess.run() with a separated argument list",
            "Validate and sanitize all user inputs",
            "Use a whitelist of allowed commands",
            "Apply least privilege to executed processes"
        ]
    },
    
    "insecure_deserialization": {
        "name": "Insecure Deserialization",
        "severity": "critical",
        "patterns": [
            r"pickle\.load\s*\(",
            r"pickle\.loads\s*\(",
            r"yaml\.load\s*\(",
            r"yaml\.unsafe_load\s*\(",
            r"marshal\.load\s*\(",
            r"dill\.load\s*\(",
            r"cloudpickle\.load\s*\(",
            r"joblib\.load\s*\(",
            r"(?:flask|django)\.request\.(?:data|form|json)",
            r"shelve\.open\s*\(",
        ],
        "description": "Insecure deserialization of Python objects allows arbitrary code execution",
        "recommendations": [
            "Use json.loads() instead of pickle for untrusted data",
            "If you must use pickle, validate data sources",
            "Use yaml.safe_load() instead of yaml.load()",
            "Implement type validation after deserialization",
            "Consider signing serialized data with HMAC",
            "Use secure libraries like msgpack or protobuf"
        ]
    },
    
    "path_traversal": {
        "name": "Path Traversal",
        "severity": "high",
        "patterns": [
            r"open\s*\(\s*['\"](?:(?![\s]*['\"])|(?:[^'\"]*\.\./))",
            r"os\.path\.join\s*\(\s*.*\.\./",
            r"(?:pathlib\.Path|Path)\s*\(\s*['\"](?:[^'\"]*\.\./)",
            r"os\.path\.join\s*\(\s*base_dir,\s*(?:user_input|request\.|path\.|filename)",
            r"open\s*\(\s*(?:os\.path\.join|path\.join).*\+\s*(?:request|user|param)",
            r"\.open\s*\(\s*['\"].*\+\s*(?:request\.args|request\.form)",
            r"zipfile\.ZipFile\.extractall\s*\(",
            r"tarfile\.TarFile\.extractall\s*\(",
            r"pathlib\.Path\.read_text\s*\(\s*['\"].*\.\./",
            r"os\.access\s*\(\s*(?:user_path|filename)\s*,",
        ],
        "description": "File access with relative or unvalidated paths can allow path traversal",
        "recommendations": [
            "Validate requested paths against a whitelist",
            "Use pathlib.Path.resolve() and verify it stays within the allowed directory",
            "Never allow '..' in user paths",
            "Use os.path.commonpath() to validate the base path",
            "Keep sensitive files outside the web root",
            "Implement base-directory sandboxing"
        ]
    },
    
    "insecure_crypto": {
        "name": "Insecure Cryptography",
        "severity": "high",
        "patterns": [
            r"hashlib\.md5\s*\(",
            r"hashlib\.sha1\s*\(",
            r"Crypto\.Hash\.MD5\.new\s*\(",
            r"Crypto\.Hash\.SHA\.new\s*\(",
            r"hashlib\.sha256\s*\(\)\.update\s*\(\s*password",
            r"crypt\.crypt\s*\(",
            r"bcrypt\.hashpw\s*\(\s*.*,\s*(?:bcrypt\.gensalt\(\)|bcrypt\.gensalt\(rounds=[0-9]\))",
            r"(?:import|from).*import.*Cipher",
            r"DES\.|DES3|AES\s*\(\s*mode=AES\.MODE_ECB",
            r"random\.choice\s*\(\s*['\"]",
        ],
        "description": "Weak cryptographic algorithms (MD5, SHA1, DES) or insecure parameters",
        "recommendations": [
            "Use SHA-256 or SHA-3 instead of MD5/SHA1",
            "Use bcrypt or argon2 for password hashing (rounds >= 12)",
            "Use os.urandom() to generate random values",
            "Use cryptography.io for symmetric cryptography (AES-GCM)",
            "Never use DES or Triple DES",
            "Use modern libraries like NaCl/libsodium"
        ]
    },
    
    "no_input_validation": {
        "name": "Lack of Input Validation",
        "severity": "medium",
        "patterns": [
            r"(?:request\.args|request\.form|request\.json|request\.data)\s*\[\s*['\"].*['\"]",
            r"int\s*\(\s*(?:request\.|input\()",
            r"(?:request\.args|request\.form|sys\.argv)\[.*\]\s*(?:\+|-|\*|/|%|==|!=|<|>)",
            r"if\s+(?:request\.args|request\.form|sys\.argv)",
            r"for\s+.+\s+in\s+(?:request\.args|request\.form|request\.json)",
            r"\.split\s*\(\s*(?:request\.args|user_input)",
            r"str\s*\(\s*(?:request\.|sys\.argv)\s*\)",
            r"eval\s*\(\s*(?:request\.args|user_input|sys\.argv)",
            r"use_strict=False[\s\S]*?(?:request\.|parse)",
            r"@app\.route.*def\s+\w+\s*\(\s*\):",
        ],
        "description": "Direct access to input parameters without validation or sanitization",
        "recommendations": [
            "Use Pydantic for model validation",
            "Use marshmallow for serialization/validation",
            "Use Cerberus for schema validation",
            "Implement middleware validation",
            "Sanitize all user inputs",
            "Use a whitelist of allowed values"
        ]
    },
    
    "insecure_dependencies": {
        "name": "Insecure Dependencies",
        "severity": "medium",
        "patterns": [
            r"requests\s*==\s*(?:2\.(?:[0-9]|1[0-9]|2[0-6])|2\.25)",
            r"django\s*==\s*(?:1\.|2\.[0-9]|3\.[0-9]|4\.0)",
            r"flask\s*==\s*(?:0\.|1\.[0-9]|2\.0\.[0-9])",
            r"sqlalchemy\s*==\s*(?:1\.[0-2])",
            r"pyyaml\s*==\s*(?:3\.|4\.|5\.[0-3])",
            r"paramiko\s*==\s*(?:1\.|2\.[0-2])",
            r"jinja2\s*==\s*(?:2\.[0-9]|3\.0\.[0-9])",
            r"cryptography\s*==\s*(?:[0-2]\.)",
            r"pillow\s*==\s*(?:[0-7]\.)",
            r"requirements\.txt.*insecure|requirements\.txt.*--allow-external",
        ],
        "description": "Use of known vulnerable library versions",
        "recommendations": [
            "Update all dependencies to secure versions",
            "Use pip-audit to identify vulnerabilities",
            "Use poetry or pipenv for dependency management",
            "Implement automatic updates with dependabot",
            "Review the changelog before updating",
            "Use requirements.txt with pinned versions"
        ]
    },
    
    "xxe_injection": {
        "name": "XML External Entity (XXE) Injection",
        "severity": "high",
        "patterns": [
            r"xml\.etree\.ElementTree\.parse\s*\(",
            r"xml\.dom\.minidom\.parse\s*\(",
            r"xml\.sax\.parse\s*\(",
            r"lxml\.etree\.parse\s*\(",
            r"defusedxml",
            r"XMLParser\s*\(\s*resolve_entities\s*=\s*True",
            r"(?:xml|et|tree)\.fromstring\s*\(\s*(?:request\.|user_input|file_data)",
            r"BeautifulSoup\s*\(\s*.*,\s*['\"]xml['\"]",
            r"untrusted_data[\s\S]*?parse\s*\(",
            r"request\.files\s*\[.*\][\s\S]*?xml\.parse",
        ],
        "description": "XML processing with external entities enabled can allow file disclosure or DoS",
        "recommendations": [
            "Use defusedxml instead of xml standard",
            "Disable DTD and external entities in parsers",
            "Use lxml with xmlschema for validation",
            "Validate and sanitize XML input",
            "Implement file size limits",
            "Use a whitelist of allowed XML elements"
        ]
    },

    "idor_insecure_direct_object_reference": {
        "name": "IDOR (Insecure Direct Object Reference)",
        "severity": "high",
        "patterns": [
            r"@app\.route\s*\(\s*['\"].*/<(?:int|str):[^>]+>",
            r"@router\.(?:get|put|patch|delete)\s*\(\s*['\"].*/\{(?:id|user_id|account_id|order_id)[^}]*\}",
            r"(?:request\.args|request\.form|request\.json)\.get\s*\(\s*['\"](?:id|user_id|account_id|order_id|resource_id)['\"]",
            r"@(?:app|router)\.route\s*\(\s*['\"][^'\"]*<(?:int|str):[^>]+>",
            r"\.(?:objects|query)\.(?:get|filter_by)\s*\(\s*.*=\s*(?:request\.args|request\.form|request\.json|id)[^)]*\)",
            r"get_object_or_404\s*\(\s*\w+\s*,\s*(?:id|pk)\s*=\s*(?:request\.args|id)",
            r"c\.execute\s*\(\s*['\"]SELECT.*WHERE\s+(?:id|user_id)\s*=\s*\?",
            r"return\s+jsonify\s*\(\s*\{[^}]*\}\s*\)\s*$",
            r"if\s+not\s+user:\s+return",
            r"return\s+jsonify\s*\(.*(?:username|password|data).*\)"
        ],
        "description": "Direct access to objects via user-controlled identifiers without validating access authorization (IDOR)",
        "recommendations": [
            "Verify ownership/authorization per resource before operating",
            "Do not trust IDs sent by clients",
            "Apply object-level access controls",
            "Use opaque identifiers when it is possible",
            "Log access to sensitive resources",
            "Add cross-user access tests"
        ]
    },

    "debug_endpoint_exposure": {
        "name": "Sensitive Information Exposure (Debug Endpoint)",
        "severity": "medium",
        "patterns": [
            r"@app\.route\s*\(\s*['\"](?:/debug|/__debug__|/internal|/api/dev)",
            r"@router\.(?:get|post)\s*\(\s*['\"](?:/debug|/internal)",
            r"@app\.route\s*\(\s*['\"][^'\"]*(?:debug|internal|dev|admin)[^'\"]*['\"]",
            r"DEBUG\s*=\s*True",
            r"app\.run\s*\(\s*.*debug\s*=\s*True",
            r"return\s+jsonify\s*\(\s*\{[^}]*(?:SECRET|jwt_secret|alg|version)[^}]*\}",
            r"return\s+str\s*\(\s*e\s*\)",
            r"return\s+f['\"](?:.*)?{.*}(?:.*)?['\"]",
            r"print\s*\(\s*request\.(?:headers|cookies|environ|full_path)",
            r"settings\.DEBUG\s*=\s*True"
        ],
        "description": "Debug endpoints/modes can expose stack traces, environment details, and sensitive data",
        "recommendations": [
            "Disable debug mode in production",
            "Do not expose stack traces to end users",
            "Restrict internal diagnostic endpoints",
            "Avoid printing secrets in logs",
            "Use generic error responses for clients",
            "Separate technical logs from HTTP responses"
        ]
    },

    "jwt_auth_mismanagement": {
        "name": "JWT Authentication Mismanagement",
        "severity": "high",
        "patterns": [
            r"jwt\.encode\s*\(\s*.*\s*,\s*['\"][^'\"]+['\"]",
            r"jwt\.decode\s*\(\s*token\s*,\s*verify\s*=\s*False",
            r"jwt\.decode\s*\(\s*token\s*,\s*options\s*=\s*\{\s*['\"]verify_signature['\"]\s*:\s*False",
            r"options\s*=\s*\{\s*['\"]verify_exp['\"]\s*:\s*False",
            r"algorithms\s*=\s*\[\s*['\"]none['\"]\s*\]",
            r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",
            r"JWT_SECRET\s*=\s*['\"][^'\"]+['\"]",
            r"ACCESS_TOKEN_EXPIRE_(?:MINUTES|HOURS|DAYS)\s*=\s*(?:365|9999)",
            r"from\s+jwt\s+import\s+decode",
            r"authorization\s*=\s*request\.headers\.get\s*\(\s*['\"]Authorization['\"]"
        ],
        "description": "Insecure JWT usage due to hardcoded secrets, disabled validations, or weak expirations",
        "recommendations": [
            "Store JWT secrets outside source code",
            "Validate signature, expiration, issuer and audience",
            "Do not allow algorithm none",
            "Use short expirations and controlled refresh tokens",
            "Rotate signature keys periodically",
            "Invalidate compromised tokens through a blacklist"
        ]
    },

    "jwt_forgery_token_manipulation": {
        "name": "JWT Forgery (Token Manipulation)",
        "severity": "critical",
        "patterns": [
            r"token\.split\(['\"]\\.['\"]\)\[1\]",
            r"base64\.b64decode\s*\(\s*token\.split",
            r"json\.loads\s*\(\s*base64\.b64decode",
            r"payload\[['\"](?:role|admin|is_admin)['\"]\]\s*=",
            r"jwt\.decode\s*\(\s*token\s*,\s*options\s*=\s*\{\s*['\"]verify_signature['\"]\s*:\s*False",
            r"jwt\.decode\s*\(\s*token\s*,\s*verify\s*=\s*False",
            r"algorithms\s*=\s*\[\s*['\"]\*['\"]\s*\]",
            r"SECRET_KEY\s*=\s*os\.getenv\s*\(\s*['\"]JWT_SECRET['\"],\s*['\"][^'\"]{10,}['\"]",
            r"token\s*=\s*jwt\.encode\s*\(.*\)",
            r"except\s+Exception\s+as\s+e[\s\S]{0,100}return\s+f?['\"].*\{?str\s*\(\s*e\s*\)?\}?"
        ],
        "description": "Manual JWT token manipulation or partial validation can allow impersonation and privilege escalation",
        "recommendations": [
            "Do not decode claims for authorization without signature verification",
            "Validate allowed algorithm explicitly",
            "Reject tokens with alg=none",
            "Validate token signature and metadata on every request",
            "Audit invalid/manipulated token events",
            "Use maintained JWT libraries with secure configuration"
        ]
    }
}
