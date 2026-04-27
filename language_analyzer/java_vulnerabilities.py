JAVA_VULN_RULES = {
    "sql_injection": {
        "name": "SQL Injection",
        "severity": "critical",
        "patterns": [
            r"(?:executeQuery|executeUpdate|execute)\s*\(\s*['\"].*\+",
            r"(?:Statement|Query)\.(?:executeQuery|executeUpdate)\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE).*\+",
            r"query\s*=\s*['\"].*\+\s*(?:user|param|request)",
            r"sql\s*=\s*['\"].*\+\s*(?:input|data|value)",
            r"String\s+sql\s*=\s*['\"].*\+\s*\w+",
            r"JdbcTemplate\s*\(\s*\).query\s*\(\s*['\"].*\+",
            r"EntityManager\.createQuery\s*\(\s*['\"].*\+",
            r"Session\.createQuery\s*\(\s*['\"].*\+",
            r"@Query\s*\(\s*value\s*=\s*['\"].*\+",
            r"PreparedStatement.*(?:!|!=)\s*",
        ],
        "description": "Variable concatenation in SQL queries without prepared statements, vulnerable to SQL injection",
        "recommendations": [
            "Use PreparedStatement with setString(), setInt(), etc",
            "Use ORMs like Hibernate, JPA or Spring Data",
            "Use @Query with parameterization in Spring Data",
            "Validate and sanitize all user inputs",
            "Use a whitelist of allowed values",
            "Apply the principle of least privilege to DB connections"
        ]
    },
    
    "command_injection": {
        "name": "Command Injection",
        "severity": "critical",
        "patterns": [
            r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(\s*['\"].*\+",
            r"new\s+ProcessBuilder\s*\(\s*.*(?:\+|\.concat|split\(\))\s*\)",
            r"Runtime\.getRuntime\(\)\.exec\s*\(\s*new\s+String\[\]\s*\{\s*['\"].*['\"],.*(?:\+|\.concat)",
            r"Process\s+\w+\s*=\s*.*\.exec\s*\(\s*['\"].*\+",
            r"exec\s*\(\s*cmd\s*\+\s*(?:userInput|param)",
            r"redirect\s*=\s*true[\s\S]*?exec\s*\(",
            r"shell\s*=\s*true[\s\S]*?ProcessBuilder",
            r"String\[\]\s+cmd\s*=\s*\{[\s\S]*?\+\s*(?:user|input|param)",
            r"/bin/sh.*-c.*\+",
            r"cmd\.exe.*\/c.*\+",
        ],
        "description": "System command execution with unvalidated variables allows command injection",
        "recommendations": [
            "Use ProcessBuilder with a separated argument list",
            "Never concatenate strings in commands",
            "Use a whitelist of allowed commands",
            "Validate and sanitize all user inputs",
            "Avoid passing user data directly to exec",
            "Apply least privilege to executed processes"
        ]
    },
    
    "xxe_injection": {
        "name": "XML External Entity (XXE) Injection",
        "severity": "critical",
        "patterns": [
            r"DocumentBuilderFactory\.newInstance\s*\(\)",
            r"SAXParserFactory\.newInstance\s*\(\)",
            r"XMLInputFactory\.newInstance\s*\(\)",
            r"SchemaFactory\.newInstance\s*\(\)",
            r"TransformerFactory\.newInstance\s*\(\)",
            r"(?:newInstance|new\s+.*ParserFactory)\s*\(\)[\s\S]*?(?!.*setFeature.*disallow)",
            r"parser\.parse\s*\(\s*(?:userInput|request\.|stream)",
            r"unmarshaller\.unmarshal\s*\(\s*(?:file|stream|source)",
            r"XPath\.evaluate\s*\(\s*['\"].*\+",
            r"DocumentBuilder\.parse\s*\(\s*\w+Input",
        ],
        "description": "XML processing with external entities enabled can allow file disclosure or DoS",
        "recommendations": [
            "Disable XXE using setFeature with DISALLOW_DOCTYPE_DECL",
            "Use OWASP XXE Prevention Cheat Sheet",
            "Use secure libraries like XStream",
            "Validate and sanitize XML input",
            "Implement file size limits",
            "Use a whitelist of allowed XML elements"
        ]
    },
    
    "hardcoded_secrets": {
        "name": "Hardcoded Secrets",
        "severity": "critical",
        "patterns": [
            r"password\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"apiKey\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"api_key\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"secret\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"token\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"accessToken\s*[=:]\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"privateKey\s*[=:]\s*['\"][\s\S]*?['\"]",
            r"\"password\"\s*:\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"System\.getenv\s*\(\s*['\"](?:API_KEY|SECRET|PASSWORD|TOKEN)",
            r"Properties\.load.*password|secret",
        ],
        "description": "Credentials, API keys, tokens, and secrets exposed in source code",
        "recommendations": [
            "Use environment variables to store secrets",
            "Use secret managers like HashiCorp Vault",
            "Use Spring Cloud Config Server for sensitive configuration",
            "Never commit files with credentials to the repository",
            "Use .gitignore to exclude secret files",
            "Rotate all discovered credentials immediately"
        ]
    },
    
    "insecure_deserialization": {
        "name": "Insecure Deserialization",
        "severity": "critical",
        "patterns": [
            r"ObjectInputStream\.readObject\s*\(",
            r"new\s+ObjectInputStream\s*\(",
            r"readObject\s*\(\s*\)",
            r"readUnshared\s*\(\s*\)",
            r"readExternal\s*\(\s*\)",
            r"XMLDecoder\.readObject\s*\(",
            r"readObjectNoData\s*\(\s*\)",
            r"readResolve\s*\(\s*\)",
            r"unmarshaller\.unmarshal\s*\(\s*untrusted",
            r"(?:jsonObject|jsonArray)\.getObject\s*\(",
        ],
        "description": "Insecure deserialization of Java objects allows arbitrary code execution",
        "recommendations": [
            "Use JSON (Jackson, Gson) instead of Java serialization",
            "Implement ObjectInputFilter to filter classes",
            "Use the NotSerializable interface for sensitive classes",
            "Validate data sources before deserializing",
            "Consider signing serialized data with HMAC",
            "Use secure libraries like Protobuf"
        ]
    },
    
    "insecure_crypto": {
        "name": "Insecure Cryptography",
        "severity": "high",
        "patterns": [
            r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]",
            r"MessageDigest\.getInstance\s*\(\s*['\"]SHA-1['\"]",
            r"MessageDigest\.getInstance\s*\(\s*['\"]SHA1['\"]",
            r"Cipher\.getInstance\s*\(\s*['\"]DES",
            r"Cipher\.getInstance\s*\(\s*['\"].*\/ECB\/",
            r"SecureRandom\s*\(\s*\)\.nextInt\s*\(",
            r"Random\s*\(\s*\)\.next",
            r"Mac\.getInstance\s*\(\s*['\"]HmacMD5['\"]",
            r"KeyGenerator\.getInstance\s*\(\s*['\"]DES",
            r"new\s+IvParameterSpec\s*\(\s*new\s+byte\[\]\s*\{",
        ],
        "description": "Weak cryptographic algorithms (MD5, SHA1, DES, ECB) or insecure parameters",
        "recommendations": [
            "Use SHA-256 or SHA-3 instead of MD5/SHA1",
            "Use bcrypt or PBKDF2 for password hashing",
            "Use AES-GCM instead of DES or ECB",
            "Generate random IVs with SecureRandom",
            "Use libraries like Bouncy Castle for cryptography",
            "Never use weak algorithms like DES"
        ]
    },
    
    "path_traversal": {
        "name": "Path Traversal",
        "severity": "high",
        "patterns": [
            r"new\s+File\s*\(\s*userInput",
            r"Files\.read\s*\(\s*(?:Paths\.get\s*\(\s*userInput|path\s*\+)",
            r"Paths\.get\s*\(\s*userInput\s*\)",
            r"request\.getParameter\s*\(['\"].*['\"][\s\S]*?File\s*\(",
            r"ServletContext\.getRealPath\s*\(\s*(?:request\.|path\s*\+)",
            r"zipFile\.getEntry\s*\(\s*(?:.*\.\.\/|userInput)",
            r"new\s+FileInputStream\s*\(\s*(?:.*\.\.|userInput)",
            r"new\s+FileOutputStream\s*\(\s*(?:.*\.\.|userInput)",
            r"RandomAccessFile\s*\(\s*(?:.*\.\.|userInput)",
            r"ZipInputStream\.getNextEntry\s*\(\s*\)[\s\S]*?\.\.",
        ],
        "description": "File access with relative or unvalidated paths can allow path traversal",
        "recommendations": [
            "Validate requested paths against a whitelist",
            "Use Path.normalize() and verify it stays within the allowed directory",
            "Never permitir '..' en user paths",
            "Use java.nio.file.Files.walkFileTree() with SecureDirectoryStream",
            "Keep sensitive files outside the web root",
            "Implement base-directory sandboxing"
        ]
    },
    
    "xss_vulnerabilities": {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "patterns": [
            r"out\.println\s*\(\s*(?:request\.|userInput)",
            r"response\.getWriter\s*\(\)\.print\s*\(\s*(?:request\.|userInput)",
            r"setAttribute\s*\(\s*['\"].*['\"],\s*(?:request\.|userInput)",
            r"model\.addAttribute\s*\(\s*['\"].*['\"],\s*(?:request\.|userInput)",
            r"template\s*\.render\s*\(\s*(?:request\.|userInput)",
            r"<\%=[\s\S]*?(?:request\.|param\.)",
            r"th:text=.*\$\{.*(?:request\.|param\.)",
            r"v-html=",
            r"dangerouslySetInnerHTML",
            r"innerHTML\s*=\s*(?:request\.|userInput)",
        ],
        "description": "Unsanitized HTML/JavaScript injection allows XSS",
        "recommendations": [
            "Use OWASP ESAPI Encoder to escape output",
            "Use templating engines with auto-escape (Thymeleaf, Velocity)",
            "Implement Content Security Policy (CSP) headers",
            "Escape special characters (<, >, &, \", ')",
            "Validate and sanitize all user inputs",
            "Use a whitelist of allowed characters"
        ]
    },
    
    "insecure_http_headers": {
        "name": "Insecure HTTP Headers",
        "severity": "medium",
        "patterns": [
            r"response\.setHeader\s*\(\s*['\"](?:X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security)['\"],\s*['\"]['\"]",
            r"response\.setHeader\s*\(\s*['\"]Access-Control-Allow-Origin['\"],\s*['\"]\*['\"]",
            r"cors\s*\.\s*allow\s*\(\s*\*\s*\)",
            r"@CrossOrigin\s*\(\s*origins\s*=\s*\{[\s\S]*?\*",
            r"response\.setHeader\s*\(\s*['\"]Set-Cookie['\"],.*(?!Secure)(?!HttpOnly)",
            r"response\.setHeader\s*\(\s*['\"]Cache-Control['\"],\s*['\"]public['\"]",
            r"response\.addHeader\s*\(\s*['\"]X-UA-Compatible['\"],\s*['\"]IE",
            r"response\.setHeader\s*\(\s*['\"]X-Powered-By",
            r"disableContentSecurityPolicy\s*=\s*true",
            r"enableXssProtection\s*=\s*false",
        ],
        "description": "Missing or misconfigured HTTP headers can enable attacks",
        "recommendations": [
            "Implement X-Frame-Options: DENY",
            "Implement X-Content-Type-Options: nosniff",
            "Implement Strict-Transport-Security",
            "Specify allowed origins en CORS",
            "Implement Content-Security-Policy",
            "Use Secure and HttpOnly cookie flags"
        ]
    },
    
    "weak_authentication": {
        "name": "Weak Authentication",
        "severity": "high",
        "patterns": [
            r"password\.equals\s*\(",
            r"password\.compareTo\s*\(",
            r"username\.equals\s*\(\s*userInput",
            r"@RequestParam.*password.*required\s*=\s*false",
            r"User\.findByUsername\s*\(\s*userInput\s*\)",
            r"if\s*\(\s*(?:username|password)\s*==\s*",
            r"setPassword\s*\(\s*plaintext",
            r"JWT\.require.*Algorithm\.HMAC256.*['\"]weak['\"]",
            r"session\.setAttribute\s*\(\s*['\"]userId['\"],\s*(?:request\.|param)",
            r"@PreAuthorize\s*\(\s*['\"]permitAll\(\)['\"]",
        ],
        "description": "Weak authentication implementation or incorrect validation",
        "recommendations": [
            "Use MessageDigest.isEqual() to compare sensitive strings",
            "Use bcrypt or PBKDF2 for hashear passwords",
            "Implement multi-factor authentication (MFA)",
            "Use JWT with strong secrets",
            "Apply rate limiting to login attempts",
            "Use secure tokens with expiration"
        ]
    },

    "idor_insecure_direct_object_reference": {
        "name": "IDOR (Insecure Direct Object Reference)",
        "severity": "high",
        "patterns": [
            r"@(?:GetMapping|PutMapping|PatchMapping|DeleteMapping)\s*\(\s*['\"].*\{id\}",
            r"@PathVariable\s*(?:\(\s*['\"]id['\"]\s*\))?\s*Long\s+id",
            r"request\.getParameter\s*\(\s*['\"]id['\"]\s*\)",
            r"repository\.findById\s*\(\s*id\s*\)",
            r"repository\.deleteById\s*\(\s*id\s*\)",
            r"entityManager\.find\s*\(\s*\w+\.class\s*,\s*id\s*\)",
            r"service\.get(?:User|Account|Order)ById\s*\(\s*id\s*\)",
            r"Optional<\w+>\s+\w+\s*=\s*repository\.findById\s*\(\s*id\s*\)",
            r"return\s+ResponseEntity\.ok\s*\(\s*\w+\s*\)",
            r"@RequestParam\s*\(\s*['\"]id['\"]\s*\)"
        ],
        "description": "Object access by user-controlled ID without resource-level authorization controls (IDOR)",
        "recommendations": [
            "Validate resource ownership/authorization before reading or modifying",
            "Do not trust IDs received through path/query/body",
            "Apply object-level authorization (method security + ABAC/RBAC)",
            "Use opaque identifiers when viable",
            "Log access events for sensitive resources",
            "Add cross-user access tests"
        ]
    },

    "debug_endpoint_exposure": {
        "name": "Sensitive Information Exposure (Debug Endpoint)",
        "severity": "medium",
        "patterns": [
            r"@RequestMapping\s*\(\s*['\"]/debug",
            r"@GetMapping\s*\(\s*['\"]/debug",
            r"['\"]/actuator/(?:env|heapdump|threaddump|mappings|beans)['\"]",
            r"management\.endpoints\.web\.exposure\.include\s*=\s*\*",
            r"server\.error\.include-stacktrace\s*=\s*always",
            r"logging\.level\.org\.springframework\s*=\s*DEBUG",
            r"response\.getWriter\s*\(\s*\)\.print\s*\(\s*e\.getStackTrace",
            r"return\s+e\.toString\s*\(\s*\)",
            r"System\.out\.println\s*\(\s*System\.getenv\s*\(",
            r"spring\.devtools\.restart\.enabled\s*=\s*true"
        ],
        "description": "Debug endpoints or configuration can expose stack traces, environment details, and sensitive configuration",
        "recommendations": [
            "Disable debugging endpoints in production",
            "Do not expose stack traces to clients",
            "Restrict endpoints Actuator with authentication/authorization",
            "Do not loggear secrets ni variables sensibles",
            "Use generic error messages for clients",
            "Separate dev/prod configuration profiles"
        ]
    },

    "jwt_auth_mismanagement": {
        "name": "JWT Authentication Mismanagement",
        "severity": "high",
        "patterns": [
            r"setSigningKey\s*\(\s*['\"][^'\"]+['\"]\s*\)",
            r"Algorithm\.HMAC256\s*\(\s*['\"][^'\"]+['\"]\s*\)",
            r"JWT\.require\s*\(\s*Algorithm\.HMAC256\s*\(\s*['\"]weak['\"]",
            r"\.setAllowedClockSkewSeconds\s*\(\s*(?:86400|999999)",
            r"\.setExpiration\s*\(\s*new\s+Date\s*\(\s*System\.currentTimeMillis\s*\(\s*\)\s*\+\s*31536000000",
            r"parseClaimsJwt\s*\(",
            r"parseClaimsJws\s*\(\s*token\s*\)\s*;\s*//\s*no\s*aud",
            r"setAllowedAlgorithms\s*\(\s*Arrays\.asList\s*\(\s*['\"]none['\"]",
            r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",
            r"jwtSecret\s*=\s*['\"][^'\"]+['\"]"
        ],
        "description": "Insecure JWT configuration due to hardcoded secrets or incomplete validations",
        "recommendations": [
            "Store secrets/keys outside source code",
            "Validate signature, issuer, audience and expiration",
            "Reject algorithm none and restrict allowed algorithms",
            "Use short expirations and key rotation",
            "Add token revocation when applicable",
            "Instrument monitoring of JWT validation failures"
        ]
    },

    "jwt_forgery_token_manipulation": {
        "name": "JWT Forgery (Token Manipulation)",
        "severity": "critical",
        "patterns": [
            r"token\.split\s*\(\s*['\"]\\.['\"]\s*\)\s*\[1\]",
            r"Base64\.getDecoder\s*\(\s*\)\.decode\s*\(\s*token\.split",
            r"new\s+String\s*\(\s*Base64\.getDecoder\s*\(\s*\)\.decode",
            r"claims\.put\s*\(\s*['\"](?:role|admin|isAdmin)['\"]",
            r"payload\.put\s*\(\s*['\"](?:role|admin|scope)['\"]",
            r"ObjectMapper\s+\w+\s*=\s*new\s+ObjectMapper\s*\(\s*\)",
            r"JWT\.decode\s*\(\s*token\s*\)",
            r"if\s*\(\s*decodedToken\.getClaim\s*\(\s*['\"]role['\"]\s*\)",
            r"header\.put\s*\(\s*['\"]alg['\"]\s*,\s*['\"]none['\"]",
            r"token\s*=\s*header\s*\+\s*['\"]\\.['\"]\s*\+\s*payload"
        ],
        "description": "Manual JWT manipulation or use of claims without signature verification allows identity spoofing",
        "recommendations": [
            "Do not trust in decoded claims without verification criptogr�fica",
            "Validate token signature and metadata on every request",
            "Strictly restrict allowed algorithms",
            "Reject tokens with alg=none",
            "Use maintained JWT libraries with secure defaults",
            "Add detection and alerts for manipulated token attempts"
        ]
    }
}
