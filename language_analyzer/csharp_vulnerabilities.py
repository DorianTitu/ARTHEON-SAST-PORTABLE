CSHARP_VULN_RULES = {
    "sql_injection": {
        "name": "SQL Injection",
        "severity": "critical",
        "patterns": [
            r"command\.CommandText\s*=\s*['\"].*\+",
            r"ExecuteQuery\s*\(\s*['\"].*\+",
            r"@\"SELECT.*\+",
            r"\$\"SELECT.*\{.*\}",
            r"new\s+SqlCommand\s*\(\s*['\"].*\+",
            r"\.Query\s*<.*>\s*\(\s*['\"].*\+",
            r"db\.Database\.ExecuteSqlCommand\s*\(\s*['\"].*\+",
            r"context\.Database\.ExecuteSqlCommand\s*\(\s*userInput",
            r"var\s+query\s*=\s*['\"].*\+\s*(?:user|param|input)",
            r"sql\s*=\s*['\"].*\+\s*\w+",
        ],
        "description": "Variable concatenation in SQL queries without parameterization, vulnerable to SQL injection",
        "recommendations": [
            "Use SqlParameter for parameterization",
            "Use LINQ to SQL or Entity Framework with parameterization",
            "Use Dapper with parameterization",
            "Validate and sanitize all user input",
            "Use a whitelist of allowed values",
            "Apply the principle of least privilege to DB connections"
        ]
    },
    
    "command_injection": {
        "name": "Command Injection",
        "severity": "critical",
        "patterns": [
            r"Process\.Start\s*\(\s*['\"]cmd['\"],\s*['\"].*\+",
            r"ProcessStartInfo.*FileName\s*=\s*['\"].*\+",
            r"ProcessStartInfo.*Arguments\s*=\s*['\"].*\+",
            r"new\s+ProcessStartInfo\s*\(\s*['\"].*\+",
            r"cmd\s*\/c\s*.*\+\s*(?:userInput|param)",
            r"bash\s*-c\s*.*\+\s*(?:userInput|param)",
            r"shell.*=.*true[\s\S]*?Process\.Start",
            r"RunAs\s*\(\s*['\"].*\+",
            r"ExecuteAsync\s*\(\s*['\"].*\+",
            r"ShellExecute\s*\(\s*['\"].*\+",
        ],
        "description": "System command execution with unvalidated variables allows command injection",
        "recommendations": [
            "Avoid Process.Start() with concatenated command strings",
            "Use ProcessStartInfo with a separated argument list",
            "Validate and sanitize all user input",
            "Use a whitelist of allowed commands",
            "Apply least privilege to executed processes",
            "Use higher-level APIs when possible"
        ]
    },
    
    "hardcoded_secrets": {
        "name": "Hardcoded Secrets",
        "severity": "critical",
        "patterns": [
            r"password\s*=\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"apiKey\s*=\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"api_key\s*=\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"secret\s*=\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"token\s*=\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"connectionString\s*=\s*['\"].*(?:password|pwd).*['\"]",
            r"\"password\"\s*:\s*['\"](?![\s]*['\"])[^'\"]+['\"]",
            r"['\"]Authorization['\"]:\s*['\"]Bearer\s+[^'\"]+['\"]",
            r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"]",
            r"appsettings\.json[\s\S]*?password",
        ],
        "description": "Credentials, API keys, tokens, and secrets exposed in source code",
        "recommendations": [
            "Use User Secrets for local development",
            "Use Azure Key Vault to store secrets",
            "Use AWS Secrets Manager",
            "Never commit secrets in appsettings.json",
            "Use secure configuration managers",
            "Rotate all discovered credentials immediately"
        ]
    },
    
    "deserialization_vulnerability": {
        "name": "Deserialization Vulnerability",
        "severity": "critical",
        "patterns": [
            r"JsonConvert\.DeserializeObject\s*<.*>\s*\(.*userInput",
            r"BinaryFormatter\.Deserialize\s*\(",
            r"DataContractSerializer\.ReadObject\s*\(",
            r"NetDataContractSerializer\s*\(",
            r"ObjectStateFormatter\.Deserialize\s*\(",
            r"JavaScriptSerializer\.Deserialize\s*\(",
            r"XmlSerializer\.Deserialize\s*\(",
            r"SoapFormatter\.Deserialize\s*\(",
            r"FormatterServices\.GetSafeUninitializedObject",
            r"untrusted[\s\S]*?Deserialize",
        ],
        "description": "Insecure deserialization allows arbitrary code execution",
        "recommendations": [
            "Use JsonConvert.DeserializeObject with SerializationBinder",
            "Never use BinaryFormatter, NetDataContractSerializer, or SoapFormatter",
            "Implement type validation during deserialization",
            "Use Newtonsoft.Json with TypeNameHandling.None",
            "Validate data sources before deserializing",
            "Consider signing serialized data with HMAC"
        ]
    },
    
    "xxe_injection": {
        "name": "XML External Entity (XXE) Injection",
        "severity": "high",
        "patterns": [
            r"XmlDocument\s*\(\s*\)",
            r"XmlReaderSettings[\s\S]*?DtdProcessing\s*=\s*DtdProcessing\.Parse",
            r"XDocument\.Load\s*\(\s*(?:userInput|stream|request)",
            r"new\s+XmlTextReader\s*\(\s*(?:userInput|stream)",
            r"XmlSerializer\.Deserialize\s*\(\s*(?:userInput|stream)",
            r"XPathDocument\s*\(\s*(?:userInput|stream)",
            r"XmlReader\.Create\s*\(\s*(?!.*DtdProcessing.*Prohibit)",
            r"<!DOCTYPE[\s\S]*?SYSTEM",
            r"<!ENTITY.*SYSTEM",
            r"ALLOW_EXTERNAL_GENERAL_ENTITIES",
        ],
        "description": "XML processing with external entities enabled can allow file disclosure or DoS",
        "recommendations": [
            "Set DtdProcessing = DtdProcessing.Prohibit",
            "Use XmlReaderSettings to disable XXE",
            "Validate and sanitize XML input",
            "Enforce file size limits",
            "Use a whitelist of allowed XML elements",
            "Disable DOCTYPE declarations"
        ]
    },
    
    "insecure_crypto": {
        "name": "Insecure Cryptography",
        "severity": "high",
        "patterns": [
            r"(?:MD5|SHA1)\.Create\s*\(\s*\)",
            r"using.*Cryptography[\s\S]*?MD5|SHA1",
            r"HashAlgorithm\.Create\s*\(\s*['\"]MD5['\"]",
            r"CryptoConfig\.CreateFromName\s*\(\s*['\"]MD5['\"]",
            r"TripleDES\.Create\s*\(\s*\)",
            r"DES\.Create\s*\(\s*\)",
            r"Aes\.Create\s*\(\s*\)[\s\S]*?Mode\s*=\s*CipherMode\.ECB",
            r"RNGCryptoServiceProvider\s*\(\s*new\s+byte\[\]",
            r"Random\s*\(\s*\)\.Next",
            r"System\.Security\.Cryptography\.Rfc2898DeriveBytes\s*\(\s*.*,\s*iterations\s*:\s*[0-9]{1,4}\)",
        ],
        "description": "Weak cryptographic algorithms (MD5, SHA1, DES) or insecure parameters",
        "recommendations": [
            "Use SHA256, SHA512, or SHA3 instead of MD5/SHA1",
            "Use Bcrypt or Argon2 for password hashing",
            "Use Aes.Create() with GCM mode",
            "Generate random IVs with RNGCryptoServiceProvider",
            "Use DataProtectionScope.CurrentUser for sensitive data",
            "Never use DES or TripleDES"
        ]
    },
    
    "path_traversal": {
        "name": "Path Traversal",
        "severity": "high",
        "patterns": [
            r"File\.Open\s*\(\s*userInput",
            r"File\.ReadAllText\s*\(\s*userInput",
            r"File\.WriteAllText\s*\(\s*userInput",
            r"Directory\.GetFiles\s*\(\s*userInput",
            r"Path\.Combine\s*\(\s*baseDir,\s*userInput",
            r"new\s+FileInfo\s*\(\s*userInput",
            r"new\s+DirectoryInfo\s*\(\s*userInput",
            r"StreamReader\s*\(\s*userInput",
            r"StreamWriter\s*\(\s*userInput",
            r"FileStream\s*\(\s*userInput",
        ],
        "description": "File access with relative or unvalidated paths can allow path traversal",
        "recommendations": [
            "Validate requested paths against a whitelist",
            "Use Path.GetFullPath() and verify it stays inside the allowed directory",
            "Never allow '..' in user paths",
            "Use Path.Combine() correctly",
            "Implement base-directory sandboxing",
            "Keep sensitive files outside the web root"
        ]
    },
    
    "weak_authentication": {
        "name": "Weak Authentication",
        "severity": "high",
        "patterns": [
            r"password\.Equals\s*\(",
            r"password\s*==\s*userInput",
            r"password\.CompareTo\s*\(",
            r"MD5\.Create\s*\(\)[\s\S]*?password",
            r"SHA1\.Create\s*\(\)[\s\S]*?password",
            r"Membership\.ValidateUser\s*\(\s*user,\s*password",
            r"FormsAuthentication\.SetAuthCookie",
            r"User\.Identity\.Name\s*==\s*(?:user|userInput)",
            r"\[Authorize\s*\(\s*Roles\s*=\s*['\"].*['\"]",
            r"ValidateUser\s*\(\s*['\"].*['\"],\s*['\"].*['\"]",
        ],
        "description": "Weak authentication implementation or incorrect validation",
        "recommendations": [
            "Use string.Equals() with StringComparison.Ordinal for sensitive data",
            "Use Bcrypt or Argon2 for password hashing",
            "Implement ASP.NET Identity for authentication",
            "Use expiring JWT tokens",
            "Apply rate limiting to login attempts",
            "Implement multi-factor authentication (MFA)"
        ]
    },
    
    "insecure_http_headers": {
        "name": "Insecure HTTP Headers",
        "severity": "medium",
        "patterns": [
            r"response\.Headers\.Add\s*\(\s*['\"]X-Frame-Options['\"],\s*['\"]['\"]",
            r"response\.Headers\.Add\s*\(\s*['\"]Access-Control-Allow-Origin['\"],\s*['\"]\*['\"]",
            r"response\.Headers\.Add\s*\(\s*['\"]X-Content-Type-Options['\"],\s*['\"].*['\"](?!nosniff)",
            r"enableXssProtection\s*=\s*false",
            r"enableStrictTransportSecurity\s*=\s*false",
            r"response\.Cookies\.Add\s*\(\s*.*HttpOnly\s*=\s*false",
            r"response\.Cookies\.Add\s*\(\s*.*Secure\s*=\s*false",
            r"response\.Headers\.Remove\s*\(\s*['\"]X-Powered-By['\"]",
            r"response\.Headers\[.*\]\s*=\s*['\"]public['\"]",
            r"cacheControl\s*=\s*['\"]public['\"]",
        ],
        "description": "Missing or misconfigured HTTP headers can enable attacks",
        "recommendations": [
            "Implement X-Frame-Options: DENY",
            "Implement X-Content-Type-Options: nosniff",
            "Implement Strict-Transport-Security",
            "Specify allowed origins in CORS",
            "Implement Content-Security-Policy",
            "Use Secure and HttpOnly cookie flags"
        ]
    },
    
    "linq_injection": {
        "name": "LINQ Injection",
        "severity": "high",
        "patterns": [
            r"\.Where\s*\(\s*['\"].*\+.*['\"]",
            r"\.Where\s*\(\s*x\s*=>\s*x\.\w+\.Contains\s*\(\s*userInput",
            r"\.Where\s*\(\s*x\s*=>\s*x\.\w+\s*==\s*userInput",
            r"dynamic\s+.*=.*userInput",
            r"System\.Linq\.Dynamic",
            r"Dynamic.*\.Where\s*\(",
            r"Expression\.Lambda\s*\(\s*.*userInput",
            r"ObjectQuery.*from.*userInput",
            r"EntitySql.*userInput",
            r"\.SqlQuery\s*\(\s*['\"].*\+",
        ],
        "description": "LINQ query injection through concatenated strings or untrusted data",
        "recommendations": [
            "Use LINQ with parameterization",
            "Avoid Dynamic LINQ with user input",
            "Use Expression Trees with validation",
            "Implement a whitelist of allowed fields",
            "Validate and sanitize user input",
            "Use an ORM with automatic parameterization"
        ]
    },

    "idor_insecure_direct_object_reference": {
        "name": "IDOR (Insecure Direct Object Reference)",
        "severity": "high",
        "patterns": [
            r"\[Http(?:Get|Put|Patch|Delete)\s*\(\s*['\"].*\{id\}",
            r"\[FromRoute\]\s*(?:int|long|string)\s+id",
            r"\[FromQuery\]\s*(?:int|long|string)\s+id",
            r"request\.(?:Query|RouteValues)\[['\"]id['\"]\]",
            r"\.FindAsync\s*\(\s*id\s*\)",
            r"\.FirstOrDefaultAsync\s*\(\s*.*\s*=>\s*.*\.Id\s*==\s*id",
            r"\.Remove\s*\(\s*entity\s*\)",
            r"return\s+Ok\s*\(\s*entity\s*\)",
            r"var\s+entity\s*=\s*await\s+_context\.\w+\.FindAsync\s*\(\s*id\s*\)",
            r"GetById\s*\(\s*(?:int|long|string)\s+id\s*\)"
        ],
        "description": "Direct object access by user-controlled ID without resource-level authorization (IDOR)",
        "recommendations": [
            "Verify resource ownership/authorization before returning or modifying data",
            "Do not trust IDs sent by clients",
            "Apply object-level authorization in the business layer",
            "Use opaque identifiers when possible",
            "Log access and denials for sensitive resources",
            "Create tests for horizontal access between users"
        ]
    },

    "debug_endpoint_exposure": {
        "name": "Sensitive Information Exposure (Debug Endpoint)",
        "severity": "medium",
        "patterns": [
            r"\[HttpGet\s*\(\s*['\"]/debug",
            r"MapGet\s*\(\s*['\"]/debug",
            r"UseDeveloperExceptionPage\s*\(\s*\)",
            r"app\.UseExceptionHandler\s*\(\s*['\"]/Error\s*\)",
            r"IncludeExceptionDetails\s*=\s*true",
            r"return\s+Problem\s*\(\s*detail\s*:\s*ex\.ToString\s*\(",
            r"return\s+Content\s*\(\s*ex\.StackTrace",
            r"Environment\.GetEnvironmentVariables\s*\(",
            r"builder\.Logging\.SetMinimumLevel\s*\(\s*LogLevel\.Debug\s*\)",
            r"ASPNETCORE_ENVIRONMENT\s*=\s*['\"]Development['\"]"
        ],
        "description": "Debug endpoints or configuration can expose stack traces, environment variables, or internal configuration",
        "recommendations": [
            "Disable development exception pages in production",
            "Do not return stack traces to clients",
            "Restrict internal diagnostic endpoints",
            "Filter sensitive data in logs and responses",
            "Use generic error responses",
            "Separate Development/Production profiles correctly"
        ]
    },

    "jwt_auth_mismanagement": {
        "name": "JWT Authentication Mismanagement",
        "severity": "high",
        "patterns": [
            r"new\s+SymmetricSecurityKey\s*\(\s*Encoding\.UTF8\.GetBytes\s*\(\s*['\"][^'\"]+['\"]\s*\)\s*\)",
            r"IssuerSigningKey\s*=\s*new\s+SymmetricSecurityKey\s*\(\s*Encoding\.UTF8\.GetBytes\s*\(\s*['\"][^'\"]+['\"]",
            r"ValidateIssuer\s*=\s*false",
            r"ValidateAudience\s*=\s*false",
            r"ValidateLifetime\s*=\s*false",
            r"RequireExpirationTime\s*=\s*false",
            r"ClockSkew\s*=\s*TimeSpan\.From(?:Hours|Days)\s*\(",
            r"SecurityAlgorithms\.None",
            r"JwtSecurityToken\s*\(\s*.*expires\s*:\s*DateTime\.UtcNow\.AddDays\s*\(\s*365",
            r"TokenValidationParameters\s*\{\s*.*\}"
        ],
        "description": "Insecure JWT configuration due to disabled validations, weak secrets, or excessive expirations",
        "recommendations": [
            "Store JWT keys outside source code",
            "Enable ValidateIssuer, ValidateAudience, and ValidateLifetime",
            "Avoid SecurityAlgorithms.None",
            "Use short expirations and controlled refresh tokens",
            "Rotate keys periodically",
            "Audit token validation errors"
        ]
    },

    "jwt_forgery_token_manipulation": {
        "name": "JWT Forgery (Token Manipulation)",
        "severity": "critical",
        "patterns": [
            r"token\.Split\s*\(\s*'\\.'\s*\)\s*\[1\]",
            r"Convert\.FromBase64String\s*\(\s*token\.Split",
            r"Encoding\.UTF8\.GetString\s*\(\s*Convert\.FromBase64String",
            r"JsonSerializer\.Deserialize\s*<\s*Dictionary<",
            r"claims\[['\"](?:role|admin|isAdmin)['\"]\]\s*=",
            r"new\s+JwtSecurityToken\s*\(\s*header\s*,\s*payload",
            r"ReadJwtToken\s*\(\s*token\s*\)",
            r"CanReadToken\s*\(\s*token\s*\)",
            r"if\s*\(\s*jwt\.Payload\[['\"]role['\"]\]",
            r"token\s*=\s*header\s*\+\s*\"\\.\"\s*\+\s*payload"
        ],
        "description": "Manual JWT manipulation or use of claims without signature validation enables impersonation and privilege escalation",
        "recommendations": [
            "Do not use token claims without cryptographic validation",
            "Validate signature and algorithm restrictions on every request",
            "Reject tokens with alg=none",
            "Do not manually build tokens by concatenating header/payload",
            "Use secure and maintained JWT libraries",
            "Monitor invalid or manipulated token patterns"
        ]
    }
}
