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
        "description": "Concatenación de variables en consultas SQL sin usar prepared statements, vulnerables a inyección SQL",
        "recommendations": [
            "Usar PreparedStatement con setString(), setInt(), etc",
            "Usar ORMs como Hibernate, JPA o Spring Data",
            "Usar @Query con parametrización en Spring Data",
            "Validar y sanitizar todas las entradas del usuario",
            "Usar whitelist de valores permitidos",
            "Implementar principio de menos privilegios en conexiones DB"
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
        "description": "Ejecución de comandos del sistema con variables sin validar, permite command injection",
        "recommendations": [
            "Usar ProcessBuilder con lista de argumentos separados",
            "Nunca concatenar strings en comandos",
            "Usar whitelisting de comandos permitidos",
            "Validar y sanitizar todas las entradas de usuario",
            "Evitar pasar datos de usuario directamente a exec",
            "Implementar least privilege para procesos ejecutados"
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
        "description": "Procesamiento de XML con entidades externas habilitadas permite lectura de archivos o DoS",
        "recommendations": [
            "Deshabilitar XXE mediante setFeature con DISALLOW_DOCTYPE_DECL",
            "Usar OWASP XXE Prevention Cheat Sheet",
            "Usar bibliotecas seguras como XStream",
            "Validar y sanitizar entrada XML",
            "Implementar límites en tamaño de archivos",
            "Usar whitelisting de elementos XML permitidos"
        ]
    },
    
    "hardcoded_secrets": {
        "name": "Secretos hardcodeados",
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
        "description": "Credenciales, claves API, tokens y secretos expuestos en código fuente",
        "recommendations": [
            "Usar variables de entorno para almacenar secretos",
            "Usar gestores de secretos como HashiCorp Vault",
            "Usar Spring Cloud Config Server para configuración sensible",
            "Nunca commitar archivos con credenciales al repositorio",
            "Usar .gitignore para excluir archivos secretos",
            "Rotar todas las credenciales encontradas inmediatamente"
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
        "description": "Desserialización insegura de objetos Java permite ejecución de código arbitrario",
        "recommendations": [
            "Usar JSON (Jackson, Gson) en lugar de serialización Java",
            "Implementar ObjectInputFilter para filtrar clases",
            "Usar NotSerializable interface en clases sensibles",
            "Validar fuente de datos antes de desserializar",
            "Considerar firmar datos serializados con HMAC",
            "Usar librerías seguras como Protobuf"
        ]
    },
    
    "insecure_crypto": {
        "name": "Criptografía insegura",
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
        "description": "Algoritmos criptográficos débiles (MD5, SHA1, DES, ECB) o parámetros inseguros",
        "recommendations": [
            "Usar SHA-256 o SHA-3 en lugar de MD5/SHA1",
            "Usar bcrypt o PBKDF2 para hashear contraseñas",
            "Usar AES-GCM en lugar de DES o ECB",
            "Generar IVs aleatorios con SecureRandom",
            "Usar librerías como Bouncy Castle para criptografía",
            "Nunca usar algoritmos débiles como DES"
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
        "description": "Acceso a archivos con rutas relativas o sin validación permite path traversal",
        "recommendations": [
            "Validar rutas solicitadas contra whitelist",
            "Usar Path.normalize() y verificar que está dentro del directorio permitido",
            "Nunca permitir '..' en rutas de usuario",
            "Usar java.nio.file.Files.walkFileTree() con SecureDirectoryStream",
            "Mantener archivos sensibles fuera del directorio web",
            "Implementar sandboxing de directorios base"
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
        "description": "Inyección de contenido HTML/JavaScript sin sanitizar permite XSS",
        "recommendations": [
            "Usar OWASP ESAPI Encoder para escapar salida",
            "Usar templating engines con auto-escape (Thymeleaf, Velocity)",
            "Implementar Content Security Policy (CSP) headers",
            "Escapar caracteres especiales (<, >, &, \", ')",
            "Validar y sanitizar todas las entradas del usuario",
            "Usar whitelist de caracteres permitidos"
        ]
    },
    
    "insecure_http_headers": {
        "name": "Encabezados HTTP inseguros",
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
        "description": "Encabezados HTTP faltantes o mal configurados pueden permitir ataques",
        "recommendations": [
            "Implementar X-Frame-Options: DENY",
            "Implementar X-Content-Type-Options: nosniff",
            "Implementar Strict-Transport-Security",
            "Especificar orígenes permitidos en CORS",
            "Implementar Content-Security-Policy",
            "Usar Secure, HttpOnly en cookies"
        ]
    },
    
    "weak_authentication": {
        "name": "Autenticación débil",
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
        "description": "Implementación de autenticación débil o validación incorrecta",
        "recommendations": [
            "Usar MessageDigest.isEqual() para comparar strings sensibles",
            "Usar bcrypt o PBKDF2 para hashear contraseñas",
            "Implementar autenticación multifactor (MFA)",
            "Usar JWT con secretos fuertes",
            "Implementar rate limiting en intentos de login",
            "Usar tokens seguros con expiration"
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
        "description": "Acceso a objetos por ID controlado por usuario sin control de autorización por recurso (IDOR)",
        "recommendations": [
            "Validar ownership/autorización del recurso antes de leer o modificar",
            "No confiar en IDs recibidos por path/query/body",
            "Aplicar autorización a nivel de objeto (method security + ABAC/RBAC)",
            "Usar identificadores opacos cuando sea viable",
            "Registrar eventos de acceso a recursos sensibles",
            "Agregar pruebas de acceso cruzado entre usuarios"
        ]
    },

    "debug_endpoint_exposure": {
        "name": "Exposición de información sensible (debug endpoint)",
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
        "description": "Endpoints o configuración de debug pueden exponer stack traces, entorno y configuración sensible",
        "recommendations": [
            "Deshabilitar endpoints de depuración en producción",
            "No exponer stack traces al cliente",
            "Restringir endpoints Actuator con autenticación/autorización",
            "No loggear secretos ni variables sensibles",
            "Usar mensajes de error genéricos hacia cliente",
            "Separar perfiles de configuración dev/prod"
        ]
    },

    "jwt_auth_mismanagement": {
        "name": "Mala gestión de autenticación con JWT",
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
        "description": "Configuración insegura de JWT por secretos hardcodeados o validaciones incompletas",
        "recommendations": [
            "Guardar secretos/llaves fuera del código fuente",
            "Validar firma, issuer, audience y expiración",
            "Rechazar algoritmo none y limitar algoritmos permitidos",
            "Usar expiración corta y rotación de claves",
            "Agregar revocación de tokens cuando aplique",
            "Instrumentar monitoreo de fallos de validación JWT"
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
        "description": "Manipulación manual del JWT o uso de claims sin verificar firma permite suplantación de identidad",
        "recommendations": [
            "No confiar en claims decodificados sin verificación criptográfica",
            "Validar firma y metadatos del token en cada request",
            "Restringir estrictamente algoritmos permitidos",
            "Rechazar tokens con alg=none",
            "Usar bibliotecas JWT mantenidas con defaults seguros",
            "Agregar detección y alertas para intentos de token manipulado"
        ]
    }
}
