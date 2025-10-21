export const passiveChecks = [
    // ############ Network / TLS / Zertifikate ############
    {
        title: "Security: Missing HSTS Header",
        description: "The HTTP Strict-Transport-Security header is not set. This allows an attacker to perform a man-in-the-middle attack by downgrading the connection from HTTPS to HTTP.",
        detectHeaders: [],
        missingHeaders: ["Strict-Transport-Security"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Weak HSTS Policy",
        description: "The HTTP Strict-Transport-Security header is set with a weak policy. A short max-age value allows an attacker to perform a man-in-the-middle attack by downgrading the connection from HTTPS to HTTP.",
        detectHeaders: ["Strict-Transport-Security: max-age=1"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },

    // ############ HTTP-Header & Policy-Checks ############
    {
        title: "Security: Missing X-Frame-Options Header",
        description: "The X-Frame-Options header is not set. This allows an attacker to embed the page in an iframe and perform a clickjacking attack.",
        detectHeaders: [],
        missingHeaders: ["X-Frame-Options"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Missing X-Content-Type-Options Header",
        description: "The X-Content-Type-Options header is not set. This can lead to MIME-sniffing attacks, where the browser interprets a file as a different content type than intended.",
        detectHeaders: [],
        missingHeaders: ["X-Content-Type-Options"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Missing Content-Security-Policy Header",
        description: "The Content-Security-Policy header is not set. This header helps to prevent Cross-Site Scripting (XSS) attacks by specifying which sources of content are allowed.",
        detectHeaders: [],
        missingHeaders: ["Content-Security-Policy"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Weak CSP 'unsafe-inline'",
        description: "The Content-Security-Policy header contains the 'unsafe-inline' directive. This allows the execution of inline scripts, which can lead to XSS vulnerabilities.",
        detectHeaders: ["Content-Security-Policy: unsafe-inline"],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Security: Weak CSP 'unsafe-eval'",
        description: "The Content-Security-Policy header contains the 'unsafe-eval' directive. This allows the use of eval(), which can be a security risk.",
        detectHeaders: ["Content-Security-Policy: unsafe-eval"],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Security: Missing Referrer-Policy Header",
        description: "The Referrer-Policy header is not set. This can leak sensitive information to other websites.",
        detectHeaders: [],
        missingHeaders: ["Referrer-Policy"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Missing Permissions-Policy Header",
        description: "The Permissions-Policy header is not set. This header allows you to control which features and APIs can be used in the browser.",
        detectHeaders: [],
        missingHeaders: ["Permissions-Policy"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Missing Cross-Origin-Opener-Policy Header",
        description: "The Cross-Origin-Opener-Policy header is not set. Without it, the page stays vulnerable to cross-origin attacks that leverage shared browsing context.",
        detectHeaders: [],
        missingHeaders: ["Cross-Origin-Opener-Policy"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Missing Cross-Origin-Embedder-Policy Header",
        description: "The Cross-Origin-Embedder-Policy header is not set. This header helps prevent untrusted cross-origin resources from being loaded into the page.",
        detectHeaders: [],
        missingHeaders: ["Cross-Origin-Embedder-Policy"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Missing Cross-Origin-Resource-Policy Header",
        description: "The Cross-Origin-Resource-Policy header is not set. Without it, resources may be embedded by external sites, increasing the attack surface.",
        detectHeaders: [],
        missingHeaders: ["Cross-Origin-Resource-Policy"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Security: Permissive CORS Policy",
        description: "Access-Control-Allow-Origin allows any origin (*). This enables third-party sites to read responses meant for authenticated users.",
        detectHeaderValues: [
            { header: "Access-Control-Allow-Origin", equals: "*" }
        ],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Security: CORS Allows Credentials for Any Origin",
        description: "The combination of Access-Control-Allow-Credentials: true and Access-Control-Allow-Origin: * allows credentialed cross-origin requests, which is insecure.",
        detectHeaderValues: [
            { header: "Access-Control-Allow-Origin", equals: "*" },
            { header: "Access-Control-Allow-Credentials", equals: "true" }
        ],
        requireAllHeaderValues: true,
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "Info: X-Powered-By Header Exposed",
        description: "The X-Powered-By header reveals backend technology details that can help attackers fingerprint known exploits.",
        detectHeaders: ["X-Powered-By"],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 1
    },
    {
        title: "Info: Server Header Exposed",
        description: "The Server header discloses information about the web server software being used. This information can be used by an attacker to identify known vulnerabilities.",
        detectHeaders: ["Server"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },

    // ############ Cookies & Sessionverwaltung ############
    {
        title: "Security: Cookie without Secure-Flag",
        description: "A cookie is set without the 'Secure' flag. This means the cookie can be transmitted over an unencrypted connection, making it vulnerable to interception.",
        detectHeaders: ["Set-Cookie:"],
        missingCookieFlags: ["Secure"],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Security: Cookie without HttpOnly-Flag",
        description: "A cookie is set without the 'HttpOnly' flag. This makes it accessible to JavaScript, which can lead to XSS attacks.",
        detectHeaders: ["Set-Cookie:"],
        missingCookieFlags: ["HttpOnly"],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Security: Cookie without SameSite-Flag",
        description: "A cookie is set without the 'SameSite' flag. This can lead to Cross-Site Request Forgery (CSRF) attacks.",
        detectHeaders: ["Set-Cookie:"],
        missingCookieFlags: ["SameSite"],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 2
    },

    // ############ File disclosure & Enumeration ############
    {
        title: "Sensitive File: .bak",
        description: "A backup file is publicly accessible. This can expose sensitive information, such as source code or configuration files.",
        rootPaths: [".bak", ".old", ".zip", ".tar.gz", ".sql"],
        detectStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Exposed Git Directory",
        description: "The .git directory is publicly accessible. This can expose the entire source code of the application, including sensitive information.",
        rootPaths: ["/.git/config"],
        detectResponses: ["[core]"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "Exposed SVN Directory",
        description: "The .svn directory is publicly accessible. This can expose the entire source code of the application, including sensitive information.",
        rootPaths: ["/.svn/entries"],
        detectResponses: ["dir"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "Directory Listing Enabled",
        description: "Directory listing is enabled on the web server. This can expose sensitive files and directories.",
        rootPaths: ["/"],
        detectResponses: ["Index of /", "Parent Directory"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Exposed .DS_Store file",
        description: "A .DS_Store file is publicly accessible. This file can expose the file and directory structure of the server.",
        rootPaths: ["/.DS_Store"],
        detectResponses: [".DS_Store"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Exposed 'WEB-INF/web.xml' file",
        description: "The WEB-INF/web.xml file is publicly accessible. This file can expose the internal structure and configuration of a Java web application.",
        rootPaths: ["/WEB-INF/web.xml"],
        detectResponses: ["<web-app"],
        tags: ["java"],
        dog: "dog-panic",
        critLevel: 2
    },

    // ############ Sensitive Data Exposure ############
    {
        title: "Info: Detailed stack traces / debug info visible",
        description: "Detailed stack traces or debug information is visible. This can expose sensitive information about the application and server.",
        detectResponses: ["stack trace", "debug info"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },

    // ############ Cross-Site-Scripting (XSS) & DOM-Analyse ############
    {
        title: "XSS Reflected - Template",
        description: "A reflected XSS vulnerability was found. The payload 'nhc-xss-test-payload' was reflected in the response. This can be exploited by an attacker to execute arbitrary JavaScript in the victim's browser.",
        params: ["nhc-xss-test-payload"],
        detectResponses: ["nhc-xss-test-payload"],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },

    // ############ Server-Side Template Injection (SSTI) ############
    {
        title: "SSTI - Server Side Template Injection",
        description: "A Server-Side Template Injection (SSTI) vulnerability was found. The payload '{{999*999}}' was evaluated and the result '998001' was reflected in the response. This can be exploited by an attacker to execute arbitrary code on the server.",
        params: ["{{999*999}}"],
        detectResponses: ["998001"],
        tags: ["get-param"],
        dog: "dog-panic",
        critLevel: 3
    },

    // ############ Prototype Pollution ############
    {
        title: "Server-Side Prototype Pollution",
        description: "A Server-Side Prototype Pollution vulnerability was found. The payload '__proto__[nhc_polluted]=true' was reflected in the response. This can be exploited by an attacker to modify the behavior of the application.",
        params: ["__proto__[nhc_polluted]=true"],
        detectResponses: ["nhc_polluted"],
        tags: ["get-param"],
        dog: "dog-panic",
        critLevel: 3
    },

    // ############ Exposed sensitive files ############
    {
        title: "Exposed .env file",
        description: "The .env file is publicly accessible. This file can expose sensitive information, such as database credentials and API keys.",
        rootPaths: ["/.env"],
        detectResponses: ["="],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    }
];
