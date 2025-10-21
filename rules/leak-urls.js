export const leakUrls = [
	{
		title: "Git Config", // the title of the alert message
		description: "The .git directory is publicly accessible. This can expose the entire source code of the application, including sensitive information such as remote repository URLs, commit history, and more.",
		paths: [ // this stuff will be after the  current url
			"/.git/",
			"/.git/config"
		],
		detectResponses: ["remote"], // check this response in body
		filterStatusCodes: ["200"], // only check other detect values if response code matches
		detectStatusCodes: ["200"], // alert is based on response code
		tags: ["root"], // only run this rule if these tags where detected on the website
		dog: "dog-laugh", // change the avatar to this image
		critLevel: 1 // 1,2,3 critlevel is for showing the most critical kitten
	},
	{
		title: "Helm Config",
		description: "A Helm configuration file is publicly accessible. This can expose sensitive information about the Kubernetes application, such as service names, versions, and other configuration details.",
		rootPaths: [
			"/.helm/values.yaml"
		],
		detectResponses: ["password"],
		filterStatusCodes: ["200"],
		tags: ["root"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Nginx Config",
		description: "An Nginx configuration file is publicly accessible. This can expose sensitive information about the web server configuration, such as server names, ports, and other directives.",
		rootPaths: [
			"/nginx/nginx.conf",
			"/nginx.conf"
		],
		detectResponses: ["server"],
		filterStatusCodes: ["200"],
		tags: ["nginx"],
		dog: "dog-laugh",
		critLevel: 1
	},
	{
		title: "Nginx - Git Configuration Exposure",
		description: "The .git directory is publicly accessible through a misconfigured Nginx server. This can expose the entire source code of the application, including sensitive information such as remote repository URLs, commit history, and more.",
		rootPaths: [
			'/static../.git/config',
			'/js../.git/config',
			'/images../.git/config',
			'/img../.git/config',
			'/css../.git/config',
			'/assets../.git/config',
			'/content../.git/config',
			'/events../.git/config',
			'/media../.git/config',
			'/lib../.git/config'
		],
		detectResponses: ["[core]"],
		filterStatusCodes: ["200"],
		tags: ["nginx"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Git Credentials Disclosure",
		description: "A .git-credentials file is publicly accessible. This file can contain plaintext credentials for Git repositories, which could be used to gain unauthorized access to the codebase.",
		rootPaths: [
			'/.git-credentials'
		],
		detectResponses: ["[credential"],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "WP-Config Backup",
		description: "A backup of the wp-config.php file is publicly accessible. This file contains sensitive information, such as database credentials, which could be used to gain unauthorized access to the database.",
		rootPaths: [
			"/wp-config.php~",
			"/wp-config.php.bak",
			"/wp-config.php.backup",
			"/wp-config.bak",
			"/wp-config.php.bkp",
			"/wp-config.php.copy",
			"/wp-config.php.old",
			"/wp-config.php.orig",
			"/wp-config.php.save",
			"/wp-config.php.swp",
			"/wp-config.php.temp",
			"/wp-config.php.tmp"
		],
		detectResponses: ["DB_PASSWORD"],
		filterStatusCodes: ["200"],
		tags: ["wordpress", "wp"],
		dog: "dog-panic",
		critLevel: 3
	},
	{
		title: "WP-Content File Listing",
		description: "Directory listing is enabled for the wp-content directory. This can expose sensitive files and directories, which could be used to identify vulnerabilities or gain unauthorized access to the application.",
		rootPaths: [
			"/wp-content/"
		],
		detectResponses: [
			"Index of"
		],
		filterStatusCodes: ["200"],
		tags: ["wordpress", "wp"],
		dog: "dog-default",
		critLevel: 2
	},
	{
		title: "SQL Backup",
		description: "A SQL backup file is publicly accessible. This can expose the entire database, including sensitive information such as user credentials, personal data, and more.",
		rootPaths: [
			"/mysql.initial.sql",
			"/db.sql",
			"/dump.sql",
			"/backup.zip",
			"/backup.sql",
			"/backup.old",
			"/data.sql",
			"/data.old",
			"/temp.sql",
			"/users.sql"
		],
		detectResponses: [
			"INSERT INTO",
			"Roundcube Webmail initial database structure"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-panic",
		critLevel: 2
	},
	{
		title: "Webserver Backupfiles",
		description: "A backup of a web server configuration file is publicly accessible. This can expose sensitive information such as database credentials, API keys, and other secrets.",
		paths: [
			"/main.php.bak",
			"/config.php.bak",
			"/db.php.bak",
			"/database.php.bak",
		],
		detectResponses: [
			"<?php"
		],
		filterStatusCodes: ["200"],
		tags: ["apache"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Ruby-on-Rails Database Configuration Exposure",
		description: "The database.yml file is publicly accessible. This file contains database credentials, which could be used to gain unauthorized access to the database.",
		rootPaths: [
			"/config/database.yml"
		],
		detectResponses: [
			"database:"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 1
	},
	{
		title: "Webserver Access Logs",
		description: "Web server access logs are publicly accessible. This can expose sensitive information about visitors to the website, such as their IP addresses, user agents, and the pages they have visited.",
		rootPaths: [
			"/access.log",
			"/log/access.log",
			"/logs/access.log",
			"/application/logs/access.log"
		],
		detectResponses: [
			"GET /"
		],
		filterStatusCodes: ["200"],
		tags: ["root"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Zend Configuration File",
		description: "A Zend Framework configuration file is publicly accessible. This can expose sensitive information, such as database credentials, API keys, and other secrets.",
		rootPaths: [
			"/application/configs/application.ini",
			"/admin/configs/application.ini",
			"/application.ini",
			"/aplicacao/application/configs/application.ini",
			"/cloudexp/application/configs/application.ini",
			"/cms/application/configs/application.ini",
			"/moto/application/configs/application.ini",
			"/Partners/application/configs/application.ini",
			"/radio/application/configs/application.ini",
			"/seminovos/application/configs/application.ini",
			"/shop/application/configs/application.ini",
			"/site_cg/application/configs/application.ini",
			"/slr/application/configs/application.ini"
		],
		detectResponses: [
			"resources.db.params.password"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-panic",
		critLevel: 3
	},
	{
		title: "Web Config file",
		description: "A web.config file is publicly accessible. This file can expose sensitive information about the application configuration, such as database connection strings, API keys, and other secrets.",
		rootPaths: [
			"/web.config",
			"/../../web.config"
		],
		detectResponses: [
			"<configuration>"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 1
	},
	{
		title: "Clockwork PHP page exposure",
		description: "A Clockwork debug page is publicly accessible. This can expose sensitive information about the application, such as database queries, application logs, and other debugging information.",
		rootPaths: [
			"/__clockwork/app"
		],
		detectResponses: [
			"<title>Clockwork</title>"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 2
	},
	{
		title: "Rails Debug Mode",
		description: "The application is running in debug mode. This can expose sensitive information about the application, such as the application's source code, database schema, and other internal details.",
		rootPaths: [
			"/jkfnjdknfkdnfgkdsng"
		],
		detectResponses: [
			"Action Controller: Exception caught"
		],
		filterStatusCodes: ["200"],
		tags: ["root"],
		dog: "dog-default",
		critLevel: 1
	},
	{
		title: "Roundcube Logs",
		description: "Roundcube logs are publicly accessible. This can expose sensitive information about email communication, such as sender and recipient email addresses, subject lines, and other metadata.",
		rootPaths: [
			"/roundcube/logs/sendmail",
			"/roundcube/logs/errors.log"
		],
		detectResponses: [
			"IMAP Error:"
		],
		filterStatusCodes: ["200"],
		tags: ["roundcube"],
		dog: "dog-laugh",
		critLevel: 1
	},
	{
		title: "BitBucket Pipelines Configuration",
		description: "A BitBucket Pipelines configuration file is publicly accessible. This can expose sensitive information about the CI/CD pipeline, such as build scripts, deployment credentials, and other secrets.",
		rootPaths: [
			"/bitbucket-pipelines.yml"
		],
		detectResponses: [
			"pipelines:"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Composer-auth JSON File Disclosure",
		description: "A composer-auth.json file is publicly accessible. This file can contain authentication tokens for Composer repositories, which could be used to gain unauthorized access to private packages.",
		rootPaths: [
			"/.composer-auth.json",
			"/vendor/webmozart/assert/.composer-auth.json"
		],
		detectResponses: [
			"github-oauth"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 2
	},
	{
		title: "Drupal Install",
		description: "The Drupal installation script is publicly accessible. This could allow an attacker to re-install the application, which could lead to a complete compromise of the site.",
		rootPaths: [
			"/install.php?profile=default"
		],
		detectResponses: [
			"<title>Choose language | Drupal</title>"
		],
		filterStatusCodes: ["200"],
		tags: ["drupal"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Drupal User Listing",
		description: "A list of Drupal users is publicly accessible. This can expose usernames and other sensitive information, which could be used to launch targeted attacks against the application.",
		rootPaths: [
			"/jsonapi/user/user"
		],
		detectResponses: [
			"display_name"
		],
		filterStatusCodes: ["200"],
		tags: ["drupal"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Public Swagger API",
		description: "A Swagger API documentation page is publicly accessible. This can expose sensitive information about the API, such as endpoints, parameters, and data models.",
		rootPaths: [
			"/swagger-ui/swagger-ui.js",
			"/swagger/swagger-ui.js",
			"/swagger-ui.js",
			"/swagger/ui/swagger-ui.js",
			"/swagger/ui/index",
			"/swagger/index.html",
			"/swagger-ui.html",
			"/swagger/swagger-ui.html",
			"/api/swagger-ui.html",
			"/api-docs/swagger.json",
			"/api-docs/swagger.yaml",
			"/api_docs",
			"/swagger.json",
			"/swagger.yaml",
			"/swagger/v1/swagger.json",
			"/swagger/v1/swagger.yaml",
			"/api/index.html",
			"/api/docs/",
			"/api/swagger.json",
			"/api/swagger.yaml",
			"/api/swagger.yml",
			"/api/swagger/index.html",
			"/api/swagger/swagger-ui.html",
			"/api/api-docs/swagger.json",
			"/api/api-docs/swagger.yaml",
			"/api/swagger-ui/swagger.json",
			"/api/swagger-ui/swagger.yaml",
			"/api/apidocs/swagger.json",
			"/api/apidocs/swagger.yaml",
			"/api/swagger-ui/api-docs",
			"/api/api-docs",
			"/api/apidocs",
			"/api/swagger",
			"/api/swagger/static/index.html",
			"/api/swagger-resources",
			"/api/swagger-resources/restservices/v2/api-docs",
			"/api/__swagger__/",
			"/api/_swagger_/",
			"/api/spec/swagger.json",
			"/api/spec/swagger.yaml",
			"/api/swagger/ui/index",
			"/__swagger__/",
			"/_swagger_/",
			"/api/v1/swagger-ui/swagger.json",
			"/api/v1/swagger-ui/swagger.yaml",
			"/swagger-resources/restservices/v2/api-docs",
			"/api/swagger_doc.json"
		],
		detectResponses: [
			"swagger:",
			"Swagger UI"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 1
	},
	{
		title: "Filezilla Config",
		description: "A Filezilla configuration file is publicly accessible. This can expose FTP credentials, which could be used to gain unauthorized access to the server.",
		rootPaths: [
			"/filezilla.xml",
			"/sitemanager.xml",
			"/FileZilla.xml"
		],
		detectResponses: [
			"<FileZilla"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 1
	},
	{
		title: "Gemfile Leak",
		description: "A Gemfile is publicly accessible. This can expose the list of gems used by the application, which can help an attacker to identify known vulnerabilities and target the application more effectively.",
		rootPaths: [
			"/Gemfile",
			"/Gemfile.lock"
		],
		detectResponses: [
			"https://rubygems.org"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 1
	},
	{
		title: "Joomla Database Listing",
		description: "Directory listing is enabled for the Joomla database directory. This can expose sensitive information, such as the database schema and table names.",
		rootPaths: [
			"/libraries/joomla/database/"
		],
		detectResponses: [
			"Index of /libraries/joomla/database"
		],
		filterStatusCodes: ["200"],
		tags: ["joomla"],
		dog: "dog-default",
		critLevel: 1
	},
	{
		title: "Oauth Credentials JSON",
		description: "An OAuth credentials file is publicly accessible. This can expose sensitive information, such as client secrets, which could be used to gain unauthorized access to the application.",
		rootPaths: [
			"/oauth-credentials.json"
		],
		detectResponses: [
			"client_secret"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Redmine Configuration",
		description: "A Redmine configuration file is publicly accessible. This can expose sensitive information, such as database credentials, API keys, and other secrets.",
		rootPaths: [
			"/configuration.yml",
			"/config/configuration.yml",
			"/redmine/config/configuration.yml"
		],
		detectResponses: [
			"password"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-panic",
		critLevel: 3
	},
	{
		title: "Secret Token Ruby",
		description: "A secret token file is publicly accessible. This can allow an attacker to forge session cookies and gain unauthorized access to the application.",
		rootPaths: [
			"/secret_token.rb",
			"/config/initializers/secret_token.rb",
			"/redmine/config/initializers/secret_token.rb"
		],
		detectResponses: [
			"::Application.config.secret"
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Detect .dockercfg",
		description: "A .dockercfg file is publicly accessible. This file can contain authentication tokens for Docker registries, which could be used to gain unauthorized access to private images.",
		rootPaths: [
			"/.dockercfg",
			"/.docker/config.json"
		],
		detectResponses: [
			'"auth":'
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-panic",
		critLevel: 3
	},
	{
		title: "Coremail - Config Discovery",
		description: "A Coremail configuration file is publicly accessible. This can expose sensitive information about the mail server, such as database credentials, user accounts, and other configuration details.",
		rootPaths: [
			"/mailsms/s?func=ADMIN:appState&dumpConfig=/"
		],
		detectResponses: [
			'<string name="User">coremail</string>'
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-panic",
		critLevel: 3
	},
	{
		title: "Dockerfile Hidden Disclosure",
		description: "A hidden Dockerfile is publicly accessible. This can expose sensitive information about the application image, such as the base image, installed packages, and other configuration details.",
		rootPaths: [
			"/.dockerfile",
			"/.Dockerfile"
		],
		detectResponses: [
			'FROM'
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "docker-compose.yml exposure",
		description: "A docker-compose.yml file is publicly accessible. This file can expose sensitive information about the application stack, such as service names, versions, and other configuration details.",
		rootPaths: [
			"/docker-compose.yml",
			"/docker-compose.prod.yml",
			"/docker-compose.production.yml",
			"/docker-compose.staging.yml",
			"/docker-compose.dev.yml",
			"/docker-compose-dev.yml",
			"/docker-compose.override.yml"
		],
		detectResponses: [
			'services:'
		],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-laugh",
		critLevel: 2
	},
	{
		title: "Info: Subdomain",
		description: "A potentially interesting subdomain was found. This is not a vulnerability, but it is useful information for an attacker.",
		subdomains: [
			"mail",
			"imap",
			"smtp",
			"weblogic",
			"api",
			"exchange",
			"owa",
			"backend",
			"backup",
			"build",
			"bitbucket",
			"citrix",
			"chat",
			"talk",
			"community",
			"console",
			"terminal",
			"confluence",
			"conf",
			"data",
			"database",
			"sql",
			"mysql",
			"demo",
			"dev",
			"development",
			"downloads",
			"download",
			"drupal",
			"files",
			"file",
			"firewall",
			"ftp",
			"home",
			"jobs",
			"mobile",
			"auth",
			"wordpress",
			"blog",
			"weblog",
			"webmail",
			"server",
			"admin",
			"git",
			"login",
			"logs",
			"registry",
			"internal",
			"intern",
			"config",
			"vpn",
			"vnc",
			"scanme"
		],
		skipRedirected: true,
		detectStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 0
	},
	{
		title: "Info: Dev Port",
		description: "A common development port is open. This is not a vulnerability, but it is useful information for an attacker.",
		ports: [
			"8080",
			"8081",
			"4434",
			"5000",
			"3000",
			"3001",
			"4000",
			"4443",
			"5000",
			"5001",
			"8443"
		],
		detectStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 0
	},
    {
        title: "Dockerfile",
        description: "A Dockerfile is publicly accessible. This can expose sensitive information about the application image, such as the base image, installed packages, and other configuration details.",
        rootPaths: [
            "/Dockerfile"
        ],
        detectResponses: ["FROM"],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 2
    },
    {
        title: ".env file",
        description: "An .env file is publicly accessible. This file can contain sensitive information, such as API keys and database credentials.",
        rootPaths: [
            "/.env",
            "/.env.local",
            "/.env.dev",
            "/.env.development",
            "/.env.prod",
            "/.env.production",
            "/.env.stage",
            "/.env.staging"
        ],
        detectResponses: ["="],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "Jenkinsfile",
        description: "A Jenkinsfile is publicly accessible. This can expose sensitive information about the CI/CD pipeline, such as build scripts, deployment credentials, and other secrets.",
        rootPaths: [
            "/Jenkinsfile"
        ],
        detectResponses: ["pipeline"],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 2
    },
    {
        title: "Kubernetes Config",
        description: "A Kubernetes configuration file is publicly accessible. This can expose sensitive information about the Kubernetes cluster, such as cluster names, user credentials, and other configuration details.",
        rootPaths: [
            "/.kube/config"
        ],
        detectResponses: ["apiVersion"],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "AWS Credentials",
        description: "An AWS credentials file is publicly accessible. This can expose AWS access keys, which could be used to gain unauthorized access to the AWS account.",
        rootPaths: [
            "/.aws/credentials"
        ],
        detectResponses: ["[default]"],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "Google Cloud Credentials",
        description: "A Google Cloud credentials file is publicly accessible. This can expose Google Cloud credentials, which could be used to gain unauthorized access to the Google Cloud account.",
        rootPaths: [
            "/.gcloud/credentials"
        ],
        detectResponses: ["["],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "SSH Private Key",
        description: "An SSH private key is publicly accessible. This can allow an attacker to gain unauthorized access to the server.",
        rootPaths: [
            "/.ssh/id_rsa"
        ],
        detectResponses: ["-----BEGIN RSA PRIVATE KEY-----"],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "SSH Known Hosts",
        description: "An SSH known_hosts file is publicly accessible. This can expose information about other servers that the current server has connected to.",
        rootPaths: [
            "/.ssh/known_hosts"
        ],
        detectResponses: ["|1|"],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-default",
        critLevel: 1
    },
    {
        title: "Server Status",
        description: "The server-status page is publicly accessible. This can expose sensitive information about the server, such as the server version, uptime, and other configuration details.",
        rootPaths: [
            "/server-status"
        ],
        detectResponses: ["Apache Server Status"],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-default",
        critLevel: 1
    },
    {
        title: "DS_Store file",
        description: "A .DS_Store file is publicly accessible. This file can expose sensitive information about the directory structure of the application.",
        rootPaths: [
            "/.DS_Store"
        ],
        detectResponses: ["Bud1"],
        filterStatusCodes: ["200"],
        tags: ["all"],
        dog: "dog-default",
        critLevel: 1
    },
	{
		title: "SSH Private Key",
		description: "An SSH private key is publicly accessible. This can allow an attacker to gain unauthorized access to the server.",
		rootPaths: [
			"/.ssh/id_dsa"
		],
		detectResponses: ["-----BEGIN DSA PRIVATE KEY-----"],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-panic",
		critLevel: 3
	},
	{
		title: "SVN Metadata Exposure",
		description: "Subversion metadata is accessible. Attackers can enumerate source files and download previous revisions.",
		rootPaths: [
			"/.svn/entries",
			"/.svn/all-wcprops"
		],
		detectResponses: ["svn:"],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 2
	},
	{
		title: "Mercurial Repository Exposure",
		description: "A Mercurial repository configuration is exposed. This can reveal repository URLs and authentication details.",
		rootPaths: [
			"/.hg/hgrc"
		],
		detectResponses: ["[paths]"],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 2
	},
	{
		title: "Composer Lock Exposure",
		description: "The composer.lock file is publicly accessible. It can expose PHP dependencies and known vulnerable package versions.",
		rootPaths: [
			"/composer.lock"
		],
		detectResponses: ["\"name\""],
		filterStatusCodes: ["200"],
		tags: ["php", "all"],
		dog: "dog-love",
		critLevel: 1
	},
	{
		title: "Node Package Lock Exposure",
		description: "The package-lock.json file is publicly accessible. This can reveal JavaScript dependencies and potential supply-chain weaknesses.",
		rootPaths: [
			"/package-lock.json",
			"/npm-shrinkwrap.json"
		],
		detectResponses: ["\"lockfileVersion\""],
		filterStatusCodes: ["200"],
		tags: ["node", "all"],
		dog: "dog-love",
		critLevel: 1
	},
	{
		title: "Yarn Lock Exposure",
		description: "The yarn.lock file is publicly accessible. Attackers can map the full dependency graph and target known vulnerabilities.",
		rootPaths: [
			"/yarn.lock"
		],
		detectResponses: ["\"resolved\""],
		filterStatusCodes: ["200"],
		tags: ["node", "all"],
		dog: "dog-love",
		critLevel: 1
	},
	{
		title: "Docker Compose File Exposure",
		description: "A docker-compose.yml file is accessible. This may disclose service credentials and internal architecture.",
		rootPaths: [
			"/docker-compose.yml",
			"/docker-compose.yaml"
		],
		detectResponses: ["services:"],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 2
	},
	{
		title: "ASP.NET Core appsettings Exposure",
		description: "An appsettings.json file is publicly accessible. It often contains connection strings and environment secrets.",
		rootPaths: [
			"/appsettings.json",
			"/appsettings.Development.json"
		],
		detectResponses: ["\"ConnectionStrings\""],
		filterStatusCodes: ["200"],
		tags: ["dotnet", "all"],
		dog: "dog-panic",
		critLevel: 3
	},
	{
		title: "Rails Database Config Exposure",
		description: "The Rails config/database.yml file is accessible. Database credentials can be extracted directly.",
		rootPaths: [
			"/config/database.yml"
		],
		detectResponses: ["adapter:"],
		filterStatusCodes: ["200"],
		tags: ["rails", "all"],
		dog: "dog-panic",
		critLevel: 3
	},
	{
		title: "Java WEB-INF Exposure",
		description: "The WEB-INF/web.xml descriptor is accessible. It discloses servlet mappings and security constraints.",
		rootPaths: [
			"/WEB-INF/web.xml"
		],
		detectResponses: ["<web-app"],
		filterStatusCodes: ["200"],
		tags: ["java", "all"],
		dog: "dog-default",
		critLevel: 2
	},
	{
		title: "npmrc Exposure",
		description: "An .npmrc file is accessible. It may contain private registry credentials or tokens.",
		rootPaths: [
			"/.npmrc"
		],
		detectResponses: ["registry="],
		filterStatusCodes: ["200"],
		tags: ["node", "all"],
		dog: "dog-panic",
		critLevel: 2
	},
	{
		title: "Firebase Debug Log Exposure",
		description: "A firebase-debug.log file is publicly accessible. It can leak stack traces, API keys, and project metadata.",
		rootPaths: [
			"/firebase-debug.log"
		],
		detectResponses: ["Firebase"],
		filterStatusCodes: ["200"],
		tags: ["all"],
		dog: "dog-default",
		critLevel: 1
	},
	{
		title: "Terraform State Exposure",
		description: "A terraform.tfstate file is publicly accessible. It contains cloud resource identifiers and secrets.",
		rootPaths: [
			"/terraform.tfstate"
		],
		detectResponses: ["\"resources\""],
		filterStatusCodes: ["200"],
		tags: ["cloud", "all"],
		dog: "dog-panic",
		critLevel: 3
	}
]
