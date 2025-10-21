export const fuzzing = [
    // This rules are running in fuzzing-engine and will be executed against
    // the current captured webrequest!
    {
        title: "SQL Injection on Login",
        description: "A simple SQL injection payload was sent in a login form. The server's response indicates that the login was successful, which may indicate a SQL injection vulnerability.",
        postParams: [
            "' OR 1=1 --"
        ],
        postParamKeywords: [
            "password",
            "pass",
            "pin"
        ],
        replaceParamValue: true,
        detectStatusCodes: ["200", "302"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Bypass: SQL Injection",
        description: "A simple SQL injection payload was sent. The server's response indicates that the request was successful, which may indicate a SQL injection vulnerability.",
        postParams: [
            "'-- ",
            "' or 'a'='a'-- "
        ],
        filterPostParams: [
            "id",
            "guid",
            "username",
            "user",
            "login",
            "password",
            "pass"
        ],
        filterStatusCodes: ["302", "200", "500"],
        detectResponses: ["auth", "logout", "syntax error"],
        dog: "dog-panic",
        critLevel: 3
    },
    {
        title: "Default Keywords",
        description: "Common default keywords were sent in a form. The server's response indicates that the request was successful, which may indicate a weak password policy.",
        postParams: [
            "admin",
            "test",
            "dev",
            "testing",
            "guest"
        ],
        filterPostParams: [
            "username",
            "user",
            "login",
            "password",
            "pass"
        ],
        isRedirected: true,
        replaceParamValue: true,
        detectStatusCodes: ["200"],
        dog: "dog-laugh",
        critLevel: 1
    },
    {
        title: "Server-Side Template Injection (SSTI)",
        description: "A simple SSTI payload was sent. The server's response indicates that the payload was executed, which may indicate a SSTI vulnerability.",
        postParams: [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}"
        ],
        detectResponses: ["49"],
        dog: "dog-panic",
        critLevel: 3
    }
]

