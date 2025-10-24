export const wafRules = [
    {
        title: "WAF/CDN: Cloudflare detected",
        description: "Response headers indicate that Cloudflare is positioned in front of the target, which may add rate limiting or traffic filtering.",
        detectHeaderValues: [
            { header: "Server", pattern: "^cloudflare", flags: "i" },
            { header: "CF-RAY", pattern: ".+", flags: "i" }
        ],
        requireAllHeaderValues: true,
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 0
    },
    {
        title: "WAF/CDN: AWS CloudFront detected",
        description: "Headers such as Via and X-Amz-Cf-Pop indicate Amazon CloudFront or AWS WAF is protecting this origin.",
        detectHeaderValues: [
            { header: "Server", pattern: "cloudfront", flags: "i" },
            { header: "Via", pattern: "cloudfront", flags: "i" },
            { header: "X-Amz-Cf-Pop", pattern: ".+", flags: "i" }
        ],
        requireAllHeaderValues: true,
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 0
    },
    {
        title: "WAF/CDN: Akamai detected",
        description: "Akamai-specific headers suggest the target is served through Akamai CDN/WAF.",
        detectHeaderValues: [
            { header: "Server", pattern: "akamai", flags: "i" },
            { header: "X-Akamai-Request-ID", pattern: ".+", flags: "i" }
        ],
        requireAllHeaderValues: true,
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 0
    },
    {
        title: "WAF/CDN: Fastly detected",
        description: "Fastly cache headers are present, indicating response delivery via Fastly.",
        detectHeaderValues: [
            { header: "X-Served-By", pattern: "fastly", flags: "i" },
            { header: "X-Cache", pattern: "fastly", flags: "i" }
        ],
        requireAllHeaderValues: true,
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 0
    },
    {
        title: "WAF: Imperva (Incapsula) detected",
        description: "Incapsula / Imperva gateway headers were returned, suggesting additional request inspection.",
        detectHeaderValues: [
            { header: "X-CDN", pattern: "incapsula", flags: "i" },
            { header: "X-Iinfo", pattern: ".+", flags: "i" }
        ],
        requireAllHeaderValues: true,
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 0
    },
    {
        title: "WAF/CDN: Azure Front Door detected",
        description: "Azure Front Door headers signal Microsoft’s edge network in front of the origin.",
        detectHeaderValues: [
            { header: "X-Azure-Ref", pattern: ".+", flags: "i" },
            { header: "X-Cache", pattern: "azureedge", flags: "i" }
        ],
        requireAllHeaderValues: true,
        tags: ["all"],
        dog: "dog-laugh",
        critLevel: 0
    }
];

