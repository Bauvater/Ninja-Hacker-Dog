export const htaccess = [
    {
        title: "HTAccess Protected Page",
        description: "A .htaccess protected page was found. This is not a vulnerability, but it is useful information for an attacker.",
        detectStatusCodes: ["401"],
        detectHeaders: ["WWW-Authenticate: Basic"],
        tags: ["all"],
        dog: "dog-default",
        critLevel: 0
    }
];