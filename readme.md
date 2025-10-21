# Ninja-Hacker-Dog
Ninja-Hacker-Dog is a Firefox extension that automates passive and active security checks while you browse. It helps you uncover exposed files, outdated services, misconfigurations, and known CVEs without leaving the browser.

## Installation
- **Mozilla Add-ons:** Install from [addons.mozilla.org](https://addons.mozilla.org/de/firefox/addon/ninja-hacker-dog/).
- **Temporary installation for development:**
  1. Open `about:debugging#/runtime/this-firefox`.
  2. Click **Load Temporary Add-on…**.
  3. Select `manifest.json` from this repository.

## Quick Start
1. Load the extension and open the Ninja-Hacker-Dog panel (`browser action` button).
2. Keep “Check while browsing” enabled to let the dog perform passive checks on every page you visit.
3. Toggle specific rule groups (leak detection, PoCs, fuzzing, active scanning) as needed.
4. Review findings per domain, filter them, or export them as JSON for handover.
5. Disable “Check while browsing” or close the panel to stop all scans immediately. Disabling only “Active Scanning” stops intrusive requests while keeping passive checks running.

## Feature Overview
- **Passive reconnaissance**
  - Detects exposed configuration, backup, and environment files (`.env`, SCM metadata, Terraform, Docker Compose, etc.).
  - Collects technology fingerprints and vulnerable version banners (WordPress, PHP, Exchange, Apache, Big-IP, etc.).
  - Flags suspicious responses and headers, such as SQL error signatures and session misconfigurations.
- **Active probing**
  - Sends targeted PoCs for supported CVEs (Confluence CVE-2022-26134, Bitbucket CVE-2022-36804, Exchange ProxyShell CVE-2021-34473, WebLogic CVE-2020-14882, and more).
  - Performs parameter fuzzing for XSS, SQL injection, command injection, SSTI, and prototype pollution.
  - Enumerates additional endpoints via GET/HEAD requests, port probes, and subdomain discovery rules.
- **Alert management**
  - Groups findings by domain with collapsible sections, live filtering, and JSON export.
  - Tracks current scan progress and request counters so you can monitor activity in real time.
  - Provides a “Skip current scan” button that cancels the running job without clearing passive state.
- **Proxy integration**
  - Optional outbound proxy with authentication, persistent storage, and one-click connectivity test.
  - Warns (rather than fails) when the proxy returns HTTP 4xx responses, including 403/407.
- **Safety controls**
  - Global kill-switch (`Check while browsing`) aborts all outstanding work, fetches, and timers instantly.
  - Separate toggle for active scanning lets you continue passive checks without aggressive probes.
  - Built-in throttling and deduplication avoid hammering the same endpoint repeatedly.

## Detection Catalogue
- Sensitive file exposure (`.env`, SCM directories, infrastructure manifests, lockfiles).
- Technology and version fingerprinting (WordPress, PHP, Apache, Exchange, Big-IP, etc.).
- Injection vectors (SQLi, XSS, command injection, SSTI, prototype pollution).
- Directory traversal, IDOR, and authentication misconfigurations.
- Proxy credential challenges and `.htaccess` protected directories (with UI notifications).
- Proof-of-Concept execution for:
  - Atlassian Confluence CVE-2022-26134
  - Atlassian Bitbucket CVE-2022-36804
  - Microsoft Exchange ProxyShell CVE-2021-34473
  - Apache HTTP Server CVE-2021-41773 (version detection)
  - Oracle WebLogic CVE-2020-14882
  - F5 BIG-IP RCE (version detection)
  - ManageEngine ADSelfService (detection heuristics)

## Rule Architecture
- `engine/detection.js` inspects responses and schedules rule sets based on detected tags.
- `rules/leak-urls.js` enumerates high-value files and directories.
- `rules/poc.js` holds PoCs for critical CVEs.
- `rules/versions.js` fingerprints software versions and compares them against vulnerable ranges.
- `rules/web.js` contains URL-driven web vulnerability checks.
- `rules/fuzzing.js` mutates GET/POST parameters for injection testing.
- `engine/fuzzing.js` and `engine/engine.js` orchestrate request timing, deduplication, and abort handling.

## Local Testing
Use well-known vulnerable targets to validate behaviour:

```bash
docker run --rm -p 8080:3000 bkimminich/juice-shop
docker run --rm -p 8080:80 adamdoupe/wackopicko
```

Visit `http://localhost:8080/` afterwards and watch Ninja-Hacker-Dog populate findings. For CVE-specific checks, projects such as [vulhub](https://github.com/vulhub/vulhub) provide ready-to-run lab environments.

## Packaging & Deployment
- **Zip build:** `zip -r Ninja-Hacker-Dog.zip . -x ".*" -x "images/.*"`
- **Windows sideloading:**
  1. Download or build the `.zip` archive.
  2. Rename it to `Ninja-Hacker-Dog.zip` if necessary.
  3. Open Firefox add-on settings → gear icon → **Install Add-on From File…**.
  4. Select the archive to install.

## Release Notes (highlights)
- **2.0** – Added proxy support, improved inline documentation, fixed details layout.
- **1.9** – Patched `.htaccess` detection and global deactivation, added custom “Woof” sound.
- **1.8** – Added vulnerability detail views, `.htaccess` rules, and new checks.

## License & Credits
- Source code: Mozilla Public License 2.0.
- Artwork (dog images), name, and branding remain © Bauvater, 2025.
- Inspired by and based on the original [Ninja Hacker Cat](https://github.com/Leetcore/ninja-hacker-cat) by 1337core.
