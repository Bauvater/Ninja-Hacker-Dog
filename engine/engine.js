import { detection } from "./detection.js"
import { request, setCurrentlyScanning } from "./helper.js"

// this engine will make requests based on the current url
export async function engine(rules, detectedTags, url, options = {}) {
	let parsedUrl = new URL(url)
	let rootUrl = parsedUrl.protocol + "//" + parsedUrl.hostname
	if (parsedUrl.port.length > 0) {
		rootUrl = parsedUrl.protocol + "//" + parsedUrl.hostname + ":" + parsedUrl.port
	}

	for (let rule of rules) {
		if (options.signal?.aborted) { break }
		
		// Check whether the tags match
		if (!checkIfRuleTagMatches(rule.tags, detectedTags)) {
			continue
		}

		// Path-based detection
		if (rule.paths) {
			console.log("Start detection based on GET paths")
			for (let path of rule.paths) {
				if (options.signal?.aborted) { break; }
				if (url[url.length - 1] === "/") {
					url = url.substring(0, url.length - 1)
				}

				let requestUrl = url + path
				setCurrentlyScanning(`Scanning:\n${requestUrl}`)

				let result = await request(
					requestUrl,
					null,
					rule.method,
					rule.postBody,
					rule.postJSON,
					[],
					options
				)

				if (result) {
					detection(requestUrl, rule, result.response, result.body, path, result.request)
				}
			}

		// Root URL-based detection
		} else if (rule.rootPaths) {
			console.log("Start detection based on root url")
			for (let rootPath of rule.rootPaths) {
				if (options.signal?.aborted) { break; }
				let requestUrl = rootUrl + rootPath
				setCurrentlyScanning(`Scanning:\n${requestUrl}`)
				console.log(requestUrl)

				let result = await request(
					requestUrl,
					rule.headers,
					rule.method,
					rule.postBody,
					rule.postJSON,
					[],
					options
				)

				if (result) {
					detection(requestUrl, rule, result.response, result.body, rootPath, result.request)
				}
			}

		// Parameter-based detection
		} else if (rule.params) {
			console.log("Start detection of GET parameters")
			let split_url = url.split("?")
			if (split_url.length === 0) {
				console.warn("Url has no ? sign.")
				continue
			}

			for (let rule_param of rule.params) {
				let urlParams = new URLSearchParams(split_url[1])
				let paramCount = Array.from(urlParams).length

				for (let index = 0; index < paramCount; index++) {
					if (options.signal?.aborted) { break; }
					let key = Array.from(urlParams)[index][0]
					urlParams = new URLSearchParams(split_url[1])

					if (rule.replaceParamValue) {
						urlParams.set(key, rule_param)
					} else {
						let current_param = urlParams.get(key)
						urlParams.set(key, current_param + rule_param)
					}

					let requestUrl = split_url[0] + "?" + urlParams.toString()
					setCurrentlyScanning(`Scanning:\n${requestUrl}`)

					let result = await request(
						requestUrl,
						rule.headers,
						rule.method,
						rule.postBody,
						rule.postJSON,
						[],
						options
					)
					if (result) {
						detection(requestUrl, rule, result.response, result.body, rule_param, result.request)
					}
				}
			}

		// Port-based detection
		} else if (rule.ports) {
			console.log("Start detection of ports")
			let url_parsed = new URL(url)
			for (let port of rule.ports) {
				if (options.signal?.aborted) { break; }
				let protocol = port.includes("80") ? "http://" : "https://"
				try {
					let requestUrl = protocol + url_parsed.hostname + ":" + port
					setCurrentlyScanning(`Scanning:\n${requestUrl}`)

					let result = await request(
						requestUrl,
						null,
						"HEAD",
						null,
						null,
						["nowait"],
						options
					)

					if (result) {
						detection(requestUrl, rule, result.response, "", port, result.request)
					}
				} catch (e) {
					console.warn(e)
				}
			}

		// Subdomain-based detection
		} else if (rule.subdomains) {
			console.log("Start detection of subdomains")
			let url_parsed = new URL(url)
			for (let subdomain of rule.subdomains) {
				if (options.signal?.aborted) { break; }
				try {
					let requestUrl = "http://" + subdomain + "." + url_parsed.hostname
					setCurrentlyScanning(`Scanning:\n${requestUrl}`)

					let result = await request(
						requestUrl,
						null,
						"HEAD",
						null,
						null,
						["nowait"],
						options
					)

					if (result) {
						detection(requestUrl, rule, result.response, "", subdomain, result.request)
					}
				} catch (e) {
					console.warn(e)
				}
			}

		// Tag-based detection
		} else {
			let requestUrl = url
			setCurrentlyScanning(`Scanning:\n${requestUrl}`)

			let result = await request(
				requestUrl,
				rule.headers,
				rule.method,
				rule.postBody,
				rule.postJSON,
				[],
				options
			)
			if (result) {
				detection(requestUrl, rule, result.response, result.body, rule.detectedBy, result.request)
			}
		}
	}
}


function checkIfRuleTagMatches(tags, detectedTags) {
	return tags.find(tag => {
		for (let detectedTag of detectedTags) {
			if (tag == detectedTag) {
				return true;
			}
		}
		// Rule applies to all tags
		if (tag == "all") {
			return true;
		}
		return false;
	});
}
