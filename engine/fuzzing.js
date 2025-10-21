import { detection } from "./detection.js"
import { countRequests } from "./helper.js"

// this fuzzing engine is based on captured webrequests
export async function fuzzing_engine(rules, requestDetails, options = {}) {
	console.log("Start detection POST fuzzing")
	for (let rule of rules) {
        if (options.signal?.aborted) { break; }

        if (rule.params) {
            let split_url = requestDetails.url.split("?")
            if (split_url.length > 1) {
                for (let rule_param of rule.params) {
                    if (options.signal?.aborted) { break; }
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

                        let response = await fetch(requestUrl, {
                            method: 'GET',
                            headers: {
                                "X-Requested-With": "Ninja Hacker Dog"
                            },
                            signal: options.signal
                        })
                        let body = await response.text()
                        countRequests()

                        let request = {
                            method: 'GET',
                            headers: {
                                "X-Requested-With": "Ninja Hacker Dog"
                            }
                        }
                        detection(
                            requestUrl,
                            rule,
                            response,
                            body,
                            rule_param,
                            request
                        )
                    }
                }
            }
        }

		// if postParamKeywords is set, only fuzz params that match
		if (rule.postParamKeywords) {
			let foundKeyword = false;
			for (const paramName in requestDetails?.requestBody?.formData) {
				if (rule.postParamKeywords.some(keyword => paramName.toLowerCase().includes(keyword))) {
					foundKeyword = true;
					break;
				}
			}
			if (!foundKeyword) {
				continue;
			}
		} else if (rule.filterPostParams) { // there is a filter param set, skip rules for this params
			let filterThisParam = true
			for (let filterPostParam of (rule.filterPostParams || [])) {
				if (requestDetails.requestBody
					&& requestDetails.requestBody.formData
					&& requestDetails.requestBody.formData[filterPostParam]) {
					filterThisParam = false
					break
				}
			}
			if (filterThisParam) {
				continue
			}
		}

		for (let param of rule.postParams) {
            if (options.signal?.aborted) { break; }
			let formData = requestDetails?.requestBody?.formData
			let paramCount = Object.keys(formData).length

			// there is no form data to change
			if (!paramCount) {
				continue
			}

			// iterate the params and change the param at the index
			for (let index = 0; index < paramCount; index++) {
                if (options.signal?.aborted) { break; }
				let usedParam = ""
				let copyFormData = {}
				Object.assign(copyFormData, formData)

				// check if param is excluded
				if (rule.excludePostParams && rule.excludePostParams.includes(Object.keys(formData)[index])) {
					continue
				}

				// count parameter we captured in the request
				if (rule.replaceParamValue) {
					copyFormData[Object.keys(formData)[index]] = param
					usedParam = Object.keys(formData)[index] + "=" + param
				} else {
					copyFormData[Object.keys(formData)[index]] = Object.values(copyFormData)[index] + param
					usedParam = Object.keys(formData)[index] + "=" + Object.values(copyFormData)[index]
				}

				// run request
				let sendData = new URLSearchParams()
				for (let key in copyFormData) {
					sendData.append(key, copyFormData[key])
				}
				
				// TODO: use request instead
				let response = await fetch(requestDetails.url, {
					method: 'POST',
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						"X-Requested-With": "Ninja Hacker Dog"
					},
					body: sendData.toString(),
                    signal: options.signal
				})
				let body = await response.text()
				countRequests()

				let request = {
                    method: 'POST',
                    body: sendData.toString(),
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Requested-With": "Ninja Hacker Dog"
                    }
                }
                detection(
					requestDetails.url,
					rule,
					response,
					body,
					usedParam,
                    request
				)
			}
		}
	}

	for (let rule of rules) {
		// there is a filter param set
		// skip rules for this params
		if (rule.filterPostParams) {
			let filterThisParam = true
			for (let filterPostParam of (rule.filterPostParams || [])) {
				if (requestDetails.requestBody
					&& requestDetails.requestBodyJSON
					&& requestDetails.requestBodyJSON[filterPostParam]) {
					filterThisParam = false
					break
				}
			}
			if (filterThisParam) {
				continue
			}
		}
		
		for (let param of rule.postParams) {
            if (options.signal?.aborted) { break; }
			let postJSON = requestDetails.requestBodyJSON
			if (!postJSON) {
				continue;
			}
			let paramCount = Object.keys(postJSON).length

			// count parameter we captured in the request
			for (let index = 0; index < paramCount; index++) {
                if (options.signal?.aborted) { break; }
				let usedParam = ""
				let copyJSON = {}
				Object.assign(copyJSON, postJSON)

				// check if param is excluded
				if (rule.excludePostParams && rule.excludePostParams.includes(Object.keys(postJSON)[index])) {
					continue
				}

				// replace / add our rule to the property at a given index
				if (rule.replaceParamValue) {
					copyJSON[Object.keys(copyJSON)[index]] = param
					usedParam = Object.keys(copyJSON)[index] + "=" + param
				} else {
					copyJSON[Object.keys(copyJSON)[index]] = Object.values(copyJSON)[index] + param
					usedParam = Object.keys(copyJSON)[index] + "=" + Object.values(copyJSON)[index]
				}

				// TODO: use request instead
				let response = await fetch(requestDetails.url, {
					method: 'POST',
					headers: {
						"Content-Type": "application/json",
						"X-Requested-With": "Ninja Hacker Dog"
					},
					body: JSON.stringify(copyJSON),
                    signal: options.signal
				})
				let body = await response.text()

                let request = {
                    method: 'POST',
                    body: JSON.stringify(copyJSON),
                    headers: {
                        "Content-Type": "application/json",
                        "X-Requested-With": "Ninja Hacker Dog"
                    }
                }
				detection(
					requestDetails.url,
					rule,
					response,
					body,
					usedParam,
                    request
				)
			}
		}
	}

	for (let rule of rules) {
		if (!rule.tags.includes("header-fuzz")) {
			continue
		}

		for (let param of rule.params) {
            if (options.signal?.aborted) { break; }
			let headers = {}
			headers[rule.header] = param
			headers["X-Requested-With"] = "Ninja Hacker Dog"
			let response = await fetch(requestDetails.url, {
				method: 'GET',
				headers: headers,
                signal: options.signal
			})
			let body = await response.text()
			countRequests()

            let request = {
                method: 'GET',
                headers: headers
            }
			detection(
				requestDetails.url,
				rule,
				response,
				body,
				`${rule.header}: ${param}`,
                request
			)
		}
	}
}
