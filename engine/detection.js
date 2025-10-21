class Message {
	constructor(url, title, detectedBy, size, avatar, critLevel, request, response, description) {
		this.url = url
		this.title = title
		this.detectedBy = detectedBy
		this.size = size
		this.avatar = avatar
		this.critLevel = critLevel || 0
        this.request = request
        this.response = response
        this.description = description
		this.render()
	}

    render() {
        const domainContainer = document.querySelector("#domain-container");
        const domain = new URL(this.url).hostname;
        let domainWrapper = document.getElementById(domain);
        if (!domainWrapper) {
            domainWrapper = document.createElement('div');
            domainWrapper.id = domain;
            domainWrapper.className = 'domain-wrapper';

            const domainHeader = document.createElement('h2');
            domainHeader.className = 'domain-header';
            domainHeader.textContent = domain;
            domainWrapper.appendChild(domainHeader);

            const domainMessages = document.createElement('div');
            domainMessages.className = 'domain-messages';
            domainWrapper.appendChild(domainMessages);

            domainContainer.appendChild(domainWrapper);
        }

        const domainMessages = domainWrapper.querySelector('.domain-messages');

        // check if message is there already
        for (let message of domainMessages.querySelectorAll(".message")) {
            if (message.querySelector(".title")?.textContent == this.title &&
                message.querySelector(".url")?.textContent == this.url &&
                message.querySelector(".size_number")?.textContent == this.size &&
                message.querySelector(".detectedBy")?.textContent == this.detectedBy) {
                return;
            }
        }

        const messageElement = document.createElement('div');
        messageElement.className = 'message';
        messageElement.dataset.critLevel = this.critLevel;
        messageElement.dataset.title = this.title;
        messageElement.dataset.url = this.url;
        messageElement.dataset.detectedBy = this.detectedBy || '';
        messageElement.dataset.size = String(this.size);
        if (this.description) {
            messageElement.dataset.description = this.description;
        }

        const deleteButton = document.createElement('button');
        deleteButton.className = 'delete-message';
        deleteButton.textContent = 'X';
        messageElement.appendChild(deleteButton);

        const titleElement = document.createElement('span');
        titleElement.className = 'title';
        titleElement.textContent = this.title;
        messageElement.appendChild(titleElement);

        messageElement.appendChild(document.createElement('br'));

        const urlElement = document.createElement('a');
        urlElement.className = 'url';
        urlElement.target = '_blank';
        urlElement.href = this.url;
        urlElement.textContent = this.url;
        messageElement.appendChild(urlElement);

        const sizeElement = document.createElement('span');
        sizeElement.className = 'size';
        sizeElement.textContent = 'Size: ';
        const sizeNumber = document.createElement('span');
        sizeNumber.className = 'size_number';
        sizeNumber.textContent = this.size;
        sizeElement.appendChild(sizeNumber);
        messageElement.appendChild(sizeElement);

        messageElement.appendChild(document.createElement('br'));

        const detectedByElement = document.createElement('span');
        detectedByElement.className = 'detect';
        const detectedByText = document.createTextNode('Detected by: ');
        const detectedByValue = document.createElement('span');
        detectedByValue.className = 'method detectedBy';
        detectedByValue.textContent = this.detectedBy;
        detectedByElement.appendChild(detectedByText);
        detectedByElement.appendChild(detectedByValue);
        messageElement.appendChild(detectedByElement);

        const detailsButton = document.createElement('button');
        detailsButton.className = 'details-button';
        detailsButton.textContent = 'Details';
        messageElement.appendChild(detailsButton);

        const detailsContent = document.createElement('div');
        detailsContent.className = 'details-content hidden';
        const preElement = document.createElement('pre');
        preElement.textContent = this.formatDetails();
        detailsContent.appendChild(preElement);
        messageElement.appendChild(detailsContent);

        domainMessages.appendChild(messageElement);
        const messages = Array.from(domainMessages.querySelectorAll('.message'));
        messages.sort((a, b) => {
            const critA = parseInt(a.dataset.critLevel, 10) || 0;
            const critB = parseInt(b.dataset.critLevel, 10) || 0;
            return critB - critA;
        });
        while (domainMessages.firstChild) {
            domainMessages.removeChild(domainMessages.firstChild);
        }
        messages.forEach(msg => domainMessages.appendChild(msg));

		if (this.critLevel > 0) {
			document.querySelector('#sound').src = "sounds/woof.mp3"
			document.querySelector('#sound').play()
		}


		// change the dog -> only show the highest critLevel
		if (this.avatar && this.critLevel >= window.nhc_currentCritLevel) {
			window.nhc_currentCritLevel = this.critLevel
			document.querySelectorAll('.avatar').forEach(avatar => {
				avatar.style.display = 'none';
			})
			if (document.querySelector(`#${this.avatar}`)) {
				document.querySelector(`#${this.avatar}`).style.display = 'block'
			}
		}

		if (this.critLevel > 0) {
			browser.notifications.create(
				{
					type: 'basic',
					title: 'Woof!',
					message: `${this.title} (${this.detectedBy})`,
				}
			)
		}

        if (typeof window.updateAlertToolsVisibility === 'function') {
            window.updateAlertToolsVisibility();
        } else {
            const alertTools = document.querySelector('#alert-tools');
            if (alertTools) {
                alertTools.classList.remove('hidden');
            }
            document.querySelector('#reset')?.classList.remove('hidden');
        }
	}

    formatDetails() {
        let details = "";
        if (this.description) {
            details += `Description:\n${this.description}\n\n`;
        }
        details += "Request:\n";
        if (this.request) {
            details += `${this.request.method || 'GET'} ${this.url}\n`;
            if (this.request.headers) {
                for (const [key, value] of Object.entries(this.request.headers)) {
                    details += `${key}: ${value}\n`;
                }
            }
            if (this.request.body) {
                details += `\n${this.request.body}\n`;
            }
        } else {
            details += `GET ${this.url}\n`;
        }

        details += "\nResponse:\n";
        if (this.response) {
            details += `Status: ${this.response.status}\n`;
            for (const [key, value] of this.response.headers.entries()) {
                details += `${key}: ${value}\n`;
            }
        }

        return details;
    }
}

export function detection(request_url, rule, response, body = "", detectedBy = "", request = null) {
	let status_code = response.status

	if (status_code === 404) {
		return;
	}

	let status_filtered = (rule.filterStatusCodes || [])
		.find(statusCode => statusCode === status_code.toString())
	let status_matched = (rule.detectStatusCodes || [])
		.find(statusCode => statusCode === status_code.toString())

	// detection: match status code or skip if no one is set
	if (status_filtered || !rule.filterStatusCodes) {
		// detect substring in response body
		for (let detect of (rule.detectResponses || [])) {
			// simple response detection with strings
			if (body.toLowerCase().indexOf(detect.toLowerCase()) >= 0) {
				if (rule.minSize && body.length < rule.minSize) {
					continue
				}
				if (rule.maxSize && body.length > rule.maxSize) {
					continue
				}
				new Message(
					request_url,
					rule.title,
					detectedBy,
					body.length,
					rule.dog,
					rule.critLevel,
                    request,
                    response,
                    rule.description
				)
				break
			}
		}

		// detect version with regex
		if (rule.regexVersion) {
			let regex = new RegExp(rule.regexVersion)
			let detectMatch = null
			if (rule.matchRegexHeaderName) {
				let header = response.headers.get(rule.matchRegexHeaderName)
				detectMatch = header.match(regex)
			} else {
				detectMatch = body.match(regex)
			}

			if (detectMatch && detectMatch.length > 0) {
				let version = detectMatch[1]
				if (checkIfVersionNumbersMatches(version, rule.minVersion, rule.maxVersion)) {
					new Message(
						request_url,
						rule.title,
						detectedBy,
						body.length,
						rule.dog,
						rule.critLevel,
                        null,
                        null,
                        rule.description
					)
				}
			}
		}

		// detect if a specific response header is there
		for (let detect of (rule.detectHeaders || [])) {
			if (response.headers.get(detect)) {
				new Message(
					request_url,
					rule.title,
					detectedBy,
					body.length,
					rule.dog,
					rule.critLevel,
                    null,
                    null,
                    rule.description
				)
				break
			}
		}

        if (rule.detectHeaderValues && rule.detectHeaderValues.length) {
            const requireAll = !!rule.requireAllHeaderValues;
            let matchedCount = 0;

            for (const detect of rule.detectHeaderValues) {
                if (!detect || !detect.header) {
                    continue;
                }
                const headerValue = response.headers.get(detect.header);
                if (!headerValue) {
                    if (requireAll) {
                        matchedCount = -1;
                        break;
                    }
                    continue;
                }

                const normalized = headerValue.trim();
                let matched = false;

                if (Object.prototype.hasOwnProperty.call(detect, "equals")) {
                    matched = normalized.toLowerCase() === String(detect.equals).toLowerCase();
                }
                if (!matched && detect.contains) {
                    matched = normalized.toLowerCase().includes(String(detect.contains).toLowerCase());
                }
                if (!matched && detect.pattern) {
                    try {
                        const regex = new RegExp(detect.pattern, detect.flags || "");
                        matched = regex.test(headerValue);
                    } catch (err) {
                        console.warn("Invalid detectHeaderValues pattern", err);
                    }
                }

                if (matched) {
                    matchedCount += 1;
                    if (!requireAll) {
                        new Message(
                            request_url,
                            rule.title,
                            detectedBy,
                            body.length,
                            rule.dog,
                            rule.critLevel,
                            null,
                            null,
                            rule.description
                        );
                        break;
                    }
                } else if (requireAll) {
                    matchedCount = -1;
                    break;
                }
            }

            if (requireAll && matchedCount === rule.detectHeaderValues.length) {
                new Message(
                    request_url,
                    rule.title,
                    detectedBy,
                    body.length,
                    rule.dog,
                    rule.critLevel,
                    null,
                    null,
                    rule.description
                );
            }
        }

        // detect if a specific response header is missing
        for (let missing of (rule.missingHeaders || [])) {
            if (!response.headers.has(missing)) {
                new Message(
                    request_url,
                    rule.title,
                    detectedBy,
                    body.length,
                    rule.dog,
                    rule.critLevel,
                    null,
                    null,
                    rule.description
                )
                break
            }
        }

        // detect if a specific cookie flag is missing
        if (rule.missingCookieFlags) {
            const cookies = response.headers.get('set-cookie');
            if (cookies) {
                for (const flag of rule.missingCookieFlags) {
                    if (!cookies.toLowerCase().includes(flag.toLowerCase())) {
                        new Message(
                            request_url,
                            rule.title,
                            detectedBy,
                            body.length,
                            rule.dog,
                            rule.critLevel,
                            null,
                            null,
                            rule.description
                        )
                        break
                    }
                }
            }
        }
	}

	if (status_matched && !status_filtered) {
		// check if redirect is a must have
		if (rule.isRedirected && !response.redirected) {
			return;
		}

		if (rule.skipRedirected && response.redirected) {
			return;
		}

		// detection based only on response status code
		for (let status of rule.detectStatusCodes) {
			if (status_matched == status) {
				new Message(
					request_url,
					rule.title,
					detectedBy,
					body.length,
					rule.dog,
					rule.critLevel,
                    null,
                    null,
                    rule.description
				)
				break
			}
		}
	}
}

function checkIfVersionNumbersMatches(version, minVersion, maxVersion) {
	let normalizedVersionString = version.split(".")
		.map(num => num.padStart(8, "0"))
		.join(".")
	let normalizedMinVersionString = minVersion.split(".")
		.map(num => num.padStart(8, "0"))
		.join(".")
	let normalizedMaxVersionString = maxVersion.split(".")
		.map(num => num.padStart(8, "0"))
		.join(".")

	return normalizedMinVersionString <= normalizedVersionString
		&& normalizedMaxVersionString >= normalizedVersionString;
}
