module.exports = {
	settings: {
		clientKey: '12345678901234567890123456789012',

		connectionTimeout: 20,
		firstAttemptWaitingInterval: 5,
		normalWaitingInterval: 2,
		isVerbose: true,
		taskId: 0,
	},

	setAPIKey(key) {
		this.settings.clientKey = key;
	},

	shutUp() {
		this.settings.isVerbose = false;
	},

	getBalance() {
		return new Promise((resolve, reject) => {
			this.JSONRequest('getBalance', {
				clientKey: this.settings.clientKey,
			})
				.then((res) => resolve(res.balance))
				.catch((err) => reject(err));
		});
	},

	solveImage(body) {
		return new Promise((resolve, reject) => {
			this.JSONRequest('createTask', {
				clientKey: this.settings.clientKey,
				task: {
					type: 'ImageToTextTask',
					body: body,
				},
			})
				.then((res) => {
					this.settings.taskId = res.taskId;
					return this.waitForResult(res.taskId);
				})
				.then((solution) => resolve(solution.text))
				.catch((err) => reject(err));
		});
	},

	solveRecaptchaV2Proxyless(websiteURL, websiteKey, isInvisible = false) {
		return new Promise((resolve, reject) => {
			let task = {
				type: 'RecaptchaV2TaskProxyless',
				websiteURL: websiteURL,
				websiteKey: websiteKey,
			};
			if (isInvisible === true) {
				task['isInvisible'] = true;
			}
			this.JSONRequest('createTask', {
				clientKey: this.settings.clientKey,
				task: task,
			})
				.then((res) => {
					this.settings.taskId = res.taskId;
					return this.waitForResult(res.taskId);
				})
				.then((solution) => {
					resolve(solution.gRecaptchaResponse);
				})
				.catch((err) => reject(err));
		});
	},

	solveRecaptchaV3Proxyless(websiteURL, websiteKey, minScore, pageAction = '', isEnterprise = false) {
		return new Promise((resolve, reject) => {
			let task = {
				type: 'RecaptchaV3TaskProxyless',
				websiteURL: websiteURL,
				websiteKey: websiteKey,
				minScore: minScore,
				pageAction: pageAction,
			};
			if (pageAction === true) {
				task['pageAction'] = true;
			}

			if (isEnterprise === true) {
				task['isEnterprise'] = true;
			}

			this.JSONRequest('createTask', {
				clientKey: this.settings.clientKey,
				task: task,
			})
				.then((res) => {
					this.settings.taskId = res.taskId;
					return this.waitForResult(res.taskId);
				})
				.then((solution) => {
					resolve(solution.gRecaptchaResponse);
				})
				.catch((err) => reject(err));
		});
	},

	solveHCaptchaProxyless(websiteURL, websiteKey) {
		let task = {
			type: 'HCaptchaTaskProxyless',
			websiteURL: websiteURL,
			websiteKey: websiteKey,
		};

		return new Promise((resolve, reject) => {
			this.JSONRequest('createTask', {
				clientKey: this.settings.clientKey,
				task: task,
			})
				.then((res) => {
					this.settings.taskId = res.taskId;
					return this.waitForResult(res.taskId);
				})
				.then((solution) => {
					resolve(solution.gRecaptchaResponse);
				})
				.catch((err) => reject(err));
		});
	},

	solveFunCaptchaProxyless(websiteURL, websiteKey) {
		return new Promise((resolve, reject) => {
			this.JSONRequest('createTask', {
				clientKey: this.settings.clientKey,
				task: {
					type: 'FunCaptchaTaskProxyless',
					websiteURL: websiteURL,
					websitePublicKey: websiteKey,
				},
			})
				.then((res) => {
					this.settings.taskId = res.taskId;
					return this.waitForResult(res.taskId);
				})
				.then((solution) => {
					resolve(solution.token);
				})
				.catch((err) => reject(err));
		});
	},

	waitForResult(taskId) {
		return new Promise((resolve, reject) => {
			(async () => {
				if (this.settings.isVerbose) console.log('created task with ID ' + taskId);
				if (this.settings.isVerbose)
					console.log('waiting ' + this.settings.firstAttemptWaitingInterval + ' seconds');
				await this.delay(this.settings.firstAttemptWaitingInterval * 1000);

				while (taskId > 0) {
					await this.JSONRequest('getTaskResult', {
						clientKey: this.settings.clientKey,
						taskId: taskId,
					})
						.then((response) => {
							if (response.status === 'ready') {
								taskId = 0;
								resolve(response.solution);
							}
							if (response.status === 'processing') {
								if (this.settings.isVerbose) console.log('captcha result is not yet ready');
							}
						})
						.catch((error) => {
							taskId = 0;
							reject(error);
						});

					if (this.settings.isVerbose)
						console.log('waiting ' + this.settings.normalWaitingInterval + ' seconds');
					await this.delay(this.settings.normalWaitingInterval * 1000);
				}
			})();
		});
	},

	JSONRequest(methodName, payLoad) {
		return new Promise((resolve, reject) => {
			if (typeof process !== 'object' || typeof require !== 'function') {
				const message = 'Application should be run either in NodeJs or a WebBrowser environment';
				console.error(message);
				reject(message);
			}

			const axios = require('axios');
			axios
				.post('https://api.anycaptcha.com/' + methodName, payLoad, {
					timeout: this.connectionTimeout * 1000,
					headers: {
						'content-type': 'application/json; charset=utf-8',
						accept: 'application/json',
					},
				})
				.then((res) => {
					return this.checkForErrors(res.data);
				})
				.then((data) => {
					resolve(data);
				})
				.catch((error) => reject(error));
		});
	},

	checkForErrors(response) {
		return new Promise((resolve, reject) => {
			if (typeof response.errorId === 'undefined') {
				reject('Incorrect API response, something is wrong');
				return;
			}
			if (typeof response.errorId !== 'number') {
				reject('Unknown API error code ' + response.errorId);
				return;
			}
			if (response.errorId > 0) {
				reject(response.errorCode);
				return;
			}
			resolve(response);
		});
	},

	delay(time) {
		return new Promise(function (resolve) {
			setTimeout(resolve, time);
		});
	},
};
