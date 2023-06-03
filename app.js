const fs = require('fs');
const { once } = require('events');
const WebSocket = require('ws');
const AnyCaptchaClient = require('./anycaptcha.js');
const AntiCaptchaClient = require('@antiadmin/anticaptchaofficial');
const TwoCaptchaClient = require('@infosimples/node_two_captcha');
const Discord = require('discord.js');
const cookiefile = require('cookiefile');
const axios = require('axios');
const axiosRetry = require('axios-retry');
const http = require('http');
const https = require('https');
const HttpsProxyAgent = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const express = require('express');
const ansiToHtml = require('ansi-to-html');
const favicon = require('serve-favicon');
const FormData = require('form-data');
const Promise = require('promise');
const puppeteer = require('puppeteer-extra');
const ProxyPlugin = require('puppeteer-extra-plugin-proxy');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const multer = require('multer');
const path = require('path');


const httpAgent = new http.Agent({ keepAlive: true });
const httpsAgent = new https.Agent({ keepAlive: true });

const logStream = fs.createWriteStream('./keydropbot.log', { flags: 'a' });

const ansiConverter = new ansiToHtml({ newline: true });

let discordGoldClient = new Discord.Client({
	intents: ['GUILDS', 'GUILD_MESSAGE_TYPING', 'GUILD_MESSAGES', 'GUILD_WEBHOOKS', 'GUILD_MEMBERS'],
});

let discordClient = new Discord.Client({
	intents: ['GUILDS', 'GUILD_MESSAGE_TYPING', 'GUILD_MESSAGES'],
});

let wsBattles;
let wsBattlesConnected;

let config;

let cookies;

let browser;
const upload = multer();

let steamId;
let keyDropToken, keyDropUsername, keyDropGold, keyDropBattleTickets;
let keyDropGoldCase = [];

let earnedGold = 0
let earnedCash = 0;

let intValUserInfoRefresh,
	intValTokenRefresh,
	intValProcBattles,
	intValProcBattlesResults,
	intValProcGiveAways,
	intValProcGiveAwaysResults,
	intValProcDailyCase,
	intValGoldMessages;

let dailyCoolDown = 0;

let goldcodemgr, battlesmgr, giveawaysmgr;

let today;

let publishChannel;

const quit = async () => {
	if (typeof logStream !== 'undefined') {
		logStream.end();
		await once(logStream, 'finish');

		process.exit(1);
	}
	else {
		process.exit(1);
	}
};

const getDate = () => {
	return getDay() + ' ' + getTime();
};

const getDay = () => {
	let date_time = new Date();

	let date = ('0' + date_time.getDate()).slice(-2);
	let month = ('0' + (date_time.getMonth() + 1)).slice(-2);
	let year = date_time.getFullYear();

	return year + '-' + month + '-' + date;
};

const getTime = () => {
	let date_time = new Date();

	let hours = String(date_time.getHours()).padStart(2, '0');
	let minutes = String(date_time.getMinutes()).padStart(2, '0');
	let seconds = String(date_time.getSeconds()).padStart(2, '0');

	return hours + ':' + minutes + ':' + seconds;
};

const onlyPositive = (intNum) => {
	if (intNum < 0)
		return 0;
	else
		return intNum;
};

const logger = (category, text, color = '') => {
	let day = getDay();
	let time = getTime();
	let output = '';
	let outputDiscord = '';

	if (day !== today) {
		today = day;
		const todayStr = `\x1b[100m${today}\x1b[0m`;

		console.log(todayStr);
		logStream.write(todayStr + '\r');
	}

	if (color !== '') output = `\x1b[${color}m${time} [${category}] ${text}\x1b[0m`;
	else output = `${time} [${category}] ${text}`;

	console.log(output);
	logStream.write(output + '\r');

	if (typeof publishChannel !== 'undefined' && color === '32') {
		try {
			let categoryIcon = '';
			let richFormat = false;


			if (category === 'GoldenCode' || category === 'GoldenCodeHistory') {
				categoryIcon = '〔:coin:〕';
				//outputDiscord += '```arm\n';
				//richFormat = true;
			}
			else if (category === 'GiveAways' || category === 'GiveAwaysResults' ) {
				categoryIcon = '〔:gift:〕';
				//outputDiscord += '```diff\n';
				//richFormat = true;
			}
			else if (category === 'Battles' || category === 'BattlesResults' ) {
				categoryIcon = '〔:crossed_swords:〕';
				//outputDiscord += '```fix\n';
				//richFormat = true;
			}
			else if (category === 'DailyCase') {
				categoryIcon = '〔:slot_machine:〕';
				//outputDiscord += '```asciidoc\n';
				//richFormat = true;
			}
			else if (category === 'GoldCase') {
				categoryIcon = '〔:moneybag:〕';
				//outputDiscord += '```asciidoc\n';
				//richFormat = true;
			}


			if (typeof config.discord_bot_mention_user_id !== 'undefined' && config.discord_bot_mention_user_id !== '')
				outputDiscord += '<@' + config.discord_bot_mention_user_id + '> ';

			outputDiscord += ((categoryIcon != '') ? categoryIcon : category+': ') + '**' + text + '** [' + keyDropUsername + ']';

			if (richFormat === true) {
				outputDiscord += '\n```';
			}

			publishChannel.send(outputDiscord);
		} catch {
			console.log(`\x1b[31m${time} [Discord] no perms on publish channel or send failed\x1b[0m`);
			logStream.write(`\x1b[31m${time} [Discord] no perms on publish channel or send failed\x1b[0m` + '\r');
		}
	}
};

const capitalize = (string) => {
	return String(string[0]).toUpperCase() + String(string).slice(1);
};


const stringifyOnce = (obj) => {
	if (typeof obj === 'string') {
		return obj;
	}

	return JSON.stringify(obj);
};

const wsClose = (wsObj) => {
	if (typeof wsObj !== 'undefined') {
		if (typeof wsObj.readyState !== 'undefined' && wsObj.readyState === WebSocket.OPEN) {
			wsObj.close();
		}
	}
};

const time2Seconds = (time, ms = false) => {
	let timeArr = time.split(':');
	let seconds = +timeArr[0] * 60 * 60 + +timeArr[1] * 60 + +timeArr[2];

	if (ms === true) seconds = seconds * 1000;

	return parseInt(seconds);
};

const seconds2Time = (secs) => {
	if (secs < 0) secs = -secs;

	const time = {
		d: Math.floor(secs / 86400),
		h: Math.floor(secs / 3600) % 24,
		min: Math.floor(secs / 60) % 60,
		s: Math.floor(secs) % 60,
	};

	return Object.entries(time)
		.filter((val) => val[1] !== 0)
		.map((val) => val[1] + val[0])
		.join(' ');
};

const fixPuppeteerLaunchPath = (pupConfig) => {
	let chromeFolder = '';

	let chromePathsArr = ['/snap/bin/chromium'];

	if (config.puppeteer_chrome_location != '')
		chromePathsArr.unshift(config.puppeteer_chrome_location);


	const startPath = path.join('./chrome');

	if (fs.existsSync(startPath)) {
		let chromePath;
		let chromeFiles = fs.readdirSync(startPath);

		chromeFiles.forEach((file) => {
			let versionFolder = chromeFiles.find((file) => /^win\d+/.test(file));
			if (typeof versionFolder !== 'undefined' && typeof startPath !== 'undefined') {
				chromeFolder = path.join(startPath, versionFolder, 'chrome-win64', 'chrome.exe');
			}
		});

		if (chromeFolder != '' && typeof chromeFolder !== 'undefined')
			chromePathsArr.push(chromeFolder);
	}

	for (let i = 0; i < chromePathsArr.length; i++) {
		chromePath = chromePathsArr[i];

		if (fs.existsSync(chromePath)) {
			pupConfig["executablePath"] = chromePath;

			break;
		}
	}

	return pupConfig;
};

const fixPuppeteerProxy = async (pupConfig) => {
	let proxyConfig = '';

	if (config.proxy_protocol !== '' && config.proxy_host !== '' && config.proxy_port !== '') {
		if (config.proxy_protocol === 'http' || config.proxy_protocol === 'https') {
			proxyConfig = `${config.proxy_protocol}://${config.proxy_host}:${config.proxy_port}`;
		} else if (
			config.proxy_protocol === 'socks' ||
			config.proxy_protocol === 'socks4' ||
			config.proxy_protocol === 'socks5'
		) {
			proxyConfig = `socks://${config.proxy_host}:${config.proxy_port}`;
		}

		pupConfig["args"].push(`--proxy-server=${proxyConfig}`);
	}

	return pupConfig;
};

const setKeyDropCookies = async () => {
	let filePathCookies = `./cookies/${config.keydrop_cookie_file}`;

	if (!fs.existsSync(filePathCookies)) {
		let pupConfig = {
			devtools: false,
			headless: false,
			defaultViewport: null,
			args: [
				'--no-sandbox',
				'--disable-setuid-sandbox',
				'--app=https://key-drop2.com/?q=/en/Login_page',
				'--disable-extensions',
				'--disable-popup-blocking',
				'--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'
			],
		};

		pupConfig = await fixPuppeteerLaunchPath(pupConfig);
		pupConfig = await fixPuppeteerProxy(pupConfig);

		puppeteer.use(StealthPlugin());
		const browserCfg = await puppeteer.launch(pupConfig);

		if (config.proxy_username !== '' && config.proxy_password !== '') {
			await page.authenticate({
				username: config.proxy_username,
				password: config.proxy_password
			});
		}
		const [page] = await browserCfg.pages();
		await page.waitForTimeout(2000);

		let loggedIn = false;
		let sessionIDCookie, keyLangCookie, vioShieldCookie;

		while (loggedIn === false) {
			const cookies = await page.cookies();
			sessionIDCookie = cookies.find((cookie) => cookie.name === 'session_id');
			keyLangCookie = cookies.find((cookie) => cookie.name === 'key-lang');
			vioShieldCookie = cookies.find((cookie) => cookie.name === '__vioShield');

			const url = await page.url();

			if (sessionIDCookie && keyLangCookie && vioShieldCookie && url.includes("key-drop.com")) {
				loggedIn = true;
			}

			await page.waitForTimeout(2000);
		}

		const cookieData = `key-drop.com\tTRUE\t/\tFALSE\t${sessionIDCookie.expires}\tsession_id\t${sessionIDCookie.value}\n` +
							`key-drop.com\tTRUE\t/\tFALSE\t${keyLangCookie.expires}\tkey-lang\t${keyLangCookie.value}\n` +
							`key-drop.com\tTRUE\t/\tFALSE\t${vioShieldCookie.expires}\t__vioShield\t${vioShieldCookie.value}\n`;

		fs.writeFileSync(filePathCookies, cookieData, (err) => {
			if (err) {
				logger('Cookies', `ERROR writing cookies file ${filePathCookies}`, '31');
			}
		});

		await browserCfg.close();
	}

	try {
		const cookiemap = new cookiefile.CookieMap(filePathCookies);
		cookies = cookiemap.toRequestHeader().replace('Cookie: ', '');
	} catch {
		if (fs.existsSync(filePathCookies)) {
			try {
				fs.unlinkSync(filePathCookies);

				logger('Cookies', `ERROR cookies file wrong format, launch again -> ${filePathCookies}`, '31');
			}
			catch {
				logger('Cookies', `ERROR with cookies file, delete and try again -> ${filePathCookies}`, '31');
			}
		}
		else {
			logger('Cookies', `ERROR cannot read cookies file -> ${filePathCookies}`, '31');
		}

		await quit();
	}
};

const parseGiveAwaysCooldown = (timeString) => {
	const regex = /(\d+)h\s+(\d+)m\s+(\d+)s/;
	const match = timeString.match(regex);

	if (match) {
		const hours = parseInt(match[1]);
		const minutes = parseInt(match[2]);
		const seconds = parseInt(match[3]);

		const totalSeconds = (hours * 3600) + (minutes * 60) + seconds;

		return totalSeconds;
	}

	return 0;
}

const getGoldMessages = async () => {
	clearTimeout(intValGoldMessages);

	if (keyDropToken === '' || typeof keyDropToken === 'undefined') {
		intValGoldMessages = setTimeout(getGoldMessages, intValRandomness(config.notoken_interval));
	} else {
		intValGoldMessages = setTimeout(getGoldMessages, intValRandomness(config.keydrop_goldcode_history_interval));

		if (config.discord_golden_code_channels.length > 0) {
			for (let chn of config.discord_golden_code_channels) {
				const channel = discordGoldClient.channels.cache.get(chn);

				if (!channel) {
					logger('DiscordGold', `ERROR no channel perms -> ${chn}`, '31');

					return;
				}

				try {
					const messages = await channel.messages.fetch({ limit: 20 });
					messages.forEach(msg => {
						let code = msg.getCode();
						let stamp = 0;
						let currentTimestamp = Date.now();

						if (code !== false) {
							stamp = msg.createdTimestamp;

							if (stamp > 0) {
								const diffTs = currentTimestamp - stamp;

								if (diffTs <= config.keydrop_goldcode_expire_interval) {
									goldcodemgr.redeem(code, 'History');
								}
							}
						}
					});
				}
				catch (error) {
					logger('DiscordGold', `ERROR getting messages: ${error}`, '31');
				}
			}
		}
	}
};

const configPupProxy = async () => {
	if (config.puppeteer_proxy == true) {
		let pupConfig = {
			headless: config.puppeteer_headless,
			args: [
				`--user-agent=${config.useragent}`,
				'--no-sandbox',
				'--disable-setuid-sandbox'
			]
		};


		pupConfig = await fixPuppeteerLaunchPath(pupConfig);
		pupConfig = await fixPuppeteerProxy(pupConfig);


		const pupProxyServer = express();

		puppeteer.use(StealthPlugin());
		browser = await puppeteer.launch(pupConfig);

		const [page] = await browser.pages();


		if (config.proxy_username !== '' && config.proxy_password !== '') {
			await page.authenticate({
				username: config.proxy_username,
				password: config.proxy_password
			});
		}

		try {
			await page.goto('https://key-drop.com/token');
			await page.waitForTimeout(100);
		}
		catch {
			logger('PupProxy', `ERROR network`, '31');

			await quit();
		}


		pupProxyServer.use(express.json());
		pupProxyServer.use(express.urlencoded({ extended: true }));
		pupProxyServer.use((req, res, next) => {
			if (req.get('X-Requested-With') === 'XMLHttpRequest') {
				express.text({ type: '*/*' })(req, res, next);
			} else {
				next();
			}
		});

		pupProxyServer.use((req, res, next) => {
			req.rawBody = req.body;
			next();
		});

		pupProxyServer.put('/', async (req, res) => {
			const url = req.originalUrl.split('?url=')[1];

			try {
				const result = await runPupProxy(url, "put", req.headers || {}, req.cookies || {});
				res.send(result);
			} catch (error) {
				logger('PupProxy', `ERROR PUT: ${error}`, '31');

				res.status(500).send('Something went wrong.');
			}
		});

		pupProxyServer.get('/', async (req, res) => {
			const url = req.originalUrl.split('?url=')[1];

			try {
				const result = await runPupProxy(url, 'get', req.headers || {}, req.cookies || {});
				res.send(result);
			} catch (error) {
				logger('PupProxy', `ERROR GET: ${error}`, '31');

				res.status(500).send('Something went wrong.');
			}
		});

		pupProxyServer.post('/', upload.none(), async (req, res) => {
			const url = req.originalUrl.split('?url=')[1];

			try {
				const isXMLHttpRequest = req.get('X-Requested-With') === 'XMLHttpRequest';

				const formData = JSON.parse(JSON.stringify(req.body));
				const xmlData = isXMLHttpRequest ? stringifyOnce(req.body) : '';

				const result = await runPupProxy(url, 'post', req.headers || {}, req.cookies || {}, formData, xmlData);
				res.send(result);
			} catch (error) {
				logger('PupProxy', `ERROR POST: ${error}`, '31');

				res.status(500).send('Something went wrong.');
			}
		});


		pupProxyServer.listen(config.puppeteer_proxy_port, () => {
			logger('PupProxy', `Listening at http://localhost:${config.puppeteer_proxy_port}`);
		});
	}
};

const configKeyDropBattlesWS = () => {
	clearTimeout(intValProcBattles);

	if (keyDropToken === '' || typeof keyDropToken === 'undefined') {
		intValProcBattles = setTimeout(configKeyDropBattlesWS, intValRandomness(config.notoken_interval));
		wsClose(wsBattles);
	} else if (keyDropBattleTickets > 0) {
		intValProcBattles = setTimeout(configKeyDropBattlesWS, intValRandomness(config.keydrop_battles_wscon_interval));

		const wsBattlesUrl = 'wss://kdrp3.com/socket.io/?connection=battle&EIO=4&transport=websocket';

		if (typeof wsBattles === 'undefined' || typeof wsBattles.readyState === 'undefined' || (typeof wsBattles !== 'undefined' && typeof wsBattles.readyState !== 'undefined' && wsBattles.readyState !== WebSocket.OPEN)) {
			wsBattles = new WebSocket(wsBattlesUrl);
		}

		wsBattles.on('open', () => {
			const authPayload = {
				token: keyDropToken
			};

			wsBattles.send(`40/case-battle,${JSON.stringify(authPayload)}`);

			logger('Battles', `Connected to WSS...`);
			wsBattlesConnected = true;

			setInterval(() => {
				if (wsBattles.readyState === WebSocket.OPEN) {
					wsBattles.send('3');
				}
			}, 10000);
		});

		wsBattles.on('message', (data) => {
			const message = data.toString('utf8');

			if (message.includes(",") == true) {
				const [message_type, ...message_data_tmp] = message.split(',');
				const message_data = message_data_tmp.join(',');

				if (message_type === "42/case-battle") {
					if (message_data.includes('"public",true,') && message_data.includes(',null]],[],')) {
						procKeyDropBattle(message_data);
					}
				}
			}
		});

		wsBattles.on('close', (code, reason) => {
			if (wsBattlesConnected == true)
				logger('Battles', `Disconnected from WSS`);

			wsBattlesConnected = false;
		});

	} else {
		intValProcBattles = setTimeout(configKeyDropBattlesWS, intValRandomness(config.retry_interval));

		wsClose(wsBattles);
	}
};

const runPupProxy = async (url, method, headers, cookies, formData = {}, xmlData = '') => {
	let page;

	if (method == "get") {
		page = await browser.newPage();
	}
	else {
		const pages = await browser.pages();
		if (typeof pages[0] !== 'undefined')
			page = pages[0];
		else {
			page = await browser.newPage();

			if (config.proxy_username !== '' && config.proxy_password !== '') {
				await page.authenticate({
					username: config.proxy_username,
					password: config.proxy_password
				});
			}

			try {
				await page.goto("https://key-drop.com/", { waitUntil: 'networkidle0' });
				await page.waitForTimeout(100);
			}
			catch {
				logger('PupProxy', `ERROR network`, '31');

				await quit();
			}
		}
	}

	let cookiesArray = [];
	if (Object.keys(cookies).length > 0) {
		cookiesArray = Object.entries(cookies).map(([name, value]) => ({
			name,
			value,
			domain: 'key-drop.com',
			path: '/',
		}));
	}
	if (Object.keys(headers).length > 0 && typeof headers['cookie'] !== 'undefined') {
		const cookiePairs = headers['cookie'].split(';');

		for (let i = 0; i < cookiePairs.length; i++) {
			const cookiePair = cookiePairs[i].trim().split('=');
			const name = cookiePair[0];
			const value = cookiePair[1];
			const cookie = {
				name: name,
				value: value,
				domain: 'key-drop.com',
				path: '/'
			};

			cookiesArray.push(cookie);
		}
	}

	if (cookiesArray.length > 0) {
		await page.deleteCookie(...(await page.cookies()));

		for (const cookie of cookiesArray) {
			await page.setCookie(cookie);
		}
	}

	if (Object.keys(headers).length > 0) {
		delete headers['postman-token'];
		delete headers['host'];
		delete headers['connection'];
		delete headers['cookie'];
		delete headers['content-type'];
		delete headers['content-length'];
		delete headers['method'];

		await page.setExtraHTTPHeaders(headers);
	}


	let content;
	let response;

	if (method == 'post' || method == 'put') {
		response = await page.evaluate(async (formData, xmlData, url, method, headers, cookiesArray) => {
			const cookieString = cookiesArray ? cookiesArray.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ') : '';

			let bodyObj;
			let formDataObj = new FormData();
			for (let key in formData) {
				if (formData.hasOwnProperty(key)) {
					let value = formData[key];

					formDataObj.append(key, value);
				}
			}

			if (Object.keys(formData).length > 0) {
				bodyObj = formDataObj;
			}

			if (xmlData != '') {
				bodyObj = xmlData;
			}

			const response = await fetch(url, {
				method: method,
				headers: {
					'Cookie': cookieString,
					...headers
				},
				body: bodyObj
			});

			return response.json();
		}, formData, xmlData, url, method, headers, cookiesArray);

		content = response;
	} else {
		try {
			if (config.proxy_username !== '' && config.proxy_password !== '') {
				await page.authenticate({
					username: config.proxy_username,
					password: config.proxy_password
				});
			}

			response = await page.goto(url, { waitUntil: 'networkidle0' });
			await page.waitForTimeout(100);

			content = await response.text();

			await page.close();
		}
		catch {
			content = {};

			await page.close();
			logger('PupProxy', `ERROR network`, '31');
		}
	}


	return content;
}

const run = async (configOV = '') => {
	fs.writeFile('./keydropbot.log', '', (err) => {
		if (err) logger('Log', `ERROR creating logfile`, '31');
	});

	let filePathConfig = './config.json';

	if (!fs.existsSync(filePathConfig)) {
		filePathConfig = './config.default.json';
	}

	if (configOV != '') {
		filePathConfig = './' + configOV;
	}

	try {
		config = JSON.parse(fs.readFileSync(filePathConfig));

		config.discord_bot_token = typeof config.discord_bot_token !== 'undefined' ? config.discord_bot_token : '';
		config.discord_bot_channel = typeof config.discord_bot_channel !== 'undefined' ? config.discord_bot_channel : '';

		config.discord_bot_mention_user_id = typeof config.discord_bot_mention_user_id !== 'undefined' ? config.discord_bot_mention_user_id : '';
		config.discord_bot_gold_token = typeof config.discord_bot_gold_token !== 'undefined' ? config.discord_bot_gold_token : '';
		config.discord_bot_gold_id = typeof config.discord_bot_gold_id !== 'undefined' ? config.discord_bot_gold_id : '';
		config.discord_golden_code_channels = typeof config.discord_golden_code_channels !== 'undefined' ? config.discord_golden_code_channels : [];

		config.captchakey = typeof config.captchakey !== 'undefined' ? config.captchakey : '';
		config.captchaservice = typeof config.captchaservice !== 'undefined' ? config.captchaservice : '';

		config.webinterface = typeof config.webinterface !== 'undefined' ? Boolean(config.webinterface) : false;
		config.webinterface_port = typeof config.webinterface_port !== 'undefined' ? parseInt(config.webinterface_port) : 3000;
		config.webinterface_user = typeof config.webinterface_user !== 'undefined' ? config.webinterface_user : '';
		config.webinterface_pass = typeof config.webinterface_pass !== 'undefined' ? config.webinterface_pass : '';

		config.puppeteer_proxy = typeof config.puppeteer_proxy !== 'undefined' ? Boolean(config.puppeteer_proxy) : false;
		config.puppeteer_proxy_port = typeof config.puppeteer_proxy_port !== 'undefined' ? parseInt(config.puppeteer_proxy_port) : 4000;
		config.puppeteer_proxy_catch_all = typeof config.puppeteer_proxy_catch_all !== 'undefined' ? Boolean(config.puppeteer_proxy_catch_all) : false;
		config.puppeteer_headless = typeof config.puppeteer_headless !== 'undefined' ? config.puppeteer_headless : 'new';
		config.puppeteer_chrome_location = typeof config.puppeteer_chrome_location !== 'undefined' ? config.puppeteer_chrome_location : '';

		config.proxy_host = typeof config.proxy_host !== 'undefined' ? config.proxy_host : '';
		config.proxy_port = typeof config.proxy_port !== 'undefined' ? config.proxy_port : '';
		config.proxy_protocol = typeof config.proxy_protocol !== 'undefined' ? config.proxy_protocol : '';
		config.proxy_username = typeof config.proxy_username !== 'undefined' ? config.proxy_username : '';
		config.proxy_password = typeof config.proxy_password !== 'undefined' ? config.proxy_password : '';

		config.connection_retries = typeof config.connection_retries !== 'undefined' ? onlyPositive(parseInt(config.connection_retries)) : 0;

		config.keydrop_cookie_file = typeof config.keydrop_cookie_file !== 'undefined' ? config.keydrop_cookie_file : 'cookie.txt',

		config.auto_goldencodes = typeof config.auto_goldencodes !== 'undefined' ? Boolean(config.auto_goldencodes) : false;
		config.auto_goldencases_open = typeof config.auto_goldencases_open !== 'undefined' ? Boolean(config.auto_goldencases_open) : false;
		config.auto_battletickets = typeof config.auto_battletickets !== 'undefined' ? Boolean(config.auto_battletickets) : false;
		config.auto_giveaways = typeof config.auto_giveaways !== 'undefined' ? Boolean(config.auto_giveaways) : false;
		config.auto_dailycase = typeof config.auto_dailycase !== 'undefined' ? Boolean(config.auto_dailycase) : false;

		config.keydrop_userinfo_interval = typeof config.keydrop_userinfo_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_userinfo_interval)) : 480000;
		config.keydrop_token_interval = typeof config.keydrop_token_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_token_interval)) : 1200000;
		config.keydrop_giveaways_interval = typeof config.keydrop_giveaways_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_giveaways_interval)) : 480000;
		config.keydrop_giveaways_results_interval = typeof config.keydrop_giveaways_results_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_giveaways_results_interval)) : 480000;
		config.keydrop_giveaways_cooldown_interval = typeof config.keydrop_giveaways_cooldown_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_giveaways_cooldown_interval)) : 3600000;
		config.keydrop_giveaways_maxrecheck_interval = typeof config.keydrop_giveaways_maxrecheck_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_giveaways_maxrecheck_interval)) : 3600000;
		config.keydrop_battles_wscon_interval = typeof config.keydrop_battles_wscon_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_battles_wscon_interval)) : 60000;
		config.keydrop_battles_maxrecheck_interval = typeof config.keydrop_battles_maxrecheck_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_battles_maxrecheck_interval)) : 14400000;
		config.keydrop_battles_waittoend_interval = typeof config.keydrop_battles_waittoend_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_battles_waittoend_interval)) : 60000;
		config.keydrop_battles_results_interval = typeof config.keydrop_battles_results_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_battles_results_interval)) : 480000;
		config.keydrop_dailycase_interval = typeof config.keydrop_dailycase_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_dailycase_interval)) : 3600000;
		config.keydrop_dailycase_maxrecheck_interval = typeof config.keydrop_dailycase_maxrecheck_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_dailycase_maxrecheck_interval)) : 14400000;
		config.keydrop_goldcode_history_interval = typeof config.keydrop_goldcode_history_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_goldcode_history_interval)) : 60000;
		config.keydrop_goldcode_expire_interval = typeof config.keydrop_goldcode_expire_interval !== 'undefined' ? onlyPositive(parseInt(config.keydrop_goldcode_expire_interval)) : 900000;

		config.keydrop_battles_maxusercount = typeof config.keydrop_battles_maxusercount !== 'undefined' ? config.keydrop_battles_maxusercount : [];
		config.keydrop_battles_minprice = typeof config.keydrop_battles_minprice !== 'undefined' ? parseFloat(config.keydrop_battles_minprice) : 0;
		config.keydrop_giveaways_retries = typeof config.keydrop_giveaways_retries !== 'undefined' ? onlyPositive(parseInt(config.keydrop_giveaways_retries)) : 1;
		config.keydrop_giveaways_minprize = typeof config.keydrop_giveaways_minprize !== 'undefined' ? onlyPositive(parseFloat(config.keydrop_giveaways_minprize)) : 0;
		config.keydrop_goldencases_autoopen_price = typeof config.keydrop_goldencases_autoopen_price !== 'undefined' ? onlyPositive(parseInt(config.keydrop_goldencases_autoopen_price)) : 0;
		config.keydrop_history_regs = typeof config.keydrop_history_regs !== 'undefined' ? onlyPositive(parseInt(config.keydrop_history_regs)) : 100000;



		config.retry_interval = typeof config.retry_interval !== 'undefined' ? onlyPositive(parseInt(config.retry_interval)) : 30000;
		config.notoken_interval = typeof config.notoken_interval !== 'undefined' ? onlyPositive(parseInt(config.notoken_interval)) : 30000;
		config.error_interval = typeof config.error_interval !== 'undefined' ? onlyPositive(parseInt(config.error_interval)) : 120000;


		if (
			typeof config.useragent === 'undefined' ||
			(typeof config.useragent !== 'undefined' && config.useragent === '')
		) {
			logger('Config', `ERROR no useragent`, '31');

			await quit();
		}

		if (config.connection_retries > 0) {
			axiosRetry(axios, {
				retries: config.connection_retries,
				retryCondition: (e) => {
					return (
						axiosRetry.isNetworkOrIdempotentRequestError(e) ||
						e.response.status === 407 ||
						e.response.status === 429
					);
				},
				retryDelay: (retryCount) => {
					return retryCount * 2000;
				},
			});
		}
	} catch {
		logger('Config', `ERROR reading ${filePathConfig}`, '31');

		await quit();
	}

	try {
		await setKeyDropCookies();
	}
	catch (error) {
		logger(error);
		logger('Cookies', `ERROR cookies not fetched from browser and ./cookies/${config.keydrop_cookie_file} not found`, '31');

		await quit();
	}

	await configPupProxy();

	getKeyDropUserInfo();

	if (config.webinterface === true) {
		const webPort = config.webinterface_port;
		const expressApp = express();

		expressApp.get('/', (req, res) => {
			let noAuth = true;
			let auth = { login: '', password: '' };
			let login = '';
			let password = '';

			if (config.webinterface_user !== '' && config.webinterface_pass !== '') {
				noAuth = false;

				auth.login = config.webinterface_user;
				auth.password = config.webinterface_pass;

				const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
				[login, password] = Buffer.from(b64auth, 'base64').toString().split(':');
			}

			if ((login && password && login === auth.login && password === auth.password) || noAuth === true) {
				const logFile = fs.readFileSync('./keydropbot.log', 'utf-8');
				const html = ansiConverter.toHtml(logFile);

				res.send(
					'<!doctype html><html lang="en">' +
						'<head>' +
						'<meta charset="UTF-8">' +
						'<meta name="Author" content="@nan4k7">' +
						'<title>KeyDropBot</title>' +
						'<script>' +
						'function loaded() { window.scrollTo(0, document.body.scrollHeight); setInterval(function() { window.location.reload(true); }, 60000); }' +
						'</script>' +
						'</head>' +
						'<body style="background: #000; font-family:courier, courier new, serif; font-size: 12px; color: #FFF;" onload="loaded();">' +
						html +
						'</body>' +
						'</html>',
				);
			} else {
				res.set('WWW-Authenticate', 'Basic realm="401"');
				res.status(401).send('Authentication required.');
			}
		});

		expressApp.use(favicon(__dirname + '/favicon.ico'));

		expressApp.listen(webPort, () => {
			logger(
				'Server',
				`Listening on port ${webPort} -> http://localhost${parseInt(webPort) !== 80 ? ':' + webPort : ''}`,
			);
		});
	}

	if (config.discord_bot_token !== '' && config.discord_bot_channel !== '') {
		const discordBotToken = Buffer.from(config.discord_bot_token, 'base64').toString('utf8');

		discordClient.once('ready', (c) => {
			logger('Discord', `Logged in as ${c.user.tag} (${discordClient.user.id})`);

			publishChannel = discordClient.channels.cache.get(config.discord_bot_channel);
		});

		discordClient.on('error', (error) => {
			logger('Discord', `ERROR: ${error}`, '31');
		});

		discordClient.login(discordBotToken).catch((error) => {
			logger('Discord', `ERROR Login: ${error.message}`, '31');
		});
	}

	if (config.auto_goldencodes === true && config.discord_bot_gold_token !== '') {
		const discordBotGoldToken = Buffer.from(config.discord_bot_gold_token, 'base64').toString('utf8');

		discordGoldClient.once('ready', (c) => {
			logger('DiscordGold', `Logged in as ${c.user.tag} (${discordGoldClient.user.id})`);

			getGoldMessages();
		});

		discordGoldClient.on('messageCreate', async (message) => {
			let code = message.getCode();
			if (code !== false) {
				logger('DiscordGold', `Received new code -> ${code}`);
				goldcodemgr.redeem(code);
			}
		});

		discordGoldClient.on('error', (error) => {
			logger('DiscordGold', `ERROR: ${error}`, '31');
		});

		discordGoldClient.login(discordBotGoldToken).catch((error) => {
			logger('DiscordGold', `ERROR Login: ${error.message}`, '31');
		});

		goldcodemgr = new GoldCodeManager();

		Discord.Message.prototype.getCode = () => {
			if (config.discord_golden_code_channels.includes(this.channelId)) {
				if (this.author.id === config.discord_bot_gold_id && config.discord_bot_gold_id !== '') {
					if (this.content?.length === 17) {
						return this.content;
					}
				}
			}

			return false;
		};
	}

	if (config.auto_battletickets === true) {
		battlesmgr = new BattlesManager();
		configKeyDropBattlesWS();
		procKeyDropBattlesResults();
	}

	if (config.auto_giveaways === true) {
		giveawaysmgr = new GiveAwaysManager();
		procKeyDropGiveAways();
		procKeyDropGiveAwaysResults();
	}

	if (config.auto_dailycase === true) {
		procKeyDropDailyCase();
	}

	if (config.auto_goldencases_open === true) {
		procKeyDropGoldCase();
	}
};

const wait = (ms) => {
	return new Promise((resolve) => {
		setTimeout(() => resolve(), ms);
	});
};

const intValRandomness = (intval) => {
	const randomNess = 1 + (1.05 - 1) * Math.random();

	return parseInt(randomNess * intval);
};

const getKeyDropUserInfo = async () => {
	clearTimeout(intValTokenRefresh);
	clearTimeout(intValUserInfoRefresh);

	if (typeof cookies !== 'undefined' && cookies !== '') {
		let axiosConfig = new AxiosConfig({
			url: 'https://key-drop.com/en/apiData/Init/index',
			method: 'get',
			cookies: cookies,
		});

		axios
			.request(axiosConfig.get())
			.then((response) => {

				if (typeof response.data !== 'undefined' && typeof response.data.steamId !== 'undefined') {
					keyDropUsername = response.data.userName;
					keyDropGold = parseInt(response.data.gold);
					keyDropBattleTickets = parseInt(response.data.caseBattleTickets);

					steamId = response.data.steamId;

					if (config.auto_goldencases_open === true) {
						let axiosConfigGoldCases = new AxiosConfig({
							url: 'https://key-drop.com/en/apiData/Cases',
							method: 'get',
							cookies: cookies,
						});

						axios
							.request(axiosConfigGoldCases.get())
							.then((response) => {
								if (
									typeof response.data !== 'undefined' &&
									typeof response.data.success !== 'undefined' &&
									response.data.success === true
								) {
									let sectionsArr = typeof response.data.sections != 'undefined' ? response.data.sections : [];

									if (sectionsArr?.length > 0) {
										let foundGoldCasesArr = false;
										let possibleCases = [];

										for (let section of sectionsArr) {
											if (section.name === 'GOLD AREA') {
												foundGoldCasesArr = true;

												let cazesArr = typeof section.cases !== 'undefined' ? section.cases : [];

												if (cazesArr?.length > 0) {
													for (let caze of cazesArr) {
														let cazeId = typeof caze.id !== 'undefined' ? parseInt(caze.id.replace(/\D/g,'')) : 0;
														let cazePrice = typeof caze.price !== 'undefined' ? parseInt(caze.price) : -1;
														let diffPrice = config.keydrop_goldencases_autoopen_price - cazePrice;


														if (cazeId > 0 && cazePrice > 0 && diffPrice >= 0) {
															let cazeData = {"id": cazeId, "price": cazePrice, "diff": diffPrice, "name": caze.name}

															possibleCases.push(cazeData);
														}
													}
												}

												break;
											}
											else {
												continue;
											}
										}

										if (foundGoldCasesArr === false) {
											logger('GoldCasesData', `ERROR: gold cases not found`, '31');
										}
										else if (possibleCases?.length === 0) {
											logger('GoldCasesData', `ERROR: no gold case cheaper than ${config.keydrop_goldencases_autoopen_price}`, '31');
										}
										else {
											keyDropGoldCase = possibleCases.reduce((prev, curr) => { return curr.diff < prev.diff ? curr : prev });
										}
									}
									else {
										logger('GoldCasesData', `ERROR: no sections data`, '31');
									}
								} else {
									logger('GoldCasesData', `ERROR res: ${JSON.stringify(response)}`, '31');
								}
							})
							.catch((error) => {
								logger('GoldCasesData', `ERROR: ${error.message}`, '31');
							});
					}


					if (keyDropUsername && keyDropUsername !== '' && typeof keyDropUsername !== 'undefined') {

						if (config.auto_giveaways === true && giveawaysmgr.joinedHistoryQueue?.length > 0) {
							const giveawaysQ = giveawaysmgr.joinedHistoryQueue?.length;
							const giveawaysWonQ = giveawaysmgr.wonQueue?.length;
							const giveawaysWon = (giveawaysWonQ > 0) ? ' -> Won: ' + giveawaysWonQ + ' (' + Math.round(((giveawaysWonQ / giveawaysQ) + Number.EPSILON) * 100) + '%)' : '';

							logger('Stats', `\x1b[44m GiveAways joined: ${giveawaysQ}${giveawaysWon} \x1b[0m`);
						}

						if (config.auto_battletickets == true && battlesmgr.foughtQueue?.length > 0) {
							const battlesQ = battlesmgr.foughtQueue?.length;
							const battlesWonQ = battlesmgr.wonQueue?.length;
							const battlesWon = (battlesWonQ > 0) ? ' -> Won: ' + battlesWonQ + ' (' + Math.round(((battlesWonQ / battlesQ) + Number.EPSILON) * 100) + '%)' : '';


							logger('Stats', `\x1b[44m Battles joined: ${battlesQ}${battlesWon} \x1b[0m`);
						}

						if (earnedCash > 0) {
							logger('Stats', `\x1b[44m Cash earned: ${earnedCash}U$D \x1b[0m`);
						}


						if (earnedGold > 0) {
							logger('Stats', `\x1b[44m Gold earned: ${earnedGold} \x1b[0m`);
						}



						logger('UserInfo', `Logged as ${keyDropUsername}`);
						logger(
							'UserInfo',
							`|\x1b[42m  ${response.data.balance}U$D  \x1b[0m|\x1b[43m  ${keyDropGold} Gold  \x1b[0m|\x1b[105m  ${keyDropBattleTickets} BT  \x1b[0m|`,
						);

						let axiosConfigInventory = new AxiosConfig({
							url: 'https://key-drop.com/en/panel/profil/my_winner_list?type=all&sort=newest&weaponType=&state=active&per_page=100&current_page=1',
							method: 'get',
							cookies: cookies,
						});

						axios
							.request(axiosConfigInventory.get())
							.then((response) => {
								if (
									typeof response.data !== 'undefined' &&
									typeof response.data.status !== 'undefined' &&
									response.data.status === true
								) {
									if (response.data.data === false) {
										logger('UserInfo', `\x1b[104m  INVENTORY EMPTY  \x1b[0m`);
									} else {
										let itemsCount = 0;
										let priceSum = 0;

										response.data.data.forEach((item) => {
											priceSum += parseFloat(item.price);

											itemsCount++;
										});

										logger(
											'UserInfo',
											`\x1b[104m INVENTORY -> ${itemsCount} item${itemsCount > 1 ? 's' : ''} (${
												Math.round(priceSum * 100) / 100
											}U$D) \x1b[0m`,
										);
									}
								} else {
									logger('UserInfo', `ERROR inventory${response.data.message ? ': ' + response.data.message : ''}`, '31');
								}
							})
							.catch((error) => {
								logger('UserInfo', `ERROR: ${error.message}`, '31');

								intValUserInfoRefresh = setTimeout(
									getKeyDropUserInfo,
									intValRandomness(config.error_interval),
								);
							});

						intValUserInfoRefresh = setTimeout(
							getKeyDropUserInfo,
							intValRandomness(config.keydrop_userinfo_interval),
						);

						refreshKeyDropToken();
						procKeyDropGoldCase();
					} else {
						logger('UserInfo', `ERROR username empty`, '31');

						intValUserInfoRefresh = setTimeout(getKeyDropUserInfo, intValRandomness(config.error_interval));
					}
				} else {
					logger('UserInfo', `ERROR no data`, '31');

					intValUserInfoRefresh = setTimeout(getKeyDropUserInfo, intValRandomness(config.error_interval));
				}
			})
			.catch((error) => {
				logger('UserInfo', `ERROR: ${error.message}`, '31');

				intValUserInfoRefresh = setTimeout(getKeyDropUserInfo, intValRandomness(config.error_interval));
			});
	}
};

const refreshKeyDropToken = async () => {
	let ts = Date.now();
	let axiosConfig = new AxiosConfig({
		url: 'https://key-drop.com/en/token?t=' + ts,
		method: 'get',
		cookies: cookies,
	});

	axios
		.request(axiosConfig.get())
		.then((response) => {
			logger('TokenRefresh', `OK`, '90');
			keyDropToken = response.data;
		})
		.catch((error) => {
			logger('TokenRefresh', `ERROR: ${error.message}`, '31');
		});

	intValTokenRefresh = setTimeout(refreshKeyDropToken, intValRandomness(config.keydrop_token_interval));
};

const parseBattleResults = async (id, rounds, winerId) => {
	if (String(steamId) === String(winerId)) {
		if (typeof rounds !== 'undefined' && rounds?.length > 0) {
			let roundsProc = await procRounds(rounds);
			let totalWon = Math.round((roundsProc.totalWon + Number.EPSILON) * 100) / 100;
			let itemsCount = roundsProc.itemsCount;

			battlesmgr.wonQueue.push(id);

			if (parseFloat(totalWon) > 0) {
				logger(
					'Battles',
					`${id} -> YOU WON!!! :D ${totalWon}U$D on ${itemsCount} item${itemsCount > 1 ? 's' : ''}`,
					'32',
				);

				earnedCash = earnedCash + parseFloat(totalWon);

			} else {
				logger('Battles', `${id} -> couldn't sum earnings, I think you won... :?`, '96');
			}

			getKeyDropUserInfo();
		} else {
			logger('Battles', `${id} -> no rounds info, WTF`, '96');
		}

		getKeyDropUserInfo();
	} else {
		logger('Battles', `${id} -> you lost... :'(`);
	}
};

const procKeyDropBattle = async (battleData) => {

	const regex_case_name = /\[\d+,"([^",\]]+)/g;

	const battle_cases = battleData.matchAll(regex_case_name);
	const battle_cases_names = Array.from(battle_cases, match => match[1]);
	let battle_cases_prize = 0;
	const battle_cases_cant = battle_cases_names.length;

	const battle_id = parseInt(battleData.split('["BC_CREATE_V3",[')[1].split(",")[0]);
	const battle_cost = parseInt(battleData.split(',null]],[],')[1].split("]]")[0]);
	const battle_max_users = parseInt(battleData.split(`["BC_CREATE_V3",[${battle_id},`)[1].split(",")[0]);


	let match;
	const regex_case_prize = /\[(\d+),"([^"]+)",(\d+\.\d+)/g;
	while ((match = regex_case_prize.exec(battleData)) !== null) {
		const prize = parseFloat(match[3]);
		battle_cases_prize += prize;
	}


	let minPrice = -1;

	if (
		config.keydrop_battles_minprice > 0 &&
		config.keydrop_battles_minprice <= 1
	)
		minPrice = config.keydrop_battles_minprice;


	if (minPrice === -1 || parseFloat(battle_cases_prize) >= parseFloat(minPrice)) {
		if (config.keydrop_battles_maxusercount.length > 0) {
			if (config.keydrop_battles_maxusercount.includes(battle_max_users))
				battlesmgr.fight(battle_id, battle_max_users);
		} else {
			battlesmgr.fight(battle_id, battle_max_users);
		}
	}

};

const procKeyDropBattlesResults = async () => {
	clearTimeout(intValProcBattlesResults);

	if (keyDropToken === '' || typeof keyDropToken === 'undefined') {
		intValProcBattlesResults = setTimeout(procKeyDropBattlesResults, intValRandomness(config.notoken_interval));
	} else {
		intValProcBattlesResults = setTimeout(
			procKeyDropBattlesResults,
			intValRandomness(config.keydrop_battles_results_interval),
		);

		const battlesUnfinished = battlesmgr.unFinishedQueue.map((x) => x);
		const battlesUnfinishedLength = battlesUnfinished?.length || 0;
		let battlesUnfinishedProcCount = 0;

		if (battlesUnfinishedLength > 0) {
			logger(
				'BattlesResults',
				`Processing ${battlesUnfinishedLength} battle${battlesUnfinishedLength > 1 ? 's' : ''}...`,
			);

			for (var i = 0; i < battlesUnfinishedLength; i++) {
				let id = String(battlesUnfinished[i]);

				const battleDetails = await getKeyDropBattlesData(id, 'BattlesResults');
				const battleDetailsData =
					typeof battleDetails !== 'undefined' && typeof battleDetails.data !== 'undefined'
						? battleDetails.data.data
						: [];

				if (
					typeof battleDetails !== 'undefined' &&
					typeof battleDetails.data !== 'undefined' &&
					typeof battleDetails.data.success !== 'undefined' &&
					battleDetails.data.success === true
				) {
					let winerId = battleDetailsData.wonSteamId;
					let batStatus = battleDetailsData.status;
					let rounds = battleDetailsData.rounds;

					if (typeof batStatus !== 'undefined' && batStatus === 'ended') {
						battlesUnfinishedProcCount++;

						parseBattleResults(id, rounds, winerId);

						battlesmgr.spliceUnfinished(id);
					} else {
						logger('BattlesResults', `not ended yet (${batStatus}})`);
					}
				} else {
					logger(
						'BattlesResults',
						`${id} -> ERROR no details?${
							battleDetailsData && battleDetailsData?.length > 0
								? ' (' + JSON.stringify(battleDetailsData) + ')'
								: ''
						}`,
						'31',
					);
				}
			}

			if (battlesUnfinishedProcCount === 0) {
				logger('BattlesResults', `no news yet`);
			}
		}
	}
};

const procRounds = async (rounds) => {
	let totalWon = 0;
	let itemsCount = 0;

	rounds.forEach((round) => {
		if (typeof round.wonItems !== 'undefined' && round.wonItems?.length > 0) {
			round.wonItems.forEach((item) => {
				totalWon += parseFloat(item.price);

				itemsCount++;
			});
		}
	});

	return { totalWon: totalWon, itemsCount: itemsCount };
};

const getKeyDropBattlesData = async (id, category = 'Battles') => {
	let axiosConfig = new AxiosConfig({
		url: 'https://kdrp2.com/CaseBattle/gameFullData/' + id,
		method: 'get',
		headers: 'no',
		cloudFlareProtection: false
	});

	try {
		const response = await axios.request(axiosConfig.get());

		return response;
	} catch (error) {
		logger(category, `ERROR data: ${error.message}`, '31');

		clearTimeout(intValProcBattlesResults);
		intValProcBattlesResults = setTimeout(
			procKeyDropBattlesResults,
			intValRandomness(config.keydrop_battles_results_interval),
		);
	}
};

const fightBattle = async (id, players = 2) => {
	id = String(id);

	logger('Battles', `found free -> ${id}`);

	let randSlot = Math.floor(Math.random() * (players - 1 + 1)) + 1;
	let axiosConfig = new AxiosConfig({
		url: 'https://kdrp2.com/CaseBattle/joinCaseBattle/' + id + '/' + randSlot,
		method: 'post',
		headers: 'no',
		additionalHeaders: [{ Authorization: 'Bearer ' + keyDropToken }],
		cloudFlareProtection: false
	});

	axios
		.request(axiosConfig.get())
		.then((response) => {
			if (
				typeof response.data !== 'undefined' &&
				typeof response.data.success !== 'undefined' &&
				response.data.success === true
			) {
				logger(
					'Battles',
					`${id} -> fighting ${players - 1 > 0 ? players - 1 : 1} player${players - 1 > 1 ? 's' : ''}...`,
				);

				let axiosConfig = new AxiosConfig({
					url: 'https://kdrp2.com/CaseBattle/gameFullData/' + id,
					method: 'get',
					headers: 'no',
					cloudFlareProtection: false
				});

				setTimeout(() => {
					axios
						.request(axiosConfig.get())
						.then((response) => {
							if (
								typeof response.data !== 'undefined' &&
								typeof response.data.success !== 'undefined' &&
								response.data.success === true
							) {
								let winerId = response.data.wonSteamId;
								let batStatus = response.data.status;
								let rounds = response.data.rounds;

								keyDropBattleTickets--;

								battlesmgr.foughtQueue.push(id);

								if (typeof batStatus !== 'undefined' && batStatus === 'ended') {
									parseBattleResults(id, rounds, winerId);
								} else {
									battlesmgr.unFinishedQueue.push(id);

									logger('Battles', `${id} -> not finished, couldn't get result`, '33');
								}
							} else {
								logger('Battles', `${id} -> ERROR: ${response.data.message}`, '31');
							}
						})
						.catch((error) => {
							logger('Battles', `${id} -> ERROR fight: ${error.message}`, '31');
						});
				}, config.keydrop_battles_waittoend_interval);
			} else {
				if (response.data.errorCode === 'userHasToWaitBeforeJoiningFreeBattle') {
					let timeStrStart = response.data.message.replace(/[^0-9 ]/g, '').trim();
					let timeArr = timeStrStart.split(' ');
					let timeStr = '';

					timeArr.forEach((value) => {
						timeStr +=
							timeStr !== '' ? ':' + String(value).padStart(2, '0') : String(value).padStart(2, '0');
					});
					timeStr.padStart(8, '00:');

					let mseconds = time2Seconds(timeStr, true);

					if (mseconds > 0) {
						if (config.keydrop_battles_maxrecheck_interval > 0 &&
							mseconds > config.keydrop_battles_maxrecheck_interval
						) {
							battlesmgr.coolDown = config.keydrop_battles_maxrecheck_interval;
						} else {
							battlesmgr.coolDown = mseconds;
						}

						battlesmgr.clear();
						clearTimeout(intValProcBattles);
						intValProcBattles = setTimeout(configKeyDropBattlesWS, intValRandomness(battlesmgr.coolDown));

						wsClose(wsBattles);
					}

					logger('Battles', `Cooldown -> ${seconds2Time(mseconds / 1000)}`, '36');

					if (battlesmgr.coolDown === config.keydrop_battles_maxrecheck_interval) {
						logger('Battles', `will recheck in -> ${seconds2Time(battlesmgr.coolDown / 1000)}`, '36');
					}
				} else if (response.data.errorCode === 'notEnoughtMoney') {
					keyDropBattleTickets = 0;

					logger('Battles', `${id} -> no tickets left`, '33');
				} else if (
					response.data.errorCode === 'slotUnavailable' ||
					response.data.message === 'slot unavailable'
				) {
					logger('Battles', `${id} -> slot unavailable`, '33');
				} else {
					logger('Battles', `${id} -> ${response.data.message} (${response.data.errorCode})`, '33');
				}
			}
		})
		.catch((error) => {
			logger('Battles', `${id} -> ERROR fight: ${error.message}`, '31');
		});
};

const procKeyDropGiveAways = async () => {
	clearTimeout(intValProcGiveAways);

	giveawaysmgr.coolDown = 0;

	if (keyDropToken === '' || typeof keyDropToken === 'undefined') {
		intValProcGiveAways = setTimeout(procKeyDropGiveAways, intValRandomness(config.notoken_interval));
	} else {
		intValProcGiveAways = setTimeout(procKeyDropGiveAways, intValRandomness(config.keydrop_giveaways_interval));

		//logger('GiveAways', `Processing...`);

		const giveaways = await refreshKeyDropGiveAways();
		const giveawaysData = typeof giveaways !== 'undefined' && typeof giveaways.data !== 'undefined' && typeof giveaways.data.data !== 'undefined' ? giveaways.data.data : [];
		const giveawaysLength = giveawaysData?.length || 0;

		if (giveawaysLength > 0) {
			for (var i = (giveawaysLength - 1); i >= 0; i--) {
				if (giveawaysData[i].haveIJoined === false) {
					let id = giveawaysData[i].id;

					if (typeof id !== 'undefined' && id !== '') {
						if (!giveawaysmgr.historyQueue.includes(id)) {
							await wait(500); //Adds delay to get giveaways details

							const giveawayDetails = await getKeyDropGiveAwaysData(id);
							const giveawayDetailsData =
								typeof giveawayDetails !== 'undefined' && typeof giveawayDetails.data !== 'undefined'
									? giveawayDetails.data.data
									: [];

							if (typeof giveawayDetailsData.id !== 'undefined') {
								if (giveawayDetailsData.haveIJoined === false) {
									logger('GiveAways', `found -> ${giveawayDetailsData.id}`);

									let totalPrizesPrice = 0;
									for (let prize of giveawayDetailsData.prizes) {
										totalPrizesPrice = totalPrizesPrice + parseFloat(prize.price);
									}

									if (totalPrizesPrice < config.keydrop_giveaways_minprize) {
										giveawaysmgr.historyQueue.push(id);

										logger('GiveAways', `${giveawayDetailsData.id} -> ${config.keydrop_giveaways_minprize}U$D minprize not met (${totalPrizesPrice}U$D)`);
									}
									else if (giveawayDetailsData.canIJoin === false) {
										giveawaysmgr.historyQueue.push(id);

										logger('GiveAways', `${giveawayDetailsData.id} -> requirements not met`);
									} else {
										giveawaysmgr.proc(id);
									}
								}
							}
						}
					}
				}
			}
		}
	}
};

const refreshKeyDropGiveAways = async () => {
	let axiosConfig = new AxiosConfig({
		url: 'https://ws-2061.key-drop.live/v1/giveaway/list?type=active&status=active&sort=latest',
		method: 'get',
		headers: 'no',
		additionalHeaders: [{ Authorization: 'Bearer ' + keyDropToken }],
		cloudFlareProtection: false
	});

	try {
		const response = await axios.request(axiosConfig.get());

		return response;
	} catch (error) {
		logger('GiveAways', `ERROR refresh: ${error.message}`, '31');
	}
};

const getKeyDropGiveAwaysData = async (id, category = 'GiveAways') => {
	let axiosConfig = new AxiosConfig({
		url: 'https://ws-2061.key-drop.live/v1/giveaway/data/' + id,
		method: 'get',
		headers: 'no',
		additionalHeaders: [{ Authorization: 'Bearer ' + keyDropToken }],
		cloudFlareProtection: false
	});

	try {
		const response = await axios.request(axiosConfig.get());

		return response;
	} catch (error) {
		clearTimeout(intValProcGiveAwaysResults);
		intValProcGiveAwaysResults = setTimeout(
			procKeyDropGiveAwaysResults,
			intValRandomness(config.keydrop_giveaways_results_interval),
		);

		logger(category, `ERROR data: ${error.message}`, '31');
	}
};

const procGiveAwayCaptcha = async (id, captchaSolution = '', retries = 0) => {
	logger('GiveAways', `${id} -> captcha solved`);

	let resnew = await procGiveAway(id, captchaSolution, retries + 1);

	if (resnew === 'success' || resnew === 'joined') {
		giveawaysmgr.joinQueue(id);
	} else {
		giveawaysmgr.spliceHistory(id);
	}
};

const procGiveAway = async (id, captcha = '', retries = 0) => {
	let axiosData;
	let headersRequest = [{ Authorization: 'Bearer ' + keyDropToken }];

	if (captcha !== '') {
		axiosData = {
			"captcha": captcha,
		};

		headersRequest.push({ 'content-type': 'application/json' });
	}

	let axiosConfig = new AxiosConfig({
		url: 'https://ws-3002.key-drop.live/v1/giveaway/joinGiveaway/' + id,
		method: 'put',
		headers: 'no',
		additionalHeaders: headersRequest,
		data: axiosData,
		cloudFlareProtection: false
	});

	let retryString = '';

	if (retries > 0) retryString = ` [retry ${retries}]`;

	const response = await axios
		.request(axiosConfig.get())
		.then((response) => {
			if (
				typeof response.data !== 'undefined' &&
				typeof response.data.success !== 'undefined' &&
				response.data.success === true
			) {
				logger('GiveAways', `${id} -> joined${retryString}`, '96');

				return 'success';
			} else {
				let msg = '';

				switch (response.data.errorCode) {
					case 'captcha':
						msg = `captcha requested${retryString}`;
						ret = 'captcha';
						break;
					case 'rateLimited':
						msg = `rate limit${retryString}`;
						ret = 'fail';
						break;
					case 'giveawayNotExist':
						msg = `does not exist${retryString}`;
						ret = 'abort';
						break;
					case 'alreadyJoined':
						//TODO REVISAR ESTE CASO CDO ESTOY JOINED Y NO LO VI EN CONSOLA
						msg = `already joined${retryString}`;
						ret = 'joined';
						break;
					case 'userHasToWaitBeforeJoiningGiveaway':
						//message: 'You must wait 2h 14m 46s before joining the next giveaway.',
						let coolSecs = parseGiveAwaysCooldown(response.data.message);

						if (coolSecs > 0)
							giveawaysmgr.coolDown = coolSecs * 1000;

						msg = `user has to wait${retryString}`;
						ret = 'cooldown';
						break;
					case 'giveawayLimitPlayers':
						msg = `players limit reached${retryString}`;
						ret = 'abort';
						break;
					case 'unknown':
						msg = `couldn't join${
							response.data.errorCode ? ': ' + response.data.errorCode : ''
						}${retryString}`;
						ret = 'abort';
						break;
					default:
						msg = `couldn't join${
							response.data.errorCode ? ': ' + response.data.errorCode : ''
						}${retryString}`;
						ret = 'fail';
						break;
				}

				logger('GiveAways', `${id} -> ${msg}`, '33');

				return ret;
			}
		})
		.catch((error) => {
			logger('GiveAways', `${id} -> ERROR joining: ${error.message}${retryString}`, '31');

			return 'error';
		});

	return response;
};

const procKeyDropGiveAwaysResults = async () => {
	clearTimeout(intValProcGiveAwaysResults);

	if (keyDropToken === '' || typeof keyDropToken === 'undefined') {
		intValProcGiveAwaysResults = setTimeout(procKeyDropGiveAwaysResults, intValRandomness(config.notoken_interval));
	} else {
		intValProcGiveAwaysResults = setTimeout(
			procKeyDropGiveAwaysResults,
			intValRandomness(config.keydrop_giveaways_results_interval),
		);

		const gaJoined = giveawaysmgr.joinedQueue.map((x) => x);
		const gaJoinedLength = gaJoined?.length || 0;
		let gaJoinedProcCount = 0;

		if (gaJoinedLength > 0) {
			logger('GiveAwaysResults', `Processing ${gaJoinedLength} giveaway${gaJoinedLength > 1 ? 's' : ''}...`);

			for (var i = 0; i < gaJoinedLength; i++) {
				let id = String(gaJoined[i]);

				const giveawayDetails = await getKeyDropGiveAwaysData(id, 'GiveAwaysResults');
				const giveawayDetailsData =
					typeof giveawayDetails !== 'undefined' && typeof giveawayDetails.data !== 'undefined'
						? giveawayDetails.data.data
						: [];

				if (
					typeof giveawayDetails !== 'undefined' &&
					typeof giveawayDetails.data !== 'undefined' &&
					typeof giveawayDetails.data.success !== 'undefined' &&
					giveawayDetails.data.success === true
				) {
					gaJoinedProcCount++;

					if (giveawayDetailsData.haveIJoined !== true) {
						giveawaysmgr.spliceJoined(id);

						logger('GiveAwaysResults', `${id} -> ERROR not joined`, '31');
					} else if (giveawayDetailsData.status === 'ended') {
						if (
							typeof giveawayDetailsData.winners !== 'undefined' &&
							giveawayDetailsData.winners?.length > 0
						) {
							let winner = false;
							let prizeId = '';
							let prizeTxt = '';

							giveawayDetailsData.winners.forEach((win) => {
								if (win.userdata.idSteam === steamId) {
									winner = true;
									prizeId = win.prizeId;
								}
							});

							giveawaysmgr.spliceJoined(id);

							if (winner === true) {
								for (let prize of giveawayDetailsData.prizes) {
									if (parseInt(prize.id) === parseInt(prizeId)) {
										prizeTxt = prize.title + ' ' + prize.subtitle + ' (' + prize.price + 'U$D)';

										earnedCash = earnedCash + parseFloat(prize.price);

										break;
									}
								}

								giveawaysmgr.wonQueue.push(id);


								logger(
									'GiveAwaysResults',
									`${id} -> YOU WON!!! :D ${prizeTxt !== '' ? prizeTxt : prizeId}`,
									'32',
								);
							} else {
								logger('GiveAwaysResults', `${id} -> not won :(`);
							}
						} else {
							logger('GiveAwaysResults', `${id} -> ERROR no winners?`, '31');
						}
					} else {
						logger('GiveAwaysResults', `${id} -> not ended yet`);
					}
				} else {
					logger(
						'GiveAwaysResults',
						`${id} -> ERROR no details?${
							giveawayDetailsData && giveawayDetailsData?.length > 0 != []
								? ' (' + JSON.stringify(giveawayDetailsData) + ')'
								: ''
						}`,
						'31',
					);
				}
			}

			if (gaJoinedProcCount === 0) {
				logger('GiveAwaysResults', `no news yet`);
			}
		}
	}
};

const procKeyDropDailyCase = async () => {
	clearTimeout(intValProcDailyCase);

	if (keyDropToken === '' || typeof keyDropToken === 'undefined') {
		intValProcDailyCase = setTimeout(procKeyDropDailyCase, intValRandomness(config.notoken_interval));
	} else {
		logger('DailyCase', `Processing...`);

		const dailycasedata = await getKeyDropDailyCaseData();

		if (
			typeof dailycasedata.data !== 'undefined' &&
			typeof dailycasedata.data.status !== 'undefined' &&
			dailycasedata.data.status === true
		) {
			const levels = dailycasedata.data.init.levels;

			if (typeof levels !== 'undefined' && levels?.length > 0) {
				let userLevel = 0;
				let deadlineTimestamp = 0;
				let canRoll = false;

				for (let level of levels) {
					let isAvailable = typeof level.isAvailable !== 'undefined' ? level.isAvailable : false;

					deadlineTimestamp =
						typeof level.deadlineTimestamp !== 'undefined' && level.deadlineTimestamp > 0
							? parseInt(level.deadlineTimestamp)
							: deadlineTimestamp;

					if (isAvailable === true) {
						canRoll = true;

						userLevel++;
						break;
					} else if (isAvailable === false && deadlineTimestamp > 0) {
						userLevel++;

						continue;
					} else {
						break;
					}
				}

				if (canRoll === true) {
					logger('DailyCase', `let's roll!!! -> Level ${userLevel}`);

					let axiosData = new FormData();
					axiosData.append('level', userLevel - 1);

					let axiosConfig = new AxiosConfig({
						url: 'https://key-drop.com/en/apiData/DailyFree/open',
						method: 'post',
						data: axiosData,
						cookies: cookies,
						formData: true,
					});

					axios
						.request(axiosConfig.get())
						.then((response) => {
							if (
								typeof response.data !== 'undefined' &&
								typeof response.data.status !== 'undefined' &&
								response.data.status === true
							) {
								let winnerData = response.data.winnerData;

								if (typeof winnerData !== 'undefined' && typeof winnerData.id !== 'undefined') {
									let prizeValue = '';

									switch (winnerData.type) {
										case 'item':
											if (
												String(winnerData.prizeValue.subtitle).includes('VOUCHER') === true ||
												String(winnerData.prizeValue.title).includes('VOUCHER') === true
											)
												prizeValue = 'Voucher (' + winnerData.prizeValue.price + 'U$D)';
											else
												prizeValue =
													winnerData.prizeValue.title +
													' ' +
													winnerData.prizeValue.subtitle +
													' (' +
													winnerData.prizeValue.price +
													'U$D)';

											earnedCash = earnedCash + parseFloat(winnerData.prizeValue.price);

											break;
										case 'gold':
											prizeValue = winnerData.prizeValue + ' Gold';
											keyDropGold = keyDropGold + parseInt(winnerData.prizeValue);
											earnedGold = earnedGold + parseInt(winnerData.prizeValue);

											procKeyDropGoldCase();

											break;
										default:
											prizeValue =
												capitalize(winnerData.type) +
												' (' +
												JSON.stringify(winnerData.prizeValue) +
												')';
											break;
									}

									logger('DailyCase', `prizes won -> ${prizeValue}`, '32');
								} else {
									logger('DailyCase', `you WON something! I don't know what :?`, '32');
								}

								getKeyDropUserInfo();
							} else {
								logger('DailyCase', `ERROR couldn't redeem: ${response.data.error}`, '31');
							}
						})
						.catch((error) => {
							logger('DailyCase', `ERROR: ${error.message}`, '31');
						});

					intValProcDailyCase = setTimeout(
						procKeyDropDailyCase,
						intValRandomness(config.keydrop_dailycase_maxrecheck_interval),
					);
				} else if (canRoll === false && deadlineTimestamp > 0) {
					let currentTimestamp = Date.now();
					const diftTs = deadlineTimestamp - currentTimestamp;
					dailyCoolDown = diftTs;

					if (
						config.keydrop_dailycase_maxrecheck_interval > 0 &&
						dailyCoolDown > config.keydrop_dailycase_maxrecheck_interval
					) {
						dailyCoolDown = config.keydrop_dailycase_maxrecheck_interval;
					}

					if (diftTs >= 0) {
						logger('DailyCase', `Cooldown -> ${seconds2Time(diftTs / 1000)}`, '36');

						if (dailyCoolDown === config.keydrop_dailycase_maxrecheck_interval) {
							logger('DailyCase', `will recheck in -> ${seconds2Time(dailyCoolDown / 1000)}`, '36');
						}

						intValProcDailyCase = setTimeout(procKeyDropDailyCase, intValRandomness(dailyCoolDown));
					} else {
						logger('DailyCase', `timestamps diff negative, will retry`, '33');

						intValProcDailyCase = setTimeout(
							procKeyDropDailyCase,
							intValRandomness(config.retry_interval),
						);
					}
				} else {
					logger('DailyCase', `ERROR not available`, '31');

					intValProcDailyCase = setTimeout(
						procKeyDropDailyCase,
						intValRandomness(config.keydrop_dailycase_interval),
					);
				}
			} else {
				logger('DailyCase', `ERROR no levels data`, '31');

				intValProcDailyCase = setTimeout(
					procKeyDropDailyCase,
					intValRandomness(config.keydrop_dailycase_interval),
				);
			}
		} else {
			logger('DailyCase', `ERROR res: ${JSON.stringify(dailycasedata.data)}`, '31');

			intValProcDailyCase = setTimeout(procKeyDropDailyCase, intValRandomness(config.retry_interval));
		}
	}
};

const getKeyDropDailyCaseData = async () => {
	let axiosConfig = new AxiosConfig({
		url: 'https://key-drop.com/en/apiData/DailyFree/index',
		method: 'get',
		cookies: cookies,
	});

	try {
		const response = await axios.request(axiosConfig.get());

		return response;
	} catch (error) {
		logger('DailyCase', `ERROR data: ${error.message}`, '31');
	}
};

const redeemGoldenCode = async (code, title = '') => {
	logger(`GoldenCode${title}`, `${code} -> redeeming...`);

	//maybe json.stringify needed here on every axiosdata
	let axiosData = {
		"promoCode": code,
		"recaptcha": null,
	};

	let axiosConfig = new AxiosConfig({
		url: 'https://key-drop.com/en/Api/activation_code',
		cookies: cookies,
		data: axiosData,
		additionalHeaders: [{ 'x-requested-with': 'XMLHttpRequest' }],
	});

	axios
		.request(axiosConfig.get())
		.then((response) => {
			if (
				typeof response.data !== 'undefined' &&
				typeof response.data.goldBonus !== 'undefined' &&
				response.data.goldBonus !== null
			) {
				logger(`GoldenCode${title}`, `${code} -> You got ${response.data.goldBonus} Gold!!`, '32');

				keyDropGold = keyDropGold + parseInt(response.data.goldBonus);
				earnedGold = earnedGold + parseInt(response.data.goldBonus);

				procKeyDropGoldCase();
				getKeyDropUserInfo();
			}
			else if (response.data.errorCode !== 'undefined' && response.data.errorCode === 'usedCode') {
				logger(`GoldenCode${title}`, `${code} -> Already used code`, '33');
			}
			else if (response.data.info !== 'undefined' && response.data.info !== '') {
				logger(`GoldenCode${title}`, `${code} -> ${response.data.info}`, '33');
			}
			else {
				logger(`GoldenCode${title}`, `${code} -> No Bonus`, '33');
			}
		})
		.catch((error) => {
			logger(`GoldenCode${title}`, `${code} -> ERROR data: ${error.message}`, '31');
		});
};

const procKeyDropGoldCase = async () => {
	if (
		config.keydrop_goldencases_autoopen_price > 0 &&
		config.auto_goldencases_open === true
	) {
		if (typeof keyDropGoldCase.id !== 'undefined' && keyDropGoldCase.id > 0) {
			if (
				keyDropGold > 0 &&
				keyDropGold >= config.keydrop_goldencases_autoopen_price
			) {

				let axiosData = {
					"id_cat": keyDropGoldCase.id,
					"count": 1,
				};

				let axiosConfig = new AxiosConfig({
					url: 'https://key-drop.com/en/skins/open',
					cookies: cookies,
					data: axiosData,
					additionalHeaders: [{ 'x-requested-with': 'XMLHttpRequest' }],
				});

				axios
					.request(axiosConfig.get())
					.then((response) => {
						if (
							typeof response.data !== 'undefined' &&
							typeof response.data.status !== 'undefined' &&
							response.data.status === true
						) {
							let prizeTxt = '';
							let caseTxt = '';
							let prizeData = typeof response.data.data !== 'undefined' ? response.data.data : [];
							const prizeDataQ = 0 + prizeData?.length;

							for (var i = 0; i < prizeDataQ; i++) {
								if (prizeTxt != '')
									prizeTxt += ' / ';

								if (typeof prizeData[i].title !== 'undefined')
									prizeTxt += prizeData[i].title + ' ';

								if (typeof prizeData[i].subtitle !== 'undefined')
									prizeTxt += prizeData[i].subtitle + ' ';

								if (typeof prizeData[i].price !== 'undefined') {
									prizeTxt += '(' + prizeData[i].price + 'U$D) ';

									earnedCash = earnedCash + parseFloat(prizeData[i].price);
								}
							}


							if (typeof keyDropGoldCase.name !== 'undefined')
								caseTxt = `-> Case ${keyDropGoldCase.name}`;

							if (typeof keyDropGoldCase.price !== 'undefined' && keyDropGoldCase.price > 0)
								keyDropGold = keyDropGold - keyDropGoldCase.price;


							logger(
								'GoldCase',
								`YOU WON!!! :D ${prizeTxt}${caseTxt}`,
								'32',
							);
						} else {
							let msg = (typeof response.data !== 'undefined' && typeof response.data.info !== 'undefined') ? response.data.info : 'unknown response';

							if (msg == 'You do not have enough money in your account! Add funds.')
								keyDropGold = 0;

							logger('GoldCase', `ERROR: ${msg}`, '31');
						}
					})
					.catch((error) => {
						logger('GoldCase', `ERROR data: ${error.message}`, '31');
					});
			}
		}
		else {
			setTimeout(() => {
				procKeyDropGoldCase();
			}, config.retry_interval);
		}
	}
};

class AxiosConfig {
	constructor({
		url = '',
		method = 'post',
		data = '',
		formData = false,
		cookies = '',
		headers = '',
		additionalHeaders = [],
		cloudFlareProtection = true,
	}) {
		this.url = url;
		this.method = method;
		this.data = data;
		this.formData = formData;
		this.cookies = cookies;
		this.headers = headers;
		this.additionalHeaders = additionalHeaders;
		this.cloudFlareProtection = cloudFlareProtection;
	}

	get() {
		let headersArr = {};

		if (this.headers === '' && this.formData === true) {
			headersArr = {
				'accept': '*/*',
				'accept-language': 'en-US,en;q=0.5',
				'accept-encoding': 'gzip, deflate, br',
				'referer': 'https://key-drop.com/en/',
				'origin': 'https://key-drop.com/en/',
				'cookie': this.cookies,
				'user-agent': config.useragent,
				...this.data.getHeaders(),
			};
		} else if (this.headers === '') {
			headersArr = {
				'accept': '*/*',
				'accept-language': 'en-US,en;q=0.5',
				'accept-encoding': 'gzip, deflate, br',
				'referer': 'https://key-drop.com/en/',
				'origin': 'https://key-drop.com/en/',
				'cookie': this.cookies,
				'user-agent': config.useragent,
			};
		}

		if (this.additionalHeaders?.length > 0) {
			for (var i = 0; i < this.additionalHeaders?.length; i++) {
				Object.assign(headersArr, this.additionalHeaders[i]);
			}
		}


		let returnObj = {
			method: this.method,
			maxBodyLength: Infinity,
			url: this.url,
			headers: headersArr,
			httpAgent: httpAgent,
			httpsAgent: httpsAgent,
			data: this.data,
		};

		if (config.proxy_protocol !== '' && config.proxy_host !== '' && config.proxy_port !== '' && (config.puppeteer_proxy == false || this.cloudFlareProtection == false)) {
			let userString = '';

			if (config.proxy_username !== '' && config.proxy_password !== '') {
				userString = config.proxy_username + ':' + config.proxy_password + '@';
			}

			if (config.proxy_protocol === 'http' || config.proxy_protocol === 'https') {
				let newAgent = new HttpsProxyAgent(
					`${config.proxy_protocol}://${userString}${config.proxy_host}:${config.proxy_port}`,
				);

				returnObj.httpsAgent = newAgent;
				returnObj.httpsAgent = newAgent;
			} else if (
				config.proxy_protocol === 'socks' ||
				config.proxy_protocol === 'socks4' ||
				config.proxy_protocol === 'socks5'
			) {
				let newAgent = new SocksProxyAgent(`socks://${userString}${config.proxy_host}:${config.proxy_port}`);

				returnObj.httpsAgent = newAgent;
				returnObj.httpsAgent = newAgent;
			}
		}
		else if (config.puppeteer_proxy == true && this.cloudFlareProtection == true || config.puppeteer_proxy_catch_all == true) {
			returnObj.url = 'http://localhost:' + config.puppeteer_proxy_port + '/?url=' + encodeURI(returnObj.url)
		}

		return returnObj;
	}

	getWithoutHeaders() {
		let returnObj = {
			method: this.method,
			maxBodyLength: Infinity,
			url: this.url,
			httpsAgent: httpsAgent,
			httpAgent: httpAgent,
			data: this.data,
		};

		if (config.puppeteer_proxy == true && this.cloudFlareProtection == true || config.puppeteer_proxy_catch_all == true) {
			returnObj.url = 'http://localhost:' + config.puppeteer_proxy_port + '/?url=' + encodeURI(returnObj.url)
		}

		return returnObj;
	}
}

class GoldCodeManager {
	constructor() {
		this.codeQueue = [];
		this.historyQueue = [];
		this.isRedeeming = false;
	}

	async _redeemNext(title = '') {
		this.isRedeeming = true;
		while (this.codeQueue?.length > 0) {
			let code = this.codeQueue[0];

			redeemGoldenCode(code, title);

			this.codeQueue.shift();
		}
		this.isRedeeming = false;
	}

	redeem(code, title = '') {

		if (!this.historyQueue.includes(code)) {
			this.historyQueue.push(code);
			this.codeQueue.push(code);

			if (!this.isRedeeming) this._redeemNext(title);
		}
		/*
		else {
			logger(`GoldenCode${title}`, `${code} -> already redeemed`, '33');
		}
		*/
	}
}

class BattlesManager {
	constructor() {
		this.idQueue = [];
		this.isFighting = false;
		this.historyQueue = [];
		this.foughtQueue = [];
		this.wonQueue = [];
		this.unFinishedQueue = [];
		this.coolDown = 0;
	}

	async _fightNext() {
		this.isFighting = true;
		while (this.idQueue?.length > 0) {
			let id = this.idQueue[0].id;
			let maxPlayers = this.idQueue[0].maxPlayers;

			fightBattle(id, maxPlayers);
			await wait(2200);

			this.idQueue.shift();
		}
		this.isFighting = false;
	}

	clear() {
		this.idQueue = [];
	}

	spliceUnfinished(id) {
		const index = this.unFinishedQueue.indexOf(id);
		if (index !== -1) {
			this.unFinishedQueue.splice(index, 1);
		}
	}

	fight(id, maxPlayers) {
		if (this.historyQueue?.length > config.keydrop_history_regs) {
			this.historyQueue.shift();
		}

		if (this.foughtQueue?.length > config.keydrop_history_regs) {
			this.foughtQueue.shift();
		}

		if (!this.historyQueue.includes(id)) {
			this.historyQueue.push(id);
			this.idQueue.push({ id: id, maxPlayers: maxPlayers });
			if (!this.isFighting) this._fightNext();
		}
	}
}

class GiveAwaysManager {
	constructor() {
		this.idQueue = [];
		this.isProcessing = false;
		this.historyQueue = [];
		this.wonQueue = [];
		this.joinedHistoryQueue = [];
		this.joinedQueue = [];
		this.maxRetries = config.keydrop_giveaways_retries;
		this.coolDown = 0;
	}

	async _checkNext() {
		this.isProcessing = true;

		while (this.idQueue?.length > 0) {
			let id = this.idQueue[0].id;
			let retries = this.idQueue[0].retries;

			if (retries <= this.maxRetries) {
				let res = await procGiveAway(id, '', retries);

				if (res === 'cooldown') {
					this.idQueue.shift();

					this.spliceHistory(id);

					clearTimeout(intValProcGiveAways);

					logger(
						'GiveAways',
						`Cooldown -> ${seconds2Time(giveawaysmgr.coolDown / 1000)}`,
						'36',
					);

					if (config.keydrop_giveaways_maxrecheck_interval > 0 &&
						giveawaysmgr.coolDown > config.keydrop_giveaways_maxrecheck_interval
					) {
						giveawaysmgr.coolDown = config.keydrop_giveaways_maxrecheck_interval;

						logger('GiveAways', `will recheck in -> ${seconds2Time(giveawaysmgr.coolDown / 1000)}`, '36');
					}



					intValProcGiveAways = setTimeout(
						procKeyDropGiveAways,
						intValRandomness(giveawaysmgr.coolDown),
					);

				} else if (res === 'success' || res === 'joined') {
					this.idQueue.shift();
					this.joinQueue(id);
				} else if (res === 'abort' || (res === 'fail' && retries >= this.maxRetries)) {
					this.idQueue.shift();

					this.spliceHistory(id);
				} else if (res === 'captcha' && retries >= this.maxRetries) {
					this.idQueue.shift();

					if (config.captchakey !== '' && config.captchaservice !== '') {
						const pageUrl = 'https://key-drop.com/en/giveaways/keydrop/' + id;
						const googleKey = '6Ld2uggaAAAAAG9YRZYZkIhCdS38FZYpY9RRYkwN';

						if (config.captchaservice === '2captcha') {
							let captchaClient = new TwoCaptchaClient(config.captchakey, {
								timeout: 45000,
								polling: 5000,
								throwErrors: false,
							});

							captchaClient
								.decodeRecaptchaV2({
									googlekey: googleKey,
									pageurl: pageUrl,
								})
								.then(async (response) => {
									const captchaSolution =
										typeof response !== 'undefined' && typeof response._text !== 'undefined'
											? response._text
											: '';

									if (captchaSolution !== '') {
										procGiveAwayCaptcha(id, captchaSolution, retries);
									} else {
										logger('GiveAways', `${id} -> captcha not solved`, '33');

										giveawaysmgr.spliceHistory(id);
									}
								});
						} else if (config.captchaservice === 'anticaptcha') {
							AntiCaptchaClient.shutUp();
							AntiCaptchaClient.setAPIKey(config.captchakey);

								AntiCaptchaClient.solveRecaptchaV2Proxyless(pageUrl, googleKey)
									.then(async (response) => {
										const captchaSolution = typeof response !== 'undefined' ? response : '';

										if (captchaSolution !== '') {
											procGiveAwayCaptcha(id, captchaSolution, retries);
										} else {
											logger('GiveAways', `${id} -> captcha not solved`, '33');

											giveawaysmgr.spliceHistory(id);
										}
									})
									.catch((error) => {
										logger('GiveAways', `${id} -> captcha not solved`, '33');

										giveawaysmgr.spliceHistory(id);
									});
							/*
							}
							*/
						} else if (config.captchaservice === 'anycaptcha') {
							AnyCaptchaClient.shutUp();
							AnyCaptchaClient.setAPIKey(config.captchakey);

							AnyCaptchaClient.solveRecaptchaV2Proxyless(pageUrl, googleKey)
								.then(async (response) => {
									const captchaSolution = typeof response !== 'undefined' ? response : '';

									if (captchaSolution !== '') {
										procGiveAwayCaptcha(id, captchaSolution, retries);
									} else {
										logger('GiveAways', `${id} -> captcha not solved`, '33');

										giveawaysmgr.spliceHistory(id);
									}
								})
								.catch((error) => {
									logger('GiveAways', `${id} -> captcha not solved`, '33');

									giveawaysmgr.spliceHistory(id);
								});
						} else {
							logger('GiveAways', `${id} -> wrong captcha service`, '31');

							this.spliceHistory(id);
						}
					} else {
						logger('GiveAways', `${id} -> no captcha service`, '31');

						this.spliceHistory(id);
					}

					this._checkNext();
				} else {
					this.idQueue[0].retries++;

					await wait(config.retry_interval);
				}
			} else {
				this.idQueue.shift();
			}
		}

		this.isProcessing = false;
	}

	joinQueue(id) {
		const index = this.joinedQueue.indexOf(id);
		if (index === -1) {
			this.joinedQueue.push(id);
		}

		const indexHist = this.joinedHistoryQueue.indexOf(id);
		if (indexHist === -1) {
			if (this.joinedHistoryQueue?.length > config.keydrop_history_regs) {
				this.joinedHistoryQueue.shift();
			}

			this.joinedHistoryQueue.push(id);
		}
	}

	spliceJoined(id) {
		const index = this.joinedQueue.indexOf(id);
		if (index !== -1) {
			this.joinedQueue.splice(index, 1);
		}
	}

	spliceHistory(id) {
		const historyIndex = this.historyQueue.indexOf(id);
		if (historyIndex !== -1) {
			this.historyQueue.splice(historyIndex, 1);
		}
	}

	async proc(id) {
		if (this.historyQueue?.length > config.keydrop_history_regs) {
			this.historyQueue.shift();
		}

		if (!this.historyQueue.includes(id) && this.coolDown == 0) {
			this.historyQueue.push(id);
			this.idQueue.push({ id: id, retries: 0 });

			await wait(2000); //Adds delay

			if (!this.isProcessing) this._checkNext();
		}
	}
}


if (require.main === module) {
	const cfgParam = process.argv[2];

	run(cfgParam);
}

module.exports = {
	run,
};