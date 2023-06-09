<p align="center">
  <img src="https://img.shields.io/github/downloads/nan4k7/KeydropAutocode/total?style=for-the-badge&logo=appveyor">
  <img src="https://img.shields.io/github/stars/nan4k7/KeydropAutocode?style=for-the-badge&logo=appveyor">
</p>

### 1. Configuration

If you change any communication with discord you might break the app.

1.1 discord_bot_token - This is a token from my bot that can send you messages with mentions whenewer you win. (To add bot to your discord server: https://discord.com/api/oauth2/authorize?client_id=1093672943864782920&permissions=292057791488&scope=bot)
1.2 discord_bot_channel - The channel id of your server to publish wins.
1.3 discord_bot_mention_user_id - Your user id if you want to get mentioned in messages.

1.4 discord_bot_gold_token - This is used to communicate with discord and get gold codes.
1.5 discord_bot_gold_id - Used to communicate with discord.
1.6 discord_golden_code_channels - Used to communicate with discord.

1.7 captchakey - Your personal API key of your captcha service
1.8 captchaservice - Captcha service. Available options are: [2captcha, anticaptcha, anycaptcha]
1.9 useragent - Changes the useragent of the app. Should be matched with the browser from which you took your cookies (if not you'll receive 403)

1.10 webinterface - Enable to have a web interface show your log file
1.11 webinterface_port - Set the port for the local interface
1.12 webinterface_user - Set a username for the web interface
1.13 webinterface_pass - Set a password for the web interface

1.15 puppeteer_proxy - Used to send request's via a local puppeteer proxy and avoid cloudflare protection
1.16 puppeteer_proxy_port - Port used to run local pup proxy
1.17 puppeteer_proxy_catch_all - If set to true al requests will be sent via puppeteer. If set false it will send normal requests via axios (faster).
1.18 puppeteer_headless - Headless value for puppeteer instance. Available options are: [true, false, "new"].
1.19 puppeteer_chrome_location - Specific location to run chrome from if you don't want to use bundled version.

1.20 proxy_host - Proxy host (if necessary).
1.21 proxy_port - Proxy port (if necessary).
1.22 proxy_protocol - Proxy protocol (if necessary). Available options are: ["http", "https", "socks"].
1.23 proxy_username - Proxy username (if necessary).
1.24 proxy_password - Proxy password (if necessary).
1.25 connection_retries - Number of retries to be made on connections before giving error.

1.30 keydrop_cookie_file - KeyDrop Cookies filename. Learn how to get contents on next section.

1.40 auto_goldencodes - Process Golden Codes automatically.
1.41 auto_goldencases_open - Will open golden cases automatically when reached the price specified in "keydrop_goldencases_autoopen_price".
1.42 auto_battletickets - Process battle tickets automatically.
1.43 auto_giveaways - Process giveaways automatically.
1.44 auto_dailycase - Redeem Daily case automatically.

1.50 keydrop_userinfo_interval - interval in ms to refresh user info.
1.51 keydrop_token_interval - interval in ms to refresh token.
1.52 keydrop_giveaways_interval - interval in ms to refresh giveaways.
1.53 keydrop_giveaways_results_interval - interval in ms to look for giveaways results.
1.54 keydrop_giveaways_maxrecheck_interval - max interval in ms to wait for giveaways cooldown.
1.54 keydrop_battles_wscon_interval - interval in ms to retry connection to battles websocket service.
1.55 keydrop_battles_results_interval - interval in ms to look for unfinished battle results.
1.56 keydrop_dailycase_interval - interval in ms to look for daily case.
1.57 keydrop_dailycase_maxrecheck_interval - max interval in ms to wait for next daily case recheck.
1.58 keydrop_goldcode_history_interval - interval in ms to look for history codes on the golden channel.
1.59 keydrop_goldcode_expire_interval - max time in ms an old gold takes to expire and don't try to redeem it.

1.60 keydrop_battles_minprice - Used to look for battles of more than minprice.
1.61 keydrop_battles_maxusercount - Used to determine wich battles to look for. Available options are: [2, 3, 4]. Array of parameters.
1.62 keydrop_battles_cases_avoid - An array of cases names to avoid while looking for battles.
1.63 keydrop_giveaways_retries - Number of retries to do before leaving the giveaway after next proc (if available).
1.64 keydrop_giveaways_minprize - Minimun prize of a giveaway to be joined.
1.65 keydrop_goldencases_autoopen_price - Will autoopen golden cases of this price when gold reaches the value. If the value specified does not have a valid case it will open the nearest below.

### 2. Cookies

In order to use the app you will need to get your cookies. One way of doing that is to install [this chrome extension](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg). and then go to Keydrop.com.

Once logged in press on the puzzle piece to reveal the chrome extension which is located in the right corner of chrome and press on the extension 'EditThisCookie'.

A popup should appear. Go to settings and change your prefered export format for cookies to 'Netscape HTTP Cookie file'

Press the export button and paste the copied items on a txt file under the cookies folder (default name -> cookie.txt ).

There's a cookie.sample.txt file inside the cookies folder which can guide you with the expected results.

You should remove all cookies (there's one per line) except for:
\_\_vioShield
session_id
key-lang

Cookies expire, you will need to refresh them once per 24/h.
However they will not expire while the program is running.

### 3. User Agent

3.1 If after placing your cookies you still receive 403 ERROR it may be necessary to replace useragent setting in config.json for the user agent from where you extracted your coookies (Basically your browser).

### 4. Running the app

4.1 Run keydrop-bot.exe in order to run the app. May be neccesary to build with npm run build.
4.2 Settings are located on config.default.json

4.3 Run app via cmd : Open a cmd, type `cd` followed by the path of the folder then type `node app.js`
