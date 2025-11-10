
# BlockStreet Auto Bot 🤖




[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/Xerdrop-seeker/BlockStreet-Auto-bot.svg)](https://github.com/Xerdrop-seeker/BlockStreet-Auto-bot/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Xerdrop-seeker/BlockStreet-Auto-bot.svg)](https://github.com/Xerdrop-seeker/BlockStreet-Auto-bot/network)

**Automated trading bot for BlockStreet platform with multi-wallet support and advanced security**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Configuration](#-configuration)

</div>

## ✨ Features

- 🔄 **Automated Trading** - Execute trades based on predefined strategies
- 👛 **Multi-Wallet Support** - Manage multiple wallets simultaneously
- 🔐 **Security First** - Built-in safety measures and transaction limits
- 🌐 **Proxy Support** - Rotate IP addresses for enhanced privacy
- 📊 **Real-time Monitoring** - Live logging and status updates
- ⚡ **High Performance** - Optimized for speed and reliability
- 🔧 **Customizable** - Easy configuration and strategy adjustments

## 🚀 Quick Start

### Prerequisites

- Ethereum wallet private keys
- 2Captcha API account (for CAPTCHA solving)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Xerdrop-seeker/BlockStreet-Auto-bot.git
   cd BlockStreet-Auto-bot
   ```

2. **Install dependencies**
   ```bash
   npm install 
   ```

3. **Configuration**
   - Add your private keys to `.env`
   - Add your 2Captcha API key to `2captcha.txt`
   - (Optional) Add proxies to `proxies.txt`

4. **Run the bot**
   ```bash
    node main.js
   ```

## 📁 Project Structure

```
BlockStreet-Auto-bot/
├── main.js                 # Main bot application
├── .env      # Wallet private keys
├── 2captcha.txt         # CAPTCHA service API key
├── proxies.txt          # Proxy server list
└── README.md           # Project documentation
```

## ⚙️ Configuration

### Wallet Setup
Format your `.env`:
```
private_key_1
private_key_2
private_key_3
```

### 2Captcha Setup
Add your API key to `2captcha.txt`:
```
your_2captcha_api_key_here
```

### Proxy Setup (Optional)
Add proxies to `proxies.txt`:
```
http://user:pass@host:port
https://user:pass@host:port
host:port:user:pass
```

## 🎯 Usage

Run the main script:
```bash
node main.js
```
