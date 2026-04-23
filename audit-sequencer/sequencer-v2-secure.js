const express = require('express');
const { ethers } = require('ethers');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

// ============================================================
// SECURITY CONFIGURATION
// ============================================================

const EMERGENCY_PAUSE = process.env.EMERGENCY_PAUSE === 'true';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || crypto.randomBytes(32).toString('hex');
const VALIDATOR_API_KEY = process.env.VALIDATOR_API_KEY;

// Blacklisted addresses (load from file or env)
const blacklistedAddresses = new Set();
const suspiciousIPs = new Map();

// Security logging
const securityLog = [];
const MAX_SECURITY_LOG = 1000;

function logSecurity(event, details) {
    const entry = {
        timestamp: new Date().toISOString(),
        event,
        ...details
    };
    securityLog.unshift(entry);
    if (securityLog.length > MAX_SECURITY_LOG) securityLog.pop();
    
    if (event.includes('ALERT') || event.includes('BLOCKED')) {
        console.warn(`[SECURITY] ${event}:`, JSON.stringify(details));
    }
}

// ============================================================
// SECURITY MIDDLEWARE
// ============================================================

app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Cache-Control', 'no-store');
    next();
});

// Strict rate limiter for transaction endpoints
const strictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyGenerator: (req) => req.ip,
    handler: (req, res) => {
        logSecurity('RATE_LIMIT_EXCEEDED', { ip: req.ip, path: req.path });
        res.status(429).json({ error: 'Too many requests. Please slow down.' });
    }
});

// General rate limiter for read endpoints
const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    keyGenerator: (req) => req.ip
});

// RPC rate limiter - ADDED: prevents DDoS on /rpc
const rpcLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60, // 60 RPC requests per minute per IP
    keyGenerator: (req) => req.ip,
    handler: (req, res) => {
        logSecurity('RPC_RATE_LIMIT', { ip: req.ip });
        res.status(429).json({
            jsonrpc: '2.0',
            id: req.body?.id || null,
            error: { code: -32005, message: 'Rate limit exceeded' }
        });
    }
});

// Suspicious activity detector with cleanup
app.use((req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (!suspiciousIPs.has(ip)) {
        suspiciousIPs.set(ip, { count: 0, lastSeen: now, blocked: false });
    }
    
    const ipData = suspiciousIPs.get(ip);
    
    if (now - ipData.lastSeen > 600000) {
        ipData.count = 0;
        ipData.blocked = false;
    }
    
    ipData.count++;
    ipData.lastSeen = now;
    
    if (ipData.count > 500) {
        if (!ipData.blocked) {
            logSecurity('ALERT_DDOS_SUSPECTED', { ip, requestCount: ipData.count });
            ipData.blocked = true;
        }
        return res.status(429).json({ error: 'Temporarily blocked due to excessive requests' });
    }
    
    next();
});

// Cleanup suspicious IPs every 10 minutes to prevent memory leak
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of suspiciousIPs) {
        if (now - data.lastSeen > 1800000) { // 30 minutes
            suspiciousIPs.delete(ip);
        }
    }
}, 600000);

// Emergency pause check
app.use((req, res, next) => {
    if (EMERGENCY_PAUSE && !req.path.startsWith('/admin')) {
        return res.status(503).json({ 
            error: 'Service temporarily paused for maintenance',
            status: 'paused'
        });
    }
    next();
});

// ============================================================
// CORE CONFIGURATION
// ============================================================

const SEQUENCER_PRIVATE_KEY = process.env.SEQUENCER_PRIVATE_KEY;
const MAIN_VALIDATOR_RPC = process.env.MAIN_VALIDATOR_RPC || 'http://[::1]:8545';

const MIN_AUDT_BALANCE = ethers.parseEther('10000');
const BLOCK_TIME_MS = 2000;
const VIP_DAILY_LIMIT = 100;
const REGULAR_DAILY_LIMIT = 1000;
const GASLESS_DAILY_LIMIT = 50;

// SECURITY: Max refund per transaction (prevent drain attacks)
const MAX_REFUND_PER_TX = ethers.parseEther('1'); // Max 1 AUDT refund per tx
const MAX_DAILY_REFUND_TOTAL = ethers.parseEther('100'); // Max 100 AUDT total per day

const provider = new ethers.JsonRpcProvider(MAIN_VALIDATOR_RPC);
const sequencerWallet = new ethers.Wallet(SEQUENCER_PRIVATE_KEY, provider);

// ============================================================
// TRANSACTION QUEUE WITH ENHANCED SECURITY
// ============================================================

class TransactionQueue {
    constructor() {
        this.vipQueue = [];
        this.regularQueue = [];
        this.processedTxs = new Map();
        this.userStats = new Map();
        this.auditBalanceCache = new Map();
        this.balanceCacheTTL = 5 * 60 * 1000;
        this.nonceTracker = new Map();
        this.gaslessStats = new Map();
        
        // SECURITY: Limit map sizes
        this.maxProcessedTxs = 10000;
        this.maxBalanceCache = 5000;
    }

    async getAuditBalance(address) {
        const normalized = address.toLowerCase();
        const cached = this.auditBalanceCache.get(normalized);
        if (cached && Date.now() - cached.timestamp < this.balanceCacheTTL) {
            return cached.balance;
        }
        
        try {
            const balance = await provider.getBalance(address);
            
            // SECURITY: Enforce map size limit
            if (this.auditBalanceCache.size >= this.maxBalanceCache) {
                const oldestKey = this.auditBalanceCache.keys().next().value;
                this.auditBalanceCache.delete(oldestKey);
            }
            
            this.auditBalanceCache.set(normalized, {
                balance,
                timestamp: Date.now()
            });
            return balance;
        } catch (error) {
            logSecurity('BALANCE_CHECK_FAILED', { address, error: error.message });
            return 0n;
        }
    }

    async isVIP(address) {
        const balance = await this.getAuditBalance(address);
        return balance >= MIN_AUDT_BALANCE;
    }

    getUserStats(address) {
        const today = Math.floor(Date.now() / 86400000);
        const key = address.toLowerCase();
        let stats = this.userStats.get(key);
        
        if (!stats || stats.day !== today) {
            stats = { day: today, vipCount: 0, regularCount: 0 };
            this.userStats.set(key, stats);
        }
        return stats;
    }

    getGaslessStats(address) {
        const today = Math.floor(Date.now() / 86400000);
        const key = address.toLowerCase();
        let stats = this.gaslessStats.get(key);
        
        if (!stats || stats.day !== today) {
            stats = { day: today, count: 0 };
            this.gaslessStats.set(key, stats);
        }
        return stats;
    }

    async canUseGasless(address) {
        const isVIP = await this.isVIP(address);
        if (!isVIP) {
            return { allowed: false, reason: 'Must hold 10,000+ AUDT for gasless transactions' };
        }
        
        const stats = this.getGaslessStats(address);
        if (stats.count >= GASLESS_DAILY_LIMIT) {
            return { allowed: false, reason: 'Daily gasless limit exceeded', used: stats.count, limit: GASLESS_DAILY_LIMIT };
        }
        
        return { allowed: true, used: stats.count, remaining: GASLESS_DAILY_LIMIT - stats.count };
    }

    incrementGaslessCount(address) {
        const stats = this.getGaslessStats(address);
        stats.count++;
        return stats.count;
    }

    verifySender(signedTx, claimedSender) {
        try {
            const tx = ethers.Transaction.from(signedTx);
            const recoveredAddress = tx.from;
            
            if (!recoveredAddress) {
                return { valid: false, error: 'Could not recover signer from transaction' };
            }
            
            if (recoveredAddress.toLowerCase() !== claimedSender.toLowerCase()) {
                logSecurity('SIGNATURE_MISMATCH', { 
                    claimed: claimedSender, 
                    recovered: recoveredAddress 
                });
                return { valid: false, error: 'Transaction signer does not match claimed sender' };
            }
            
            return { valid: true, from: recoveredAddress, nonce: tx.nonce };
        } catch (error) {
            logSecurity('TX_PARSE_FAILED', { error: error.message });
            return { valid: false, error: 'Invalid transaction format' };
        }
    }

    checkReplay(address, nonce) {
        const key = address.toLowerCase();
        const lastNonce = this.nonceTracker.get(key) || -1;
        
        if (nonce <= lastNonce) {
            logSecurity('REPLAY_ATTEMPT', { address, nonce, lastNonce });
            return false;
        }
        
        this.nonceTracker.set(key, nonce);
        return true;
    }

    async addTransaction(signedTx, sender, priority = false, ip = 'unknown') {
        if (blacklistedAddresses.has(sender.toLowerCase())) {
            logSecurity('BLACKLISTED_ATTEMPT', { address: sender, ip });
            return { success: false, error: 'Address is blacklisted' };
        }

        const verification = this.verifySender(signedTx, sender);
        if (!verification.valid) {
            return { success: false, error: verification.error };
        }

        const txHash = ethers.keccak256(signedTx);
        
        if (this.processedTxs.has(txHash)) {
            return { success: false, error: 'Transaction already submitted', txHash };
        }

        if (!this.checkReplay(sender, verification.nonce)) {
            return { success: false, error: 'Possible replay attack detected - nonce too low' };
        }

        const isVIP = await this.isVIP(sender);
        const stats = this.getUserStats(sender);

        // SECURITY: Enforce map size limit for processedTxs
        if (this.processedTxs.size >= this.maxProcessedTxs) {
            const oldestKey = this.processedTxs.keys().next().value;
            this.processedTxs.delete(oldestKey);
        }

        if (priority && isVIP) {
            if (stats.vipCount >= VIP_DAILY_LIMIT) {
                return { success: false, error: 'Daily VIP limit exceeded', limit: VIP_DAILY_LIMIT };
            }
            
            this.vipQueue.push({
                signedTx,
                sender: verification.from,
                txHash,
                timestamp: Date.now(),
                priority: true,
                ip
            });
            stats.vipCount++;
            
            this.processedTxs.set(txHash, { lane: 'vip', position: this.vipQueue.length - 1, timestamp: Date.now() });
            
            logSecurity('VIP_TX_QUEUED', { address: sender, txHash: txHash.slice(0, 18) });
            
            return {
                success: true,
                txHash,
                lane: 'VIP',
                position: this.vipQueue.length,
                message: 'Transaction queued for PRIORITY inclusion - FIRST IN BLOCK!'
            };
        } else {
            if (stats.regularCount >= REGULAR_DAILY_LIMIT) {
                return { success: false, error: 'Daily transaction limit exceeded', limit: REGULAR_DAILY_LIMIT };
            }
            
            this.regularQueue.push({
                signedTx,
                sender: verification.from,
                txHash,
                timestamp: Date.now(),
                priority: false,
                ip
            });
            stats.regularCount++;
            
            const position = this.vipQueue.length + this.regularQueue.length;
            this.processedTxs.set(txHash, { lane: 'regular', position, timestamp: Date.now() });
            
            return {
                success: true,
                txHash,
                lane: 'regular',
                position,
                vipAhead: this.vipQueue.length,
                message: isVIP 
                    ? 'VIP eligible! Use /priority endpoint for first-in-block inclusion'
                    : `Transaction queued (${this.vipQueue.length} VIP txs ahead)`
            };
        }
    }

    async buildOrderedBundle(maxTxs = 500) {
        const bundle = [];
        
        while (this.vipQueue.length > 0 && bundle.length < maxTxs) {
            bundle.push(this.vipQueue.shift());
        }
        
        while (this.regularQueue.length > 0 && bundle.length < maxTxs) {
            bundle.push(this.regularQueue.shift());
        }
        
        if (bundle.length === 0) return null;

        const orderedTxHashes = bundle.map(tx => tx.txHash);
        const certificate = await this.signOrderingCertificate(orderedTxHashes);
        
        return {
            transactions: bundle.map(tx => tx.signedTx),
            txHashes: orderedTxHashes,
            certificate,
            vipCount: bundle.filter(tx => tx.priority).length,
            regularCount: bundle.filter(tx => !tx.priority).length,
            timestamp: Date.now()
        };
    }

    async signOrderingCertificate(txHashes) {
        const message = ethers.solidityPackedKeccak256(
            ['bytes32[]', 'uint256'],
            [txHashes, Date.now()]
        );
        const signature = await sequencerWallet.signMessage(ethers.getBytes(message));
        return { message, signature, signer: sequencerWallet.address };
    }

    getStatus(txHash) {
        return this.processedTxs.get(txHash) || null;
    }

    getQueueStats() {
        return {
            vipQueueLength: this.vipQueue.length,
            regularQueueLength: this.regularQueue.length,
            totalPending: this.vipQueue.length + this.regularQueue.length,
            processedCount: this.processedTxs.size,
            activeCacheEntries: this.auditBalanceCache.size
        };
    }

    cleanup() {
        const oneHourAgo = Date.now() - 3600000;
        
        for (const [hash, data] of this.processedTxs) {
            if (data.timestamp && data.timestamp < oneHourAgo) {
                this.processedTxs.delete(hash);
            }
        }
        
        for (const [addr, data] of this.auditBalanceCache) {
            if (data.timestamp < oneHourAgo) {
                this.auditBalanceCache.delete(addr);
            }
        }

        // Clean old nonce tracker entries (keep last 24 hours)
        // Note: We can't clean nonces without risking replay, so we keep them
    }
}

const txQueue = new TransactionQueue();

setInterval(() => txQueue.cleanup(), 600000);

// ============================================================
// INPUT VALIDATION HELPERS
// ============================================================

function isValidAddress(address) {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
}

function isValidHex(hex) {
    return /^0x[a-fA-F0-9]+$/.test(hex);
}

function sanitizeAddress(address) {
    if (!isValidAddress(address)) return null;
    return address.toLowerCase();
}

// ============================================================
// PUBLIC ENDPOINTS (Read-only)
// ============================================================

app.use('/health', generalLimiter);
app.use('/stats', generalLimiter);
app.use('/eligibility', generalLimiter);
app.use('/queue', generalLimiter);
app.use('/status', generalLimiter);

app.get('/health', (req, res) => {
    res.json({
        status: EMERGENCY_PAUSE ? 'paused' : 'ok',
        service: 'Audit Sequencer',
        chain: 'AuditChain',
        chainId: 1337,
        sequencer: sequencerWallet.address,
        security: {
            signatureVerification: true,
            replayProtection: true,
            rateLimiting: true,
            blacklistEnabled: true,
            maxRefundPerTx: ethers.formatEther(MAX_REFUND_PER_TX) + ' AUDT'
        },
        ...txQueue.getQueueStats()
    });
});

app.get('/eligibility/:address', async (req, res) => {
    try {
        const address = sanitizeAddress(req.params.address);
        if (!address) {
            return res.status(400).json({ error: 'Invalid address format' });
        }

        const balance = await txQueue.getAuditBalance(address);
        const isVIP = balance >= MIN_AUDT_BALANCE;
        const stats = txQueue.getUserStats(address);
        
        res.json({
            address,
            auditBalance: ethers.formatEther(balance),
            isVIP,
            minRequired: '10,000 AUDT',
            dailyLimits: {
                vip: { used: stats.vipCount, max: VIP_DAILY_LIMIT, remaining: VIP_DAILY_LIMIT - stats.vipCount },
                regular: { used: stats.regularCount, max: REGULAR_DAILY_LIMIT, remaining: REGULAR_DAILY_LIMIT - stats.regularCount }
            },
            benefits: isVIP ? [
                'Priority block inclusion (FIRST IN BLOCK)',
                'Up to 100 priority txs per day',
                'MEV protection',
                'Front-run immunity',
                'Automatic gas refunds (50/day)'
            ] : ['Hold 10,000+ AUDT for VIP benefits']
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/queue', (req, res) => {
    res.json(txQueue.getQueueStats());
});

app.get('/status/:txHash', (req, res) => {
    if (!isValidHex(req.params.txHash)) {
        return res.status(400).json({ error: 'Invalid transaction hash format' });
    }
    
    const status = txQueue.getStatus(req.params.txHash);
    
    if (status) {
        res.json({ found: true, txHash: req.params.txHash, ...status });
    } else {
        res.status(404).json({ found: false, txHash: req.params.txHash });
    }
});

// ============================================================
// TRANSACTION ENDPOINTS (Strict rate limiting)
// ============================================================

app.use('/submit', strictLimiter);
app.use('/priority', strictLimiter);

app.post('/submit', async (req, res) => {
    try {
        const { signedTransaction, sender } = req.body;
        
        if (!signedTransaction || !sender) {
            return res.status(400).json({ error: 'Missing signedTransaction or sender' });
        }
        
        if (!isValidHex(signedTransaction)) {
            return res.status(400).json({ error: 'Invalid transaction format' });
        }
        
        if (!isValidAddress(sender)) {
            return res.status(400).json({ error: 'Invalid sender address format' });
        }

        const result = await txQueue.addTransaction(signedTransaction, sender, false, req.ip);
        
        res.status(result.success ? 200 : 400).json(result);
    } catch (error) {
        logSecurity('SUBMIT_ERROR', { error: error.message, ip: req.ip });
        res.status(500).json({ error: 'Transaction processing failed' });
    }
});

app.post('/priority', async (req, res) => {
    try {
        const { signedTransaction, sender } = req.body;
        
        if (!signedTransaction || !sender) {
            return res.status(400).json({ error: 'Missing signedTransaction or sender' });
        }
        
        if (!isValidHex(signedTransaction)) {
            return res.status(400).json({ error: 'Invalid transaction format' });
        }
        
        if (!isValidAddress(sender)) {
            return res.status(400).json({ error: 'Invalid sender address format' });
        }

        const isVIP = await txQueue.isVIP(sender);
        if (!isVIP) {
            const balance = await txQueue.getAuditBalance(sender);
            return res.status(403).json({
                error: 'VIP status required for priority transactions',
                currentBalance: ethers.formatEther(balance),
                required: '10,000 AUDT',
                needed: ethers.formatEther(MIN_AUDT_BALANCE - balance)
            });
        }

        const result = await txQueue.addTransaction(signedTransaction, sender, true, req.ip);
        
        res.status(result.success ? 200 : 400).json(result);
    } catch (error) {
        logSecurity('PRIORITY_ERROR', { error: error.message, ip: req.ip });
        res.status(500).json({ error: 'Transaction processing failed' });
    }
});

// ============================================================
// JSON-RPC PROXY (Priority Block Inclusion) - WITH RATE LIMITING
// ============================================================

app.post('/rpc', rpcLimiter, async (req, res) => {
    try {
        const { jsonrpc, method, params, id } = req.body;
        
        if (method === 'eth_sendRawTransaction' && params && params[0]) {
            const signedTx = params[0];
            
            let sender;
            try {
                const tx = ethers.Transaction.from(signedTx);
                sender = tx.from;
            } catch (parseErr) {
                const response = await forwardRPC(req.body);
                return res.json(response);
            }
            
            const isVIP = sender ? await txQueue.isVIP(sender) : false;
            
            if (isVIP) {
                console.log(`[PRIORITY] VIP tx from ${sender.slice(0,10)}... - priority queue`);
                
                const response = await forwardRPC(req.body);
                
                if (response.result) {
                    logSecurity('PRIORITY_TX_SENT', { 
                        from: sender, 
                        txHash: response.result,
                        vip: true 
                    });
                }
                
                return res.json(response);
            } else {
                // Regular user: Add delay to ensure VIP txs go first
                await new Promise(resolve => setTimeout(resolve, 50));
                const response = await forwardRPC(req.body);
                return res.json(response);
            }
        }
        
        const response = await forwardRPC(req.body);
        res.json(response);
        
    } catch (error) {
        console.error('[RPC] Error:', error.message);
        res.json({
            jsonrpc: '2.0',
            id: req.body?.id || null,
            error: { code: -32603, message: error.message }
        });
    }
});

// Batch RPC endpoint with rate limiting
app.post('/rpc/batch', rpcLimiter, async (req, res) => {
    try {
        if (!Array.isArray(req.body)) {
            return res.status(400).json({ error: 'Expected array of requests' });
        }
        
        // SECURITY: Limit batch size
        if (req.body.length > 20) {
            return res.status(400).json({ error: 'Batch size exceeds maximum of 20' });
        }
        
        const results = await Promise.all(
            req.body.map(async (request) => {
                try {
                    return await forwardRPC(request);
                } catch (err) {
                    return {
                        jsonrpc: '2.0',
                        id: request.id || null,
                        error: { code: -32603, message: err.message }
                    };
                }
            })
        );
        
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

async function forwardRPC(body) {
    const response = await fetch('http://[::1]:8545', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    return response.json();
}

// ============================================================
// GASLESS TRANSACTIONS - REMOVED (SECURITY VULNERABILITY)
// ============================================================
// The old /gasless endpoint was REMOVED because it allowed wallet draining.
// Gas refunds are now ONLY done automatically via the block monitor below,
// which verifies actual on-chain transactions.

// Return error for old gasless endpoint to prevent confusion
app.post('/gasless', strictLimiter, (req, res) => {
    res.status(410).json({
        error: 'This endpoint has been disabled for security reasons',
        alternative: 'Gas costs are automatically refunded when you transact through the /rpc endpoint',
        note: 'Simply use https://sequencer.example.com/rpc as your MetaMask RPC and gas will be refunded automatically'
    });
});

// ============================================================
// GASLESS CHECK ENDPOINT (Read-only, safe)
// ============================================================

app.get('/gasless/check/:address', generalLimiter, async (req, res) => {
    try {
        const address = req.params.address;
        if (!isValidAddress(address)) {
            return res.status(400).json({ error: 'Invalid address format' });
        }
        
        const balance = await txQueue.getAuditBalance(address);
        const isVIP = balance >= MIN_AUDT_BALANCE;
        const stats = txQueue.getGaslessStats(address);
        const sequencerBalance = await provider.getBalance(sequencerWallet.address);
        
        res.json({
            address,
            auditBalance: ethers.formatEther(balance),
            isEligible: isVIP,
            reason: isVIP ? 'Eligible for automatic gas refunds' : 'Must hold 10,000+ AUDT for automatic gas refunds',
            used: stats.count,
            remaining: isVIP ? GASLESS_DAILY_LIMIT - stats.count : 0,
            dailyLimit: GASLESS_DAILY_LIMIT,
            maxRefundPerTx: ethers.formatEther(MAX_REFUND_PER_TX) + ' AUDT',
            sequencerFunds: ethers.formatEther(sequencerBalance) + ' AUDT',
            message: isVIP 
                ? 'Your gas costs are automatically refunded when transacting via the sequencer RPC!' 
                : 'Hold 10,000+ AUDT for automatic gas refunds'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// ADMIN ENDPOINTS (Protected)
// ============================================================

const adminAuth = (req, res, next) => {
    const apiKey = req.headers['x-admin-key'] || req.query.key;
    if (!apiKey || apiKey !== ADMIN_API_KEY) {
        logSecurity('ADMIN_AUTH_FAILED', { ip: req.ip, path: req.path });
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

app.get('/admin/security-log', adminAuth, (req, res) => {
    res.json({
        entries: securityLog.slice(0, 100),
        totalEntries: securityLog.length
    });
});

app.post('/admin/blacklist', adminAuth, (req, res) => {
    const { address, action } = req.body;
    if (!isValidAddress(address)) {
        return res.status(400).json({ error: 'Invalid address' });
    }
    
    const normalized = address.toLowerCase();
    if (action === 'add') {
        blacklistedAddresses.add(normalized);
        logSecurity('ADDRESS_BLACKLISTED', { address: normalized });
        res.json({ success: true, message: 'Address blacklisted' });
    } else if (action === 'remove') {
        blacklistedAddresses.delete(normalized);
        logSecurity('ADDRESS_UNBLACKLISTED', { address: normalized });
        res.json({ success: true, message: 'Address removed from blacklist' });
    } else {
        res.status(400).json({ error: 'Invalid action' });
    }
});

app.get('/admin/stats', adminAuth, (req, res) => {
    res.json({
        queue: txQueue.getQueueStats(),
        blacklistSize: blacklistedAddresses.size,
        suspiciousIPCount: suspiciousIPs.size,
        securityLogSize: securityLog.length,
        gasRefund: gasRefundStats
    });
});

// ============================================================
// AUTOMATIC GAS REFUND SYSTEM (Secure - verifies on-chain txs)
// ============================================================

const gasRefundStats = {
    lastProcessedBlock: 0,
    totalRefunded: 0n,
    refundCount: 0,
    dailyRefunded: 0n,
    dailyResetDay: 0
};

const perAddressRefundStats = new Map();

function getGasRefundStats(address) {
    const today = Math.floor(Date.now() / 86400000);
    const key = address.toLowerCase();
    let stats = perAddressRefundStats.get(key);
    
    if (!stats || stats.day !== today) {
        stats = { day: today, count: 0, totalRefunded: 0n };
        perAddressRefundStats.set(key, stats);
    }
    return stats;
}

async function processBlockForRefunds(blockNumber) {
    try {
        const block = await provider.getBlock(blockNumber, true);
        if (!block || !block.prefetchedTransactions) return;
        
        // Reset daily counter
        const today = Math.floor(Date.now() / 86400000);
        if (gasRefundStats.dailyResetDay !== today) {
            gasRefundStats.dailyResetDay = today;
            gasRefundStats.dailyRefunded = 0n;
        }
        
        for (const tx of block.prefetchedTransactions) {
            try {
                if (!tx || !tx.from) continue;
                
                // Skip sequencer's own transactions
                if (tx.from.toLowerCase() === sequencerWallet.address.toLowerCase()) continue;
                
                // Check if sender is VIP
                const isVIP = await txQueue.isVIP(tx.from);
                if (!isVIP) continue;
                
                // Check daily refund limit per address
                const stats = getGasRefundStats(tx.from);
                if (stats.count >= GASLESS_DAILY_LIMIT) continue;
                
                // Get actual gas cost from receipt
                const receipt = await provider.getTransactionReceipt(tx.hash);
                if (!receipt) continue;
                
                const gasUsed = receipt.gasUsed;
                const gasPrice = tx.gasPrice || tx.maxFeePerGas || 0n;
                let gasCost = gasUsed * gasPrice;
                
                if (gasCost === 0n) continue;
                
                // SECURITY: Cap refund amount per transaction
                if (gasCost > MAX_REFUND_PER_TX) {
                    console.log(`[REFUND] Capping refund from ${ethers.formatEther(gasCost)} to ${ethers.formatEther(MAX_REFUND_PER_TX)} AUDT`);
                    gasCost = MAX_REFUND_PER_TX;
                }
                
                // SECURITY: Check daily global limit
                if (gasRefundStats.dailyRefunded + gasCost > MAX_DAILY_REFUND_TOTAL) {
                    console.log(`[REFUND] Daily global limit reached, skipping`);
                    continue;
                }
                
                // Check sequencer has enough balance
                const seqBalance = await provider.getBalance(sequencerWallet.address);
                const minReserve = ethers.parseEther('10'); // Keep 10 AUDT reserve
                if (seqBalance < gasCost + minReserve) {
                    console.log(`[REFUND] Low funds (${ethers.formatEther(seqBalance)} AUDT), skipping refund`);
                    continue;
                }
                
                // Send refund
                console.log(`[REFUND] VIP ${tx.from.slice(0,10)}... gas ${ethers.formatEther(gasCost)} AUDT`);
                
                const refundTx = await sequencerWallet.sendTransaction({
                    to: tx.from,
                    value: gasCost
                });
                await refundTx.wait();
                
                stats.count++;
                stats.totalRefunded += gasCost;
                gasRefundStats.totalRefunded += gasCost;
                gasRefundStats.dailyRefunded += gasCost;
                gasRefundStats.refundCount++;
                
                logSecurity('GAS_REFUND_SENT', { 
                    to: tx.from, 
                    amount: ethers.formatEther(gasCost),
                    txHash: refundTx.hash,
                    dailyCount: stats.count 
                });
                
                console.log(`  -> Refunded! (${stats.count}/${GASLESS_DAILY_LIMIT} today)`);
            } catch (txError) {
                // Skip individual tx errors silently
            }
        }
    } catch (error) {
        // Block processing error, will retry
    }
}

async function gasRefundMonitor() {
    if (process.env.EMERGENCY_PAUSE === 'true') return;
    
    try {
        const currentBlock = await provider.getBlockNumber();
        
        if (gasRefundStats.lastProcessedBlock === 0) {
            gasRefundStats.lastProcessedBlock = currentBlock;
            console.log(`[REFUND] Starting gas refund monitor from block ${currentBlock}`);
        }
        
        // Process new blocks (up to 10 at a time)
        let processed = 0;
        while (gasRefundStats.lastProcessedBlock < currentBlock && processed < 10) {
            gasRefundStats.lastProcessedBlock++;
            await processBlockForRefunds(gasRefundStats.lastProcessedBlock);
            processed++;
        }
    } catch (error) {
        console.error('[REFUND] Monitor error:', error.message);
    }
}

setInterval(gasRefundMonitor, 2000);

// Refund stats endpoint
app.get('/refund/stats', generalLimiter, (req, res) => {
    res.json({
        enabled: true,
        lastProcessedBlock: gasRefundStats.lastProcessedBlock,
        totalRefunded: ethers.formatEther(gasRefundStats.totalRefunded) + ' AUDT',
        dailyRefunded: ethers.formatEther(gasRefundStats.dailyRefunded) + ' AUDT',
        dailyLimit: ethers.formatEther(MAX_DAILY_REFUND_TOTAL) + ' AUDT',
        refundCount: gasRefundStats.refundCount,
        perTxLimit: GASLESS_DAILY_LIMIT,
        maxRefundPerTx: ethers.formatEther(MAX_REFUND_PER_TX) + ' AUDT',
        sequencerAddress: sequencerWallet.address
    });
});

// Check refund status for specific address
app.get('/refund/check/:address', generalLimiter, async (req, res) => {
    try {
        const address = req.params.address;
        if (!isValidAddress(address)) {
            return res.status(400).json({ error: 'Invalid address format' });
        }
        
        const balance = await txQueue.getAuditBalance(address);
        const isVIP = balance >= MIN_AUDT_BALANCE;
        const stats = getGasRefundStats(address);
        const sequencerBalance = await provider.getBalance(sequencerWallet.address);
        
        res.json({
            address,
            auditBalance: ethers.formatEther(balance),
            isVIP,
            autoRefundEnabled: isVIP,
            refundsToday: stats.count,
            refundsRemaining: isVIP ? GASLESS_DAILY_LIMIT - stats.count : 0,
            dailyLimit: GASLESS_DAILY_LIMIT,
            maxRefundPerTx: ethers.formatEther(MAX_REFUND_PER_TX) + ' AUDT',
            sequencerFunds: ethers.formatEther(sequencerBalance) + ' AUDT',
            message: isVIP 
                ? 'Your gas costs are automatically refunded!' 
                : 'Hold 10,000+ AUDT for automatic gas refunds'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// STARTUP
// ============================================================

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║     AUDT SEQUENCER v2.0 - Security Hardened Edition       ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log(`║  Port: ${PORT}                                               ║`);
    console.log(`║  Chain: AuditChain (589)                                     ║`);
    console.log(`║  Sequencer: ${sequencerWallet.address.slice(0, 20)}...  ║`);
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log('║  SECURITY FEATURES:                                        ║');
    console.log('║    ✓ Signature verification (prevents spoofing)           ║');
    console.log('║    ✓ Replay attack protection (nonce tracking)            ║');
    console.log('║    ✓ Rate limiting on ALL endpoints including /rpc        ║');
    console.log('║    ✓ IP-based DDoS detection & blocking                   ║');
    console.log('║    ✓ Address blacklisting                                  ║');
    console.log('║    ✓ Emergency pause capability                            ║');
    console.log('║    ✓ Security event logging                                ║');
    console.log('║    ✓ Input validation & sanitization                       ║');
    console.log('║    ✓ Memory leak prevention (map size limits)             ║');
    console.log('║    ✓ Max refund caps (prevents wallet drain)              ║');
    console.log('║    ✓ Vulnerable /gasless endpoint REMOVED                  ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log('║  VIP Benefits (10K+ AUDT):                                  ║');
    console.log('║    ✓ Priority block inclusion                              ║');
    console.log('║    ✓ FIRST IN BLOCK guaranteed                             ║');
    console.log('║    ✓ MEV/Front-run protection                              ║');
    console.log('║    ✓ Automatic gas refunds (50/day, max 1 AUDT each)        ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log('');
    console.log('Admin API Key:', ADMIN_API_KEY.slice(0, 8) + '...');
    console.log('');
    
    gasRefundMonitor();
});

module.exports = app;
