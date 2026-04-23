require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const { monitorDeposits } = require('./services/bridgeMonitor');
const { startCompetitionIndexer } = require('./services/competitionIndexer');
const { startMonitoring: startPoolRegistrar } = require('./services/poolRegistrar');
const { createIntent, getIntent, getLeaderboard, getUserRank, getCompetitionStats } = require('./db');
const { PublicKey } = require('@solana/web3.js');
const { ethers } = require('ethers');
const v3LockerRoutes = require('./routes/v3-locker.js');

const app = express();
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === 'production';

const apiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 2000,
  message: 'Too many requests, please try again later'
});

app.use(cors());
app.use(express.json());
app.use('/api/', apiLimiter);

// V3 NFT Position Locker routes
app.use('/api/v3-locker', v3LockerRoutes);

// Health check endpoint - deployment can ping this for status
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: Date.now() });
});

if (isProduction) {
  // Serve frontend static files with caching disabled for fresh updates
  app.use(express.static(path.join(__dirname, '../frontend/dist'), {
    maxAge: 0,
    etag: false
  }));
}

app.get('/api/bridge/info', async (req, res) => {
  try {
    const { getCustodialBalances } = require('./services/bridgeMonitor');
    const balances = await getCustodialBalances();
    
    res.json({
      solanaWallet: process.env.SOLANA_CUSTODIAL_PUBLIC,
      auditchainWallet: process.env.AUDITCHAIN_CUSTODIAL_PUBLIC,
      exchangeRate: '1.0',
      auditsolMint: 'G782hdAKxXiceuYMEAsTjv1nzf2JNtHw1khdWsQHYyCR',
      wauditAddress: '0x0000000000000000000000000000000000000010',
      auditsolBalance: balances.auditsol,
      wauditBalance: balances.waudit,
      auditsolPrice: '0.00',
      wauditPrice: '0.00',
      status: 'active'
    });
  } catch (error) {
    console.error('Error getting bridge info:', error);
    res.status(500).json({ error: 'Failed to get bridge info' });
  }
});

function isValidSolanaAddress(address) {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
}

function isValidAuditchainAddress(address) {
  return ethers.isAddress(address);
}

app.post('/api/bridge/create-intent', (req, res) => {
  try {
    const { direction, sourceAddress, destAddress, amount } = req.body;
    
    if (!direction || !sourceAddress || !destAddress || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (direction !== 'sol-to-waudit' && direction !== 'waudit-to-sol') {
      return res.status(400).json({ error: 'Invalid direction' });
    }
    
    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    
    if (direction === 'sol-to-waudit') {
      if (!isValidSolanaAddress(sourceAddress)) {
        return res.status(400).json({ error: 'Invalid Solana source address' });
      }
      if (!isValidAuditchainAddress(destAddress)) {
        return res.status(400).json({ error: 'Invalid AuditChain destination address' });
      }
    } else {
      if (!isValidAuditchainAddress(sourceAddress)) {
        return res.status(400).json({ error: 'Invalid AuditChain source address' });
      }
      if (!isValidSolanaAddress(destAddress)) {
        return res.status(400).json({ error: 'Invalid Solana destination address' });
      }
    }
    
    const rate = '1.0';
    const intentId = createIntent(direction, sourceAddress, destAddress, amount, rate);
    
    res.json({
      intentId,
      depositAddress: direction === 'sol-to-waudit' 
        ? process.env.SOLANA_CUSTODIAL_PUBLIC 
        : process.env.AUDITCHAIN_CUSTODIAL_PUBLIC,
      amount,
      rate,
      memo: intentId
    });
  } catch (error) {
    console.error('Error creating intent:', error);
    res.status(500).json({ error: 'Failed to create swap intent' });
  }
});

app.post('/api/contracts/verify', async (req, res) => {
  try {
    const { templateName, contractAddress, constructorValues } = req.body;
    
    if (!templateName || !contractAddress) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (!ethers.isAddress(contractAddress)) {
      return res.status(400).json({ error: 'Invalid contract address' });
    }
    
    const { verifyDeployedContract } = require('./services/contractVerification');
    const result = await verifyDeployedContract(templateName, contractAddress, constructorValues);
    
    res.json(result);
  } catch (error) {
    console.error('Error verifying contract:', error);
    res.status(500).json({ 
      success: false,
      error: error.message || 'Verification failed' 
    });
  }
});

app.get('/api/bridge/intent/:id', (req, res) => {
  try {
    const intent = getIntent(req.params.id);
    if (!intent) {
      return res.status(404).json({ error: 'Intent not found' });
    }
    res.json(intent);
  } catch (error) {
    console.error('Error fetching intent:', error);
    res.status(500).json({ error: 'Failed to fetch intent' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/bridge/rpc-status', (req, res) => {
  try {
    const { getRpcStatus } = require('./services/bridgeMonitor');
    res.json(getRpcStatus());
  } catch (error) {
    res.status(500).json({ error: 'Failed to get RPC status' });
  }
});

app.get('/api/competitions/leaderboard', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const leaderboard = getLeaderboard(limit);
    res.json({ leaderboard });
  } catch (error) {
    console.error('Error fetching leaderboard:', error);
    res.status(500).json({ error: 'Failed to fetch leaderboard' });
  }
});

app.get('/api/competitions/stats', (req, res) => {
  try {
    const stats = getCompetitionStats();
    res.json(stats);
  } catch (error) {
    console.error('Error fetching competition stats:', error);
    res.status(500).json({ error: 'Failed to fetch competition stats' });
  }
});

app.get('/api/competitions/rank/:address', (req, res) => {
  try {
    const rank = getUserRank(req.params.address);
    if (!rank) {
      return res.json({ rank: null });
    }
    res.json(rank);
  } catch (error) {
    console.error('Error fetching user rank:', error);
    res.status(500).json({ error: 'Failed to fetch user rank' });
  }
});

if (isProduction) {
  app.use((req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/dist/index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`🌉 Bridge API server running on port ${PORT}`);
  console.log(`📍 Solana Custodial: ${process.env.SOLANA_CUSTODIAL_PUBLIC}`);
  console.log(`📍 AuditChain Custodial: ${process.env.AUDITCHAIN_CUSTODIAL_PUBLIC}`);
  
  monitorDeposits();
  
  // RPC-dependent services only work in production due to Replit dev environment restrictions
  if (isProduction) {
    const db = require('./db');
    
    console.log('🏆 Starting competition indexer service...');
    startCompetitionIndexer(db);
    
    console.log('🔄 Starting automatic pool registration service...');
    startPoolRegistrar();
  } else {
    console.log('ℹ️  RPC services disabled in development (Replit network restrictions)');
    console.log('   Competition indexer & pool auto-registration will activate when deployed');
  }
});
