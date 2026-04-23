const { ethers } = require("ethers");
const fs = require("fs");

// Configuration
const MIN_AUDT_BALANCE = ethers.parseEther("10000"); // 10K AUDT for VIP
const DAILY_REFUND_LIMIT = 50; // Max 50 refunds per day per wallet
const CHECK_INTERVAL_MS = 2000; // Check every 2 seconds (matches block time)

// Load validator key
const VALIDATOR_KEY = fs.readFileSync("/root/auditchain-v2/node1/key", "utf8").trim();

const provider = new ethers.JsonRpcProvider("http://[::1]:8545");
const validatorWallet = new ethers.Wallet(VALIDATOR_KEY, provider);

// Track refunds per address per day
const refundStats = new Map(); // address -> { day, count }
let lastProcessedBlock = 0;
let totalRefunded = 0n;
let refundCount = 0;

console.log("=== AuditChain Gas Refund Service ===");
console.log("Validator:", validatorWallet.address);
console.log("VIP Requirement:", "10,000+ AUDT");
console.log("Daily Limit:", DAILY_REFUND_LIMIT, "refunds per wallet");
console.log("");

function getRefundStats(address) {
    const today = Math.floor(Date.now() / 86400000);
    const key = address.toLowerCase();
    let stats = refundStats.get(key);
    
    if (!stats || stats.day !== today) {
        stats = { day: today, count: 0 };
        refundStats.set(key, stats);
    }
    return stats;
}

async function isVIP(address) {
    try {
        const balance = await provider.getBalance(address);
        return balance >= MIN_AUDT_BALANCE;
    } catch {
        return false;
    }
}

async function processBlock(blockNumber) {
    try {
        const block = await provider.getBlock(blockNumber, true);
        if (!block || !block.transactions) return;
        
        for (const txHash of block.transactions) {
            const tx = await provider.getTransaction(txHash);
            if (!tx || !tx.from) continue;
            
            // Skip validator transactions (our own refunds)
            if (tx.from.toLowerCase() === validatorWallet.address.toLowerCase()) continue;
            
            // Check if sender is VIP
            const vip = await isVIP(tx.from);
            if (!vip) continue;
            
            // Check daily limit
            const stats = getRefundStats(tx.from);
            if (stats.count >= DAILY_REFUND_LIMIT) {
                console.log(`[LIMIT] ${tx.from.slice(0,10)}... hit daily limit (${stats.count}/${DAILY_REFUND_LIMIT})`);
                continue;
            }
            
            // Get transaction receipt for actual gas used
            const receipt = await provider.getTransactionReceipt(txHash);
            if (!receipt) continue;
            
            const gasUsed = receipt.gasUsed;
            const gasPrice = tx.gasPrice || tx.maxFeePerGas || 0n;
            const gasCost = gasUsed * gasPrice;
            
            if (gasCost === 0n) continue;
            
            // Refund the gas cost
            console.log(`[REFUND] ${tx.from.slice(0,10)}... paid ${ethers.formatEther(gasCost)} AUDT gas - refunding...`);
            
            try {
                const refundTx = await validatorWallet.sendTransaction({
                    to: tx.from,
                    value: gasCost
                });
                await refundTx.wait();
                
                stats.count++;
                totalRefunded += gasCost;
                refundCount++;
                
                console.log(`  -> Refunded! TX: ${refundTx.hash.slice(0,18)}... (${stats.count}/${DAILY_REFUND_LIMIT} today)`);
            } catch (error) {
                console.error(`  -> Refund failed:`, error.message);
            }
        }
    } catch (error) {
        // Block might not exist yet, ignore
    }
}

async function monitor() {
    try {
        const currentBlock = await provider.getBlockNumber();
        
        if (lastProcessedBlock === 0) {
            lastProcessedBlock = currentBlock;
            console.log(`Starting from block ${currentBlock}`);
        }
        
        // Process any new blocks
        while (lastProcessedBlock < currentBlock) {
            lastProcessedBlock++;
            await processBlock(lastProcessedBlock);
        }
    } catch (error) {
        console.error("[MONITOR] Error:", error.message);
    }
}

// Start monitoring
monitor();
setInterval(monitor, CHECK_INTERVAL_MS);

// Stats every 5 minutes
setInterval(() => {
    console.log(`[STATS] Block ${lastProcessedBlock}, ${refundCount} refunds, ${ethers.formatEther(totalRefunded)} AUDT total`);
}, 300000);
